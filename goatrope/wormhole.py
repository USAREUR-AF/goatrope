# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Wormhole, WORK IN PROGRESS: the smallest case of docs/adr/0003, an address-level proxy at both ends.

A goatrope machine at each site claims, on its own link, the addresses the declaration gives to the
far machines, and carries the declared UDP and TCP between them through a WireGuard interface that
belongs to the pair. Each end uses only addresses of its own link, so two sites may reuse a subnet.

It claims an address only after an ARP probe (RFC 5227) and while the far end's heartbeat arrives.
A claim is added to the kernel with a short lifetime and renewed, so it ends by itself if this
process dies. Nothing is routed or bridged: IP forwarding must be off, and every datagram or stream
passes through a socket that one rule opened. It runs in the foreground; install adds no unit.
"""
from __future__ import annotations

import errno
import json
import os
import selectors
import signal
import socket
import struct
import sys
import threading
import time

from . import config as cfgmod, sysutil as su

SO_BINDTODEVICE, IP_FREEBIND = 25, 15
BEAT, DOWN_AFTER, UP_AFTER = 1.0, 3.5, 3       # heartbeat period; seconds of silence; beats in a row
LIFETIME, RENEW = 10, 3.0                      # a claim's kernel lifetime and how often it is renewed
PROBES, PROBE_GAP, PROBE_WAIT = 3, 1.0, 2.0    # RFC 5227 PROBE_NUM, PROBE_MIN, ANNOUNCE_WAIT
CONFLICT_HOLD = 60.0                           # after a conflict, this long before another probe
MAX_FLOWS, IDLE, BUF = 256, 120.0, 65536       # per rule; seconds; bytes held per TCP direction
BEAT_MAGIC = b"GTWH"


class WormholeRefusal(Exception):
    pass


def health_path(w: cfgmod.Wormhole) -> str:
    return f"/var/lib/goatrope/wormhole-{w.link_interface}.health"


def _tunnel_address(ifname: str) -> str | None:
    v4 = [a.split("/")[0] for a in su.addresses(ifname) if ":" not in a]
    return v4[0] if len(v4) == 1 else None


def _forwarding(w: cfgmod.Wormhole) -> list[str]:
    on = [f"{fam} on {i}" for i in [w.link_interface] + [p.interface for p in w.peers] for fam in su.forwarding(i)]
    if su.read("/proc/sys/net/ipv6/conf/all/forwarding") == "1":
        on.append("ipv6 on all interfaces")
    return on


def _addr_entries(ifname: str | None = None) -> list[tuple[str, dict]]:
    p = su.run(["ip", "-j", "-4", "addr", "show"] + (["dev", ifname] if ifname else []))
    try:
        return [(i.get("ifname", ""), a) for i in json.loads(p.stdout or "[]") for a in i.get("addr_info", [])]
    except ValueError:
        return []


def preflight(cfg: cfgmod.Config) -> None:
    w = cfg.wormhole
    if w is None:
        raise WormholeRefusal("this declaration has no [wormhole]")
    if not su.exists(w.link_interface):
        raise WormholeRefusal(f"no interface {w.link_interface}")
    if su.kind(w.link_interface) in ("bridge", "wireguard", "tun") or su.master(w.link_interface):
        raise WormholeRefusal(f"{w.link_interface} is a bridge, a tunnel or a bridge member; the wormhole sends "
                              "from a plain interface of its own")
    if su.read(f"/proc/sys/net/ipv6/conf/{w.link_interface}/disable_ipv6") != "1":
        raise WormholeRefusal(f"IPv6 is on for {w.link_interface}: the kernel would send neighbor discovery and MLD "
                              "frames on the link. Disable it (net.ipv6.conf.<if>.disable_ipv6 = 1)")
    fwd = _forwarding(w)
    if fwd:
        raise WormholeRefusal(f"IP forwarding is on ({', '.join(fwd)}): the kernel would route between a tunnel and "
                              "the link, around the rules. Turn it off; a machine that must route cannot be a wormhole")
    if su.read("/proc/sys/net/ipv4/conf/all/arp_ignore") not in ("1", "2"):
        raise WormholeRefusal("net.ipv4.conf.all.arp_ignore is not 1 or 2: the machine would answer ARP for a claimed "
                              "address on its other interfaces too. Set net.ipv4.conf.all.arp_ignore = 1")
    held = su.addresses(w.link_interface)
    if w.link_address not in held:
        raise WormholeRefusal(f"{w.link_interface} does not hold {w.link_address} (it has {', '.join(held) or 'none'}); "
                              "configure the machine's own address on its interface first")
    claims = {c for p in w.peers for c in p.claims}
    for ifname, a in _addr_entries():
        if a.get("local") in claims and not (ifname == w.link_interface and a.get("dynamic")):
            raise WormholeRefusal(f"{ifname} already holds {a['local']}, which is declared as a claim")
    for p in w.peers:
        if su.kind(p.interface) != "wireguard":
            raise WormholeRefusal(f"{p.interface} is not a WireGuard interface; each pair authenticates through its own")
        if _tunnel_address(p.interface) is None:
            raise WormholeRefusal(f"{p.interface} must hold exactly one IPv4 address")
        out = su.run(["wg", "show", p.interface, "allowed-ips"])
        peers = [ln.split("\t", 1) for ln in out.stdout.splitlines() if ln.strip()]
        if out.returncode != 0 or len(peers) != 1 or peers[0][1].split() != [f"{p.address}/32"]:
            raise WormholeRefusal(f"{p.interface} must have one WireGuard peer, allowed only {p.address}/32: that is "
                                  f"what ties the address to a key (it has {len(peers)} peer(s): "
                                  f"{'; '.join(x[1] for x in peers) or out.stderr.strip() or 'none'})")


# ---------------------------------------------------------------- ARP and claims

def _mac(ifname: str) -> bytes:
    return bytes.fromhex((su.read(f"{su.SYS_NET}/{ifname}/address") or "").replace(":", ""))


def _arp(mac: bytes, sender: str, target: str) -> bytes:
    return (b"\xff" * 6 + mac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + mac + socket.inet_aton(sender) + b"\0" * 6 + socket.inet_aton(target))


class Claims(threading.Thread):
    """Probes for, holds, renews and gives up each claimed address. `held` is what the rules may use."""

    def __init__(self, w: cfgmod.Wormhole, up) -> None:
        super().__init__(daemon=True)
        self.w, self.up = w, up  # up(peer name) -> the far end is heard
        self.peer_of = {c: p.name for p in w.peers for c in p.claims}
        self.state = {c: "waiting" for c in self.peer_of}
        self.conflicts = {c: 0 for c in self.peer_of}
        self.held: set[str] = set()
        self.stop_now = threading.Event()
        self.next_try = {c: 0.0 for c in self.peer_of}
        self.probe = {}  # claim -> [probes sent, next action at]
        self.renewed = 0.0
        self.prefix = w.link_address.split("/")[1]
        self.mac = _mac(w.link_interface)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        self.sock.bind((w.link_interface, 0x0806))
        self.sock.settimeout(0.1)

    def _ip(self, verb: str, claim: str) -> bool:
        cmd = ["ip", "addr", verb, f"{claim}/{self.prefix}", "dev", self.w.link_interface]
        if verb == "replace":
            cmd += ["valid_lft", str(LIFETIME), "preferred_lft", str(LIFETIME)]
        return su.run(cmd).returncode == 0

    def _drop(self, claim: str, state: str) -> None:
        self.held.discard(claim)  # the rules stop using it before the kernel stops answering
        self._ip("del", claim)
        self.probe.pop(claim, None)
        self.state[claim] = state
        print(f"goatrope wormhole: {claim} ({self.peer_of[claim]}): {state}", flush=True)

    def _conflict(self, claim: str, mac: bytes) -> None:
        self.conflicts[claim] += 1
        self.next_try[claim] = time.monotonic() + CONFLICT_HOLD
        self._drop(claim, f"conflict with {mac.hex(':')}")

    def _listen(self) -> None:
        try:
            f, meta = self.sock.recvfrom(2048)
        except (TimeoutError, OSError):
            return
        if meta[2] == socket.PACKET_OUTGOING or len(f) < 42 or f[14:20] != b"\0\x01\x08\0\x06\x04":
            return
        mac, sender, target = f[22:28], socket.inet_ntoa(f[28:32]), socket.inet_ntoa(f[38:42])
        if mac == self.mac:
            return
        if sender in self.peer_of and (sender in self.held or sender in self.probe):
            self._conflict(sender, mac)
        elif sender == "0.0.0.0" and target in self.probe:  # another machine probes for it at the same time
            self._conflict(target, mac)

    def run(self) -> None:
        for c in self.peer_of:  # a claim left by a process that died; its lifetime has not ended yet
            self._ip("del", c)
        while not self.stop_now.is_set():
            self._listen()
            now = time.monotonic()
            for c, peer in self.peer_of.items():
                up = self.up(peer)
                if not up and (c in self.held or c in self.probe):
                    self._drop(c, "tunnel down")
                elif up and c not in self.held and c not in self.probe and now >= self.next_try[c]:
                    self.probe[c] = [0, now]
                    self.state[c] = "probing"
                if c in self.probe and now >= self.probe[c][1]:
                    sent = self.probe[c][0]
                    if sent < PROBES:
                        self.sock.send(_arp(self.mac, "0.0.0.0", c))
                        self.probe[c] = [sent + 1, now + (PROBE_GAP if sent + 1 < PROBES else PROBE_WAIT)]
                    elif self._ip("replace", c):
                        del self.probe[c]
                        self.sock.send(_arp(self.mac, c, c))  # announce
                        self.held.add(c)
                        self.state[c] = "held"
                        print(f"goatrope wormhole: {c} ({peer}): held", flush=True)
                    else:
                        self.next_try[c] = now + CONFLICT_HOLD
                        self._drop(c, "could not be added")
            if now - self.renewed >= RENEW:
                self.renewed = now
                for c in list(self.held):
                    if not self._ip("replace", c):
                        self._drop(c, "could not be renewed")
        for c in list(self.held):
            self._drop(c, "released")


# ---------------------------------------------------------------- sockets

def _sock(kind: int, dev: str, addr: str, port: int, free: bool = False, share: bool = False) -> socket.socket:
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
    if free:  # a claim is bound before it is held, and stays bound while the tunnel is down
        s.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)
    if kind == socket.SOCK_STREAM or share:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    try:
        s.bind((addr, port))
    except OSError:
        s.close()
        raise
    return s


def _keep_port(kind: int, dev: str, addr: str, port: int, free: bool, c: dict, share: bool = False) -> socket.socket:
    """The sender's own source port where it can be had, so a far machine that checks it sees it. share: a
    connected UDP flow beside a listener on the same port (both machines use one fixed port)."""
    try:
        return _sock(kind, dev, addr, port, free, share)
    except OSError:
        c["port_changed"] += 1
        return _sock(kind, dev, addr, 0, free)


class Stream:
    """Two TCP legs, with a bounded buffer each way and half-close carried across."""

    def __init__(self, hole, rule, a: socket.socket, b: socket.socket) -> None:
        self.hole, self.rule, self.s = hole, rule, (a, b)
        self.buf = [bytearray(), bytearray()]    # [i]: bytes to write to s[i]
        self.eof, self.shut = [False, False], [False, False]
        self.connected = [True, False]
        self.closed = False
        for x in self.s:
            x.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            x.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.update()

    def update(self) -> None:
        for i in (0, 1):
            want = 0
            if self.connected[i]:
                if not self.eof[i] and len(self.buf[1 - i]) < BUF:
                    want |= selectors.EVENT_READ
                if self.buf[i]:
                    want |= selectors.EVENT_WRITE
            else:
                want = selectors.EVENT_WRITE
            self.hole.watch(self.s[i], want, ("stream", self, i))

    def event(self, i: int, mask: int) -> None:
        try:
            if not self.connected[i]:
                e = self.s[i].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if e:
                    raise OSError(e, os.strerror(e))
                self.connected[i] = True
            if mask & selectors.EVENT_READ and not self.eof[i]:
                d = self.s[i].recv(BUF)
                if d:
                    self.buf[1 - i] += d
                    self.rule.c["bytes_out" if i == 0 else "bytes_back"] += len(d)
                else:
                    self.eof[i] = True
            for j in (0, 1):
                if self.buf[j] and self.connected[j]:
                    try:
                        del self.buf[j][:self.s[j].send(self.buf[j])]
                    except BlockingIOError:
                        pass
                if self.eof[1 - j] and not self.buf[j] and self.connected[j] and not self.shut[j]:
                    self.s[j].shutdown(socket.SHUT_WR)
                    self.shut[j] = True
        except BlockingIOError:
            pass
        except OSError:
            self.rule.c["errors"] += 1
            self.close(reset=True)
            return
        if all(self.shut) and all(self.eof):
            self.close()
        else:
            self.update()

    def close(self, reset: bool = False) -> None:
        if self.closed:
            return
        self.closed = True
        for x in self.s:
            self.hole.watch(x, 0, None)
            if reset:
                x.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            x.close()
        self.rule.flows.pop(id(self), None)


class Rule:
    """One declared rule: a listener, and the flows it opened."""

    def __init__(self, peer, spec, out: bool) -> None:
        self.peer, self.spec, self.out, self.flows = peer, spec, out, {}
        self.claim = spec.at if out else spec.as_
        self.c = {k: 0 for k in ("out", "back", "bytes_out", "bytes_back", "denied", "not_held", "errors", "port_changed", "full")}

    def name(self) -> str:
        s = self.spec
        return (f"{self.peer.name} {s.protocol}: {s.from_} -> {s.at}:{s.port} => tunnel port {s.tunnel_port}" if self.out else
                f"{self.peer.name} {s.protocol}: tunnel port {s.tunnel_port} => {s.as_} -> {s.to}:{s.port}")


class Hole:
    def __init__(self, cfg: cfgmod.Config) -> None:
        self.w = cfg.wormhole
        self.sel = selectors.DefaultSelector()
        self.quit = False
        self.tunnel = {p.name: _tunnel_address(p.interface) for p in self.w.peers}
        self.beat = {p.name: {"heard": 0.0, "run": 0, "up": False, "seq": 0, "last": 0, "lost": 0, "rtt_ms": None,
                              "rtt_max_ms": 0.0, "downs": 0} for p in self.w.peers}
        self.beat_sock = {}
        for p in self.w.peers:
            s = _sock(socket.SOCK_DGRAM, p.interface, self.tunnel[p.name], p.heartbeat_port)
            self.beat_sock[p.name] = s
            self.sel.register(s, selectors.EVENT_READ, ("beat", p, s))
        self.rules = []
        for p in self.w.peers:
            self.rules += [Rule(p, r, True) for r in p.out] + [Rule(p, r, False) for r in p.in_]
        for r in self.rules:
            kind = socket.SOCK_DGRAM if r.spec.protocol == "udp" else socket.SOCK_STREAM
            if r.out:
                s = _sock(kind, self.w.link_interface, r.spec.at, r.spec.port, free=True, share=True)
            else:
                s = _sock(kind, r.peer.interface, self.tunnel[r.peer.name], r.spec.tunnel_port)
            if kind == socket.SOCK_STREAM:
                s.listen(16)
            r.listener = s
            self.sel.register(s, selectors.EVENT_READ, ("rule", r, s))
            print(f"goatrope wormhole (WIP): {r.name()}", flush=True)
        self.claims = Claims(self.w, lambda name: self.beat[name]["up"])

    def watch(self, s: socket.socket, events: int, data) -> None:
        known = s.fileno() in self.sel.get_map()
        if not events:
            if known:
                self.sel.unregister(s)
        elif known:
            self.sel.modify(s, events, data)
        else:
            self.sel.register(s, events, data)

    def usable(self, r: Rule) -> bool:
        return r.claim in self.claims.held and self.beat[r.peer.name]["up"]

    # -- heartbeat: 'q' seq sent-at, answered as 'r' with the same bytes
    def on_beat(self, p, s) -> None:
        b = self.beat[p.name]
        try:
            d, (src, sport) = s.recvfrom(64)
        except OSError:
            return
        if src != p.address or sport != p.heartbeat_port or len(d) != 21 or d[:4] != BEAT_MAGIC:
            return
        kind, seq, at = struct.unpack("!cQd", d[4:])
        now = time.monotonic()
        if kind == b"r":
            b["rtt_ms"] = round((now - at) * 1000, 3)
            b["rtt_max_ms"] = max(b["rtt_max_ms"], b["rtt_ms"])
            return
        try:
            s.sendto(d[:4] + struct.pack("!cQd", b"r", seq, at), (p.address, p.heartbeat_port))
        except OSError:
            pass
        if b["last"] and seq > b["last"] + 1:
            b["lost"] += seq - b["last"] - 1
        b["last"] = seq
        b["run"] = b["run"] + 1 if now - b["heard"] < DOWN_AFTER else 1
        b["heard"] = now
        if not b["up"] and b["run"] >= UP_AFTER:
            b["up"] = True
            print(f"goatrope wormhole: {p.name}: the far end is heard", flush=True)

    def beats(self, now: float) -> None:
        for p in self.w.peers:
            b = self.beat[p.name]
            b["seq"] += 1
            try:
                self.beat_sock[p.name].sendto(BEAT_MAGIC + struct.pack("!cQd", b"q", b["seq"], now), (p.address, p.heartbeat_port))
            except OSError:
                pass

    def expire(self, now: float) -> None:
        for p in self.w.peers:
            b = self.beat[p.name]
            if b["up"] and now - b["heard"] > DOWN_AFTER:
                b["up"], b["run"] = False, 0
                b["downs"] += 1
                print(f"goatrope wormhole: {p.name}: the far end is not heard", flush=True)
        for r in self.rules:
            ok = self.usable(r)
            for f in list(r.flows.values()):
                if isinstance(f, Stream):
                    if not ok:
                        f.close(reset=True)
                elif not ok or now - f["used"] > IDLE:
                    self.end_flow(r, f)

    # -- UDP
    def end_flow(self, r: Rule, f: dict) -> None:
        self.watch(f["sock"], 0, None)
        f["sock"].close()
        r.flows.pop(f["key"], None)

    def on_udp(self, r: Rule) -> None:
        for _ in range(64):
            try:
                d, src = r.listener.recvfrom(65535)
            except OSError:
                return
            if src[0] != (r.spec.from_ if r.out else r.peer.address):
                r.c["denied"] += 1
                continue
            if not self.usable(r):
                r.c["not_held"] += 1
                continue
            f = r.flows.get(src)
            if f is None:
                if len(r.flows) >= MAX_FLOWS:
                    r.c["full"] += 1
                    continue
                try:
                    if r.out:
                        s = _keep_port(socket.SOCK_DGRAM, r.peer.interface, self.tunnel[r.peer.name], src[1], False, r.c, r.spec.replies)
                        s.connect((r.peer.address, r.spec.tunnel_port))
                    else:
                        s = _keep_port(socket.SOCK_DGRAM, self.w.link_interface, r.spec.as_, src[1], True, r.c, r.spec.replies)
                        s.connect((r.spec.to, r.spec.port))
                except OSError:
                    r.c["errors"] += 1
                    continue
                f = r.flows[src] = {"sock": s, "key": src, "used": 0.0}
                if r.spec.replies:  # connected: the kernel takes replies from that address and port only
                    self.sel.register(s, selectors.EVENT_READ, ("flow", r, f))
            f["used"] = time.monotonic()
            try:
                f["sock"].send(d)
                r.c["out"] += 1
                r.c["bytes_out"] += len(d)
            except OSError:
                r.c["errors"] += 1

    def on_flow(self, r: Rule, f: dict) -> None:
        far = (r.peer.address, r.spec.tunnel_port) if r.out else (r.spec.to, r.spec.port)
        for _ in range(64):
            try:
                d, src = f["sock"].recvfrom(65535)
            except BlockingIOError:
                return
            except OSError:
                r.c["errors"] += 1
                return
            if src != far:  # queued between bind and connect
                r.c["denied"] += 1
                continue
            if not self.usable(r):
                r.c["not_held"] += 1
                continue
            f["used"] = time.monotonic()
            try:
                r.listener.sendto(d, f["key"])
                r.c["back"] += 1
                r.c["bytes_back"] += len(d)
            except OSError:
                r.c["errors"] += 1

    # -- TCP
    def on_accept(self, r: Rule) -> None:
        try:
            a, src = r.listener.accept()
        except OSError:
            return
        why = None
        if src[0] != (r.spec.from_ if r.out else r.peer.address):
            why = "denied"
        elif not self.usable(r):
            why = "not_held"
        elif len(r.flows) >= MAX_FLOWS:
            why = "full"
        b = None
        if why is None:
            a.setblocking(False)
            try:
                if r.out:
                    b = _keep_port(socket.SOCK_STREAM, r.peer.interface, self.tunnel[r.peer.name], src[1], False, r.c)
                    e = b.connect_ex((r.peer.address, r.spec.tunnel_port))
                else:
                    b = _keep_port(socket.SOCK_STREAM, self.w.link_interface, r.spec.as_, src[1], True, r.c)
                    e = b.connect_ex((r.spec.to, r.spec.port))
                if e not in (0, errno.EINPROGRESS):
                    why = "errors"
            except OSError:
                why = "errors"
        if why:
            r.c[why] += 1
            for x in (a, b):
                if x is not None:
                    x.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    x.close()
            return
        r.c["out"] += 1
        st = Stream(self, r, a, b)
        r.flows[id(st)] = st

    def health(self) -> None:
        doc = {"time": time.time(), "peers": {n: {k: b[k] for k in ("up", "rtt_ms", "rtt_max_ms", "lost", "downs")}
                                              for n, b in self.beat.items()},
               "claims": {c: {"state": s, "conflicts": self.claims.conflicts[c]} for c, s in self.claims.state.items()},
               "rules": [{"rule": r.name(), "flows": len(r.flows)} | r.c for r in self.rules]}
        path = health_path(self.w)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + ".new", "w") as f:
                json.dump(doc, f)
            os.replace(path + ".new", path)
        except OSError as e:
            print(f"health: {e}", flush=True)

    def run(self) -> int:
        self.claims.start()
        beat = check = 0.0
        code = 0
        while not self.quit:
            for key, mask in self.sel.select(timeout=0.25):
                what, x, y = key.data
                if what == "rule":
                    self.on_udp(x) if x.spec.protocol == "udp" else self.on_accept(x)
                elif what == "flow":
                    if x.flows.get(y["key"]) is y:
                        self.on_flow(x, y)
                elif what == "stream":
                    if not x.closed:
                        x.event(y, mask)
                else:
                    self.on_beat(x, y)
            now = time.monotonic()
            if now - beat >= BEAT:
                beat = now
                self.beats(now)
            self.expire(now)
            if now - check >= 2:
                check = now
                self.health()
                fwd = _forwarding(self.w)
                if fwd or not self.claims.is_alive():
                    print("goatrope wormhole: stopping: " + (f"IP forwarding was turned on ({', '.join(fwd)})" if fwd
                                                             else "the claims stopped"), file=sys.stderr)
                    code, self.quit = 1, True
        for r in self.rules:
            for f in list(r.flows.values()):
                f.close(reset=True) if isinstance(f, Stream) else self.end_flow(r, f)
        self.claims.stop_now.set()
        self.claims.join(timeout=5)
        self.health()
        return code


def run(cfg: cfgmod.Config) -> int:
    try:
        preflight(cfg)
        hole = Hole(cfg)
    except WormholeRefusal as e:
        print(f"goatrope wormhole: refused: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"goatrope wormhole: {e}", file=sys.stderr)
        return 1

    def stop(*_):
        hole.quit = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    return hole.run()
