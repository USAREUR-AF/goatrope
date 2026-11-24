# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Decode-and-send: take the tap's copy, deserialize, optionally convert, and send.

[[send]]  goatrope's own forwarder. It reads frames on a tap port (receive only),
          reassembles IPv4 fragments, keeps the UDP datagrams the match names,
          optionally converts each payload with a pinned goat-transformers
          binary, and sends it to UDP, TCP, HTTP or a file. It never sends
          through a tap port: a destination routed through one is refused.
[[decode]] a pinned first-bite `mind` that goatrope configures, runs and
          health-checks. It decodes with its own dictionary and delivers with
          its own sinks (Zenoh among them); goatrope does not read its output.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

from . import VERSION, config as cfgmod, sysutil as su

UNITS = "/etc/systemd/system"
BIN = "/usr/local/sbin/goatrope"
ETC = "/etc/goatrope"
HEADER = "# Written by goatrope {v} from {cfg}. goatrope uninstall removes it; do not edit.\n"
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


def units(cfg: cfgmod.Config) -> list[str]:
    return ([f"goatrope-send@{s.name}.service" for s in cfg.sends]
            + [f"goatrope-decode@{d.name}.service" for d in cfg.decodes])


def render(cfg: cfgmod.Config) -> dict[str, str]:
    files = {}
    h = HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml")
    if cfg.sends:
        files[f"{UNITS}/goatrope-send@.service"] = h + f"""[Unit]
Description=goatrope: decode-and-send %i
After=goatrope-ports.service network-online.target
Wants=goatrope-ports.service

[Service]
ExecStart={BIN} run-send %i --config {ETC}/goatrope.toml
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/goatrope
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""
    if cfg.decodes:
        files[f"{UNITS}/goatrope-decode@.service"] = h + f"""[Unit]
Description=goatrope: first-bite decoder %i
After=goatrope-ports.service
Wants=goatrope-ports.service

[Service]
EnvironmentFile={ETC}/decode-%i.env
ExecStartPre={BIN} verify-component decode %i --config {ETC}/goatrope.toml
ExecStart=/bin/sh -c 'exec "$MIND" $PORTS --dictionary "$DICTIONARY" --filter "$FILTER"'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        for d in cfg.decodes:
            files[f"{ETC}/decode-{d.name}.env"] = (
                h + f"MIND={d.binary}\nPORTS={' '.join(d.ports)}\nDICTIONARY={d.dictionary}\n"
                f"FILTER={d.filter}\nSUBSCRIBER_CONFIG_PATH={d.subscribers}\n")
    return files


def sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def refuse_tap_routes(cfg: cfgmod.Config) -> list[str]:
    """Destinations whose route leaves through a tap port: sending there would transmit on the link."""
    taken = set(cfg.tap_ports()) | {"goatrope0"}
    bad = []
    for s in cfg.sends:
        for d in s.to:
            if d.scheme in ("udp", "tcp", "http", "https") and d.host:
                try:
                    addr = str(ipaddress.ip_address(d.host))
                except ValueError:
                    addr = socket.gethostbyname(d.host)
                dev = su.route_dev(addr)
                if dev in taken:
                    bad.append(f"[[send]] {s.name}: {d.url} is reached through {dev}, a tap port")
    return bad


def start(cfg: cfgmod.Config, log=print) -> None:
    for u in units(cfg):
        su.systemctl("enable", u)
        su.systemctl("restart", u)


def check(cfg: cfgmod.Config) -> list[dict]:
    items = []
    for s in cfg.sends:
        if s.convert:
            h = sha256(s.convert.binary)
            items.append({"id": f"pin:send:{s.name}", "ok": h == s.convert.sha256,
                          "want": f"goat-transformers {s.convert.version} sha256 {s.convert.sha256[:12]}",
                          "have": (h[:12] if h else "absent")})
        hb = _heartbeat(s.name)
        items.append({"id": f"send-health:{s.name}", "ok": hb is not None and time.time() - hb.get("time", 0) < 30,
                      "want": "heartbeat within 30 s", "have": json.dumps(hb) if hb else "none"})
    for d in cfg.decodes:
        h = sha256(d.binary)
        items.append({"id": f"pin:decode:{d.name}", "ok": h == d.sha256,
                      "want": f"first-bite {d.version} sha256 {d.sha256[:12]}", "have": (h[:12] if h else "absent")})
    for b in refuse_tap_routes(cfg):
        items.append({"id": "send-route", "ok": False, "want": "no destination through a tap port", "have": b})
    return items


def _heartbeat(name: str) -> dict | None:
    s = su.read(f"/var/lib/goatrope/send/{name}.health")
    try:
        return json.loads(s) if s else None
    except json.JSONDecodeError:
        return None


def status(cfg: cfgmod.Config, log=print) -> None:
    for s in cfg.sends:
        hb = _heartbeat(s.name) or {}
        log(f"  send   {s.name:<14} {su.unit_active(f'goatrope-send@{s.name}.service'):<9} "
            f"matched={hb.get('matched', 0)} sent={hb.get('sent', 0)} errors={hb.get('errors', 0)} "
            f"-> {', '.join(d.url for d in s.to)}")
    for d in cfg.decodes:
        log(f"  decode {d.name:<14} {su.unit_active(f'goatrope-decode@{d.name}.service'):<9} "
            f"first-bite {d.version} on {' '.join(d.ports)}")


def verify_component(cfg: cfgmod.Config, kind: str, name: str) -> int:
    items = [d for d in cfg.decodes if d.name == name] if kind == "decode" else []
    if not items:
        print(f"goatrope: no [[decode]] {name}", file=sys.stderr)
        return 2
    d = items[0]
    h = sha256(d.binary)
    if h != d.sha256:
        print(f"goatrope: {d.binary} is not the pinned first-bite {d.version} (sha256 {h})", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------- runtime

class Fragments:
    """IPv4 reassembly, bounded: 30 s and 256 datagrams in flight."""

    def __init__(self):
        self.pending: dict[tuple, dict] = {}

    def add(self, key: tuple, offset: int, more: bool, data: bytes) -> bytes | None:
        now = time.monotonic()
        for k in [k for k, v in self.pending.items() if now - v["t"] > 30]:
            del self.pending[k]
        if len(self.pending) > 256:
            self.pending.clear()
        e = self.pending.setdefault(key, {"t": now, "parts": {}, "end": None})
        e["parts"][offset] = data
        if not more:
            e["end"] = offset + len(data)
        if e["end"] is None:
            return None
        buf, pos = b"", 0
        for off in sorted(e["parts"]):
            if off != pos:
                return None
            buf += e["parts"][off]
            pos = off + len(e["parts"][off])
        if pos != e["end"]:
            return None
        del self.pending[key]
        return buf


def parse(frame: bytes, frags: Fragments):
    """(src, dst, sport, dport, payload) of a UDP datagram, or None."""
    if len(frame) < 14:
        return None
    et = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
        et = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
    if et == 0x0800:
        if len(frame) < off + 20:
            return None
        vihl, _, total, ident, fl, _, proto = struct.unpack_from("!BBHHHBB", frame, off)
        ihl = (vihl & 0x0F) * 4
        src = socket.inet_ntop(socket.AF_INET, frame[off + 12:off + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[off + 16:off + 20])
        if proto != 17:
            return None
        body = frame[off + ihl:off + total]
        foff, more = (fl & 0x1FFF) * 8, bool(fl & 0x2000)
        if foff or more:
            body = frags.add((src, dst, ident), foff, more, body)
            if body is None:
                return None
    elif et == 0x86DD:
        if len(frame) < off + 40:
            return None
        plen, nh = struct.unpack_from("!HB", frame, off + 4)
        if nh != 17:
            return None
        src = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
        body = frame[off + 40:off + 40 + plen]
    else:
        return None
    if len(body) < 8:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", body, 0)
    return src, dst, sport, dport, body[8:ulen] if ulen >= 8 else body[8:]


def matches(m: cfgmod.Match, src, dst, sport, dport) -> bool:
    return ((m.src is None or m.src == src) and (m.dst is None or m.dst == dst)
            and (m.src_port is None or m.src_port == sport) and (m.dst_port is None or m.dst_port == dport))


class Sink:
    def __init__(self, d: cfgmod.Destination, taken: set[str]):
        self.d, self.taken, self.sock, self.fh = d, taken, None, None

    def _guard(self):
        if self.d.host:
            dev = su.route_dev(self.d.host)
            if dev in self.taken:
                raise OSError(f"{self.d.url} is reached through tap port {dev}; not sending")

    def send(self, payload: bytes, meta: dict) -> None:
        d = self.d
        if d.scheme == "udp":
            if self.sock is None:
                self._guard()
                fam = socket.AF_INET6 if ":" in d.host else socket.AF_INET
                self.sock = socket.socket(fam, socket.SOCK_DGRAM)
            self.sock.sendto(payload, (d.host, d.port))
        elif d.scheme == "tcp":
            if self.sock is None:
                self._guard()
                self.sock = socket.create_connection((d.host, d.port), timeout=5)
            data = struct.pack("!I", len(payload)) + payload if d.framing == "len32be" else payload
            try:
                self.sock.sendall(data)
            except OSError:
                self.sock.close()
                self.sock = None
                raise
        elif d.scheme in ("http", "https"):
            self._guard()
            req = urllib.request.Request(d.url, data=payload, method="POST",
                                         headers={"Content-Type": "application/octet-stream",
                                                  "X-Goatrope-Feed": meta["feed"]})
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
        elif d.scheme == "file":
            if self.fh is None:
                os.makedirs(os.path.dirname(d.path), exist_ok=True)
                self.fh = open(d.path, "ab", buffering=0)
            if d.format == "jsonl":
                rec = dict(meta, payload_hex=payload.hex())
                self.fh.write((json.dumps(rec, sort_keys=True) + "\n").encode())
            else:
                self.fh.write(payload)


def convert(c: cfgmod.Convert, payload: bytes) -> bytes:
    p = subprocess.run([c.binary, "convert", "--from", c.from_format, "--to", c.to_format],
                       input=payload.hex().encode() + b"\n", capture_output=True, timeout=10)
    if p.returncode != 0:
        raise ValueError(p.stderr.decode(errors="replace").strip()[:200])
    return p.stdout.rstrip(b"\n")


def run_send(cfg: cfgmod.Config, name: str) -> int:
    found = [s for s in cfg.sends if s.name == name]
    if not found:
        print(f"goatrope: no [[send]] {name}", file=sys.stderr)
        return 2
    s = found[0]
    if s.convert and sha256(s.convert.binary) != s.convert.sha256:
        print(f"goatrope: {s.convert.binary} is not the pinned goat-transformers {s.convert.version}", file=sys.stderr)
        return 1
    taken = set(cfg.tap_ports()) | {"goatrope0"}
    sinks = [Sink(d, taken) for d in s.to]
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((s.port, 0))
    sock.settimeout(1.0)
    frags = Fragments()
    counts = {"matched": 0, "sent": 0, "errors": 0}
    health = f"/var/lib/goatrope/send/{name}.health"
    os.makedirs(os.path.dirname(health), exist_ok=True)
    last_hb = 0.0
    print(f"goatrope send {name}: {s.port} udp {s.match} -> {', '.join(d.url for d in s.to)}", flush=True)
    while True:
        now = time.time()
        if now - last_hb >= 2:
            tmp = health + ".new"
            with open(tmp, "w") as f:
                json.dump(dict(counts, time=now), f)
            os.replace(tmp, health)
            last_hb = now
        try:
            frame, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        # In inline mode a bridge port also shows each frame it transmits (pkttype OUTGOING);
        # that is the other direction of the link, so it is kept.
        got = parse(frame, frags)
        if got is None or not matches(s.match, *got[:4]):
            continue
        src, dst, sport, dport, payload = got
        counts["matched"] += 1
        meta = {"feed": name, "time": round(now, 6), "src": src, "dst": dst, "sport": sport, "dport": dport}
        try:
            out = convert(s.convert, payload) if s.convert else payload
        except (ValueError, subprocess.TimeoutExpired) as e:
            counts["errors"] += 1
            print(f"convert failed: {e}", flush=True)
            continue
        for sink in sinks:
            try:
                sink.send(out, meta)
                counts["sent"] += 1
            except OSError as e:
                counts["errors"] += 1
                print(f"{sink.d.url}: {e}", flush=True)
