# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Relay, WORK IN PROGRESS: the smallest case of docs/adr/0003, a fixed-port UDP forwarder.

A remote machine reaches the relay through a WireGuard interface. WireGuard
authenticates the remote machine by its key and binds its tunnel address to that
key, so a datagram's source address inside the tunnel names an authenticated
machine. Each allow rule names that address, a port on the tunnel, and one
address and port on the link. Everything else is dropped and counted.

The relay TRANSMITS on the link, from its own interface and address. It never
uses a tap port, never bridges, forwards no broadcast or multicast, and runs in
the foreground only: `goatrope install` installs no relay unit.
"""
from __future__ import annotations

import json
import os
import selectors
import socket
import sys
import time

from . import config as cfgmod, sysutil as su

SO_BINDTODEVICE = 25
HEALTH = "/var/lib/goatrope/relay.health"


class RelayRefusal(Exception):
    pass


def preflight(cfg: cfgmod.Config) -> None:
    r = cfg.relay
    if r is None:
        raise RelayRefusal("this declaration has no [relay]")
    if su.kind(r.remote_interface) != "wireguard":
        raise RelayRefusal(f"{r.remote_interface} is not a WireGuard interface; the relay authenticates the "
                           "remote machine through WireGuard and accepts nothing else")
    if not su.exists(r.link_interface):
        raise RelayRefusal(f"no interface {r.link_interface}")
    if su.kind(r.link_interface) in ("bridge", "wireguard") or su.master(r.link_interface):
        raise RelayRefusal(f"{r.link_interface} is a bridge, a tunnel or a bridge member; the relay sends from "
                           "a plain interface of its own")
    taps = set(cfg.tap_ports()) | {"goatrope0"}
    if r.link_interface in taps or r.remote_interface in taps:
        raise RelayRefusal("a relay interface is a tap interface")
    if ":" not in r.link_address and su.read(f"/proc/sys/net/ipv6/conf/{r.link_interface}/disable_ipv6") != "1":
        raise RelayRefusal(f"IPv6 is on for {r.link_interface}: the kernel would send neighbor discovery and MLD "
                           "frames on the link. Disable it (net.ipv6.conf.<if>.disable_ipv6 = 1) or declare an IPv6 address")
    addrs = su.addresses(r.link_interface)
    if r.link_address not in addrs:
        raise RelayRefusal(f"{r.link_interface} does not hold {r.link_address} (it has {', '.join(addrs) or 'none'}); "
                           "configure the relay's own address on its interface first")


def _bound(dev: str, addr: str, port: int) -> socket.socket:
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
    s.bind((addr, port))
    s.setblocking(False)
    return s


def run(cfg: cfgmod.Config, max_seconds: float | None = None) -> int:
    try:
        preflight(cfg)
    except RelayRefusal as e:
        print(f"goatrope relay: refused: {e}", file=sys.stderr)
        return 2
    r = cfg.relay
    link_ip = r.link_address.split("/")[0]
    sel = selectors.DefaultSelector()
    state = []
    for rule in r.rules:
        remote_sock = _bound(r.remote_interface, "0.0.0.0" if ":" not in rule.remote else "::", rule.listen_port)
        link_sock = _bound(r.link_interface, link_ip, 0)
        st = {"rule": rule, "remote_sock": remote_sock, "link_sock": link_sock, "peer": None,
              "to_link": 0, "to_remote": 0, "denied": 0}
        sel.register(remote_sock, selectors.EVENT_READ, ("remote", st))
        sel.register(link_sock, selectors.EVENT_READ, ("link", st))
        state.append(st)
        print(f"goatrope relay (WIP): {rule.remote} -> {r.remote_interface}:{rule.listen_port} => "
              f"{link_ip} -> {rule.target}:{rule.target_port} on {r.link_interface} ({rule.direction})", flush=True)
    start = last = time.monotonic()
    last_denied_log = 0.0
    while max_seconds is None or time.monotonic() - start < max_seconds:
        for key, _ in sel.select(timeout=1.0):
            side, st = key.data
            rule = st["rule"]
            try:
                data, (src, sport, *_) = key.fileobj.recvfrom(65535)
            except OSError:
                continue
            if side == "remote":
                if src != rule.remote:
                    st["denied"] += 1
                    if time.monotonic() - last_denied_log > 10:
                        print(f"denied: {src}:{sport} -> port {rule.listen_port} (allowed: {rule.remote})", flush=True)
                        last_denied_log = time.monotonic()
                    continue
                st["peer"] = (src, sport)
                st["link_sock"].sendto(data, (rule.target, rule.target_port))
                st["to_link"] += 1
            else:
                if rule.direction != "both" or (src, sport) != (rule.target, rule.target_port) or not st["peer"]:
                    st["denied"] += 1
                    continue
                st["remote_sock"].sendto(data, st["peer"])
                st["to_remote"] += 1
        if time.monotonic() - last >= 2:
            _health(state)
            last = time.monotonic()
    _health(state)
    return 0


def _health(state: list) -> None:
    os.makedirs(os.path.dirname(HEALTH), exist_ok=True)
    rows = [{"listen_port": s["rule"].listen_port, "target": f"{s['rule'].target}:{s['rule'].target_port}",
             "to_link": s["to_link"], "to_remote": s["to_remote"], "denied": s["denied"]} for s in state]
    tmp = HEALTH + ".new"
    with open(tmp, "w") as f:
        json.dump({"time": time.time(), "rules": rows}, f)
    os.replace(tmp, HEALTH)
