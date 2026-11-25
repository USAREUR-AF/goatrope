# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""The relay's boundary transport (docs/adr/0002, Transport).

For a site that must be treated as outside the deployment, the relay reaches the
remote side through a WireGuard interface of its own with exactly one peer: the
declared boundary point. The peer's key, endpoint and single tunnel address are
fixed by the declaration, and the interface is checked against it before the relay
starts and every two seconds while it runs.

The interface may be made by goatrope (`goatrope boundary up`, or the relay when it
is absent) or by other tooling; either way it must match the declaration exactly.
goatrope never reads or prints a private key's value: it compares the public key
derived from the declared key file with the one the interface uses.
"""
from __future__ import annotations

import ipaddress
import os
import stat
import subprocess

from . import config as cfgmod, sysutil as su


class BoundaryRefusal(Exception):
    pass


def _host_len(addr: str) -> int:
    return 32 if ipaddress.ip_address(addr).version == 4 else 128


def _file_problem(path: str, what: str) -> str | None:
    try:
        st = os.stat(path)
    except OSError:
        return f"{what} {path} does not exist (make it with `goatrope boundary key`)"
    if not stat.S_ISREG(st.st_mode):
        return f"{what} {path} is not a regular file"
    if st.st_uid != 0 or st.st_mode & 0o077:
        return f"{what} {path} must be owned by root and readable by root only (mode 600)"
    return None


def _pubkey(private_key_file: str) -> str | None:
    try:
        with open(private_key_file, encoding="ascii") as f:
            proc = subprocess.run(["wg", "pubkey"], stdin=f, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _same_secret(path: str, value: str) -> bool:
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip() == value
    except OSError:
        return False


def check(b: cfgmod.Boundary, ifname: str) -> list[str]:
    """Every way the interface differs from the declaration; empty when it matches."""
    if not su.have("wg"):
        return ["the wg tool (wireguard-tools) is not installed"]
    problems = [p for p in (_file_problem(b.private_key_file, "private key file"),
                            _file_problem(b.preshared_key_file, "preshared key file") if b.preshared_key_file else None) if p]
    if problems:
        return problems
    if not su.exists(ifname):
        return [f"no interface {ifname}"]
    if su.kind(ifname) != "wireguard":
        return [f"{ifname} is not a WireGuard interface"]
    dump = su.run(["wg", "show", ifname, "dump"], timeout=10)
    if dump.returncode != 0:
        return [f"wg show {ifname} failed: {dump.stderr.strip()}"]
    lines = [ln.split("\t") for ln in dump.stdout.splitlines() if ln.strip()]
    if not lines or len(lines[0]) < 3:
        return [f"wg show {ifname}: unexpected output"]
    head, peers = lines[0], lines[1:]
    if head[2] != str(b.listen_port):
        problems.append(f"{ifname} listens on {head[2]}, not the declared {b.listen_port}")
    want_pub = _pubkey(b.private_key_file)
    if want_pub is None:
        problems.append(f"cannot derive a public key from {b.private_key_file}")
    elif head[1] != want_pub:
        problems.append(f"{ifname} does not use the key in {b.private_key_file}")
    if len(peers) != 1:
        problems.append(f"{ifname} has {len(peers)} peers; a boundary interface has exactly one, the boundary point")
    for p in peers[:1]:
        if len(p) < 8:
            problems.append(f"wg show {ifname}: unexpected peer line")
            continue
        pub, psk, endpoint, allowed, keepalive = p[0], p[1], p[2], p[3], p[7]
        if pub != b.peer_public_key:
            problems.append(f"{ifname}'s peer is not the declared boundary point (key {pub[:8]}...)")
        if b.preshared_key_file:
            if psk == "(none)" or not _same_secret(b.preshared_key_file, psk):
                problems.append(f"{ifname}'s peer does not use the preshared key in {b.preshared_key_file}")
        elif psk != "(none)":
            problems.append(f"{ifname}'s peer has a preshared key the declaration does not name")
        if endpoint != b.peer_endpoint:
            problems.append(f"{ifname}'s peer endpoint is {endpoint}, not the declared {b.peer_endpoint}")
        want_allowed = f"{b.peer_address}/{_host_len(b.peer_address)}"
        if allowed != want_allowed:
            problems.append(f"{ifname}'s peer may send from {allowed}; a boundary interface allows only {want_allowed}")
        want_ka = str(b.keepalive_s) if b.keepalive_s else "off"
        if keepalive != want_ka:
            problems.append(f"{ifname}'s peer keepalive is {keepalive}, not the declared {want_ka}")
    if b.address not in su.addresses(ifname):
        problems.append(f"{ifname} does not hold {b.address}")
    return problems


def up(b: cfgmod.Boundary, ifname: str) -> bool:
    """Make the interface when it is absent; then require it to match. Returns True when it was made here."""
    made = False
    if not su.exists(ifname):
        if not su.have("wg"):
            raise BoundaryRefusal("the wg tool (wireguard-tools) is not installed")
        bad = [p for p in (_file_problem(b.private_key_file, "private key file"),
                           _file_problem(b.preshared_key_file, "preshared key file") if b.preshared_key_file else None) if p]
        if bad:
            raise BoundaryRefusal("; ".join(bad))
        peer = ["peer", b.peer_public_key, "endpoint", b.peer_endpoint,
                "allowed-ips", f"{b.peer_address}/{_host_len(b.peer_address)}"]
        if b.preshared_key_file:
            peer += ["preshared-key", b.preshared_key_file]
        if b.keepalive_s:
            peer += ["persistent-keepalive", str(b.keepalive_s)]
        steps = [["ip", "link", "add", ifname, "type", "wireguard"],
                 ["wg", "set", ifname, "listen-port", str(b.listen_port), "private-key", b.private_key_file] + peer,
                 ["ip", "address", "add", b.address, "dev", ifname],
                 ["ip", "link", "set", ifname, "up"]]
        for cmd in steps:
            if cmd[1] == "address":  # goatrope's own interface: it never routes, and carries no IPv6 unless declared
                su.write(f"/proc/sys/net/ipv4/conf/{ifname}/forwarding", "0")
                su.write(f"/proc/sys/net/ipv6/conf/{ifname}/forwarding", "0")
                if ":" not in b.address:
                    su.write(f"/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6", "1")
            p = su.run(cmd, timeout=15)
            if p.returncode != 0:
                if made:  # the interface exists from the first step: take it away again
                    su.run(["ip", "link", "del", ifname], timeout=15)
                raise BoundaryRefusal(f"{' '.join(cmd[:3])} failed: {p.stderr.strip()}")
            made = True
    problems = check(b, ifname)
    if problems:
        if made:
            su.run(["ip", "link", "del", ifname], timeout=15)
        raise BoundaryRefusal(f"{ifname} does not match the declaration: " + "; ".join(problems))
    return made


def down(ifname: str) -> bool:
    if not su.exists(ifname):
        return False
    if su.kind(ifname) != "wireguard":
        raise BoundaryRefusal(f"{ifname} is not a WireGuard interface; goatrope removes only its boundary interface")
    su.run(["ip", "link", "del", ifname], check=True, timeout=15)
    return True


def make_key(path: str) -> str:
    """Write a new private key, mode 600, refusing to replace one. Returns the public key."""
    if not su.have("wg"):
        raise BoundaryRefusal("the wg tool (wireguard-tools) is not installed")
    if os.path.exists(path):
        raise BoundaryRefusal(f"{path} already exists; goatrope never replaces a key (remove it yourself to rotate)")
    gen = su.run(["wg", "genkey"], timeout=10)
    if gen.returncode != 0:
        raise BoundaryRefusal(f"wg genkey failed: {gen.stderr.strip()}")
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        su.write_all(fd, (gen.stdout.strip() + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    pub = _pubkey(path)
    if pub is None:
        raise BoundaryRefusal(f"cannot derive a public key from {path}")
    return pub


def sheet(b: cfgmod.Boundary, ifname: str) -> str:
    """What the boundary point's operator needs; no private value."""
    pub = _pubkey(b.private_key_file) or "(no key yet: goatrope boundary key)"
    mine = b.address.split("/")[0]
    return (f"public key      {pub}\n"
            f"listen port     {b.listen_port} (UDP, on this machine's address facing the boundary point)\n"
            f"tunnel address  {mine} (the boundary point allows only {mine}/{_host_len(mine)} from this peer)\n"
            f"boundary point  {b.peer_endpoint}, tunnel address {b.peer_address}, interface {ifname} here\n"
            f"preshared key   {'yes, exchanged out of band' if b.preshared_key_file else 'none'}")
