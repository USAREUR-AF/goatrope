# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Reading and changing the machine: interfaces, routes, ethtool, tc, systemd."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess

SYS_NET = "/sys/class/net"


def run(cmd: list[str], check: bool = False, timeout: float = 30) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        p = subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stderr.strip()}")
    return p


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def read(path: str, default: str | None = None) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default


def write_file(path: str, content: str, mode: int = 0o644) -> None:
    """Replace path atomically and durably: a power cut leaves the old file or the new one, never half."""
    d = os.path.dirname(path)
    tmp = os.path.join(d, f".{os.path.basename(path)}.goatrope-new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    fsync_dir(d)


def fsync_dir(d: str) -> None:
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def uppers(ifname: str) -> list[str]:
    """Devices stacked on ifname (VLAN, macvlan, ipvlan, a bridge or bond it belongs to)."""
    try:
        return sorted(n[len("upper_"):] for n in os.listdir(f"{SYS_NET}/{ifname}") if n.startswith("upper_"))
    except OSError:
        return []


def lowers(ifname: str, depth: int = 0) -> set[str]:
    """ifname and every device beneath it: tp0.100 is carried by tp0."""
    out = {ifname}
    if depth > 8:
        return out
    try:
        for n in os.listdir(f"{SYS_NET}/{ifname}"):
            if n.startswith("lower_"):
                out |= lowers(n[len("lower_"):], depth + 1)
    except OSError:
        pass
    return out


def write(path: str, value: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(value)
        return True
    except OSError:
        return False


def exists(ifname: str) -> bool:
    return os.path.exists(f"{SYS_NET}/{ifname}")


def addresses(ifname: str) -> list[str]:
    p = run(["ip", "-j", "addr", "show", "dev", ifname])
    if p.returncode != 0 or not p.stdout.strip():
        return []
    out = []
    for link in json.loads(p.stdout):
        for a in link.get("addr_info", []):
            out.append(f"{a.get('local')}/{a.get('prefixlen')}")
    return out


def master(ifname: str) -> str | None:
    link = os.path.realpath(f"{SYS_NET}/{ifname}/master")
    return os.path.basename(link) if os.path.exists(f"{SYS_NET}/{ifname}/master") else None


def flags(ifname: str) -> list[str]:
    p = run(["ip", "-j", "link", "show", "dev", ifname])
    if p.returncode != 0 or not p.stdout.strip():
        return []
    return json.loads(p.stdout)[0].get("flags", [])


def kind(ifname: str) -> str | None:
    p = run(["ip", "-j", "-d", "link", "show", "dev", ifname])
    if p.returncode != 0 or not p.stdout.strip():
        return None
    return json.loads(p.stdout)[0].get("linkinfo", {}).get("info_kind")


def route_dev(addr: str) -> str | None:
    p = run(["ip", "-j", "route", "get", addr])
    if p.returncode != 0 or not p.stdout.strip():
        return None
    r = json.loads(p.stdout)
    return r[0].get("dev") if r else None


def default_route_devs() -> list[str]:
    """Every device a default route in any table leaves through, ECMP next hops included."""
    devs = []
    for fam in ("-4", "-6"):
        p = run(["ip", "-j", fam, "route", "show", "default", "table", "all"])
        if p.returncode == 0 and p.stdout.strip():
            for r in json.loads(p.stdout):
                if r.get("dev"):
                    devs.append(r["dev"])
                devs += [h["dev"] for h in r.get("nexthops", []) if h.get("dev")]
    return sorted(set(devs))


def _split_scope(hostport: str) -> tuple[str, str | None]:
    """'[fe80::1%tp0]:22' or '192.0.2.1:22' or 'fe80::1%tp0' -> (address, scope interface or None)."""
    h = hostport
    if h.startswith("[") and "]" in h:
        inside, rest = h[1:h.index("]")], h[h.index("]") + 1:]
        if rest.startswith("%"):  # ss prints the scope after the bracket: [fe80::1]%tp0:22
            inside += "%" + rest[1:].rsplit(":", 1)[0]
        h = inside
    elif h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    addr, _, scope = h.partition("%")
    return addr, (scope or None)


def peer_devices(peer: str, scope: str | None = None) -> set[str]:
    """The devices a connection to peer uses, down to the physical port: for a link-local
    peer the scope names the interface; otherwise the route does."""
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return set()
    if ip.is_loopback:
        return {"lo"}
    dev = scope if (scope and ip.is_link_local) else route_dev(peer)
    return lowers(dev) if dev else set()


def established() -> list[tuple[str, set[str]]]:
    """(peer, devices beneath it) for every established TCP connection, an SSH session among them."""
    p = run(["ss", "-Htn", "state", "established"])
    out = []
    for line in p.stdout.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local, peer = cols[-2], cols[-1]
        laddr, lscope = _split_scope(local)
        paddr, pscope = _split_scope(peer)
        devs = peer_devices(paddr, pscope or lscope) - {"lo"}
        if lscope:
            devs |= lowers(lscope)
        if devs:
            out.append((paddr, devs))
    return out


def session() -> tuple[str, set[str]] | None:
    """The operator's SSH session: (peer, devices beneath it)."""
    s = os.environ.get("SSH_CONNECTION") or os.environ.get("GOATROPE_SSH_CONNECTION")
    if not s:
        return None
    parts = s.split()
    paddr, pscope = _split_scope(parts[0])
    lscope = _split_scope(parts[2])[1] if len(parts) > 2 else None
    devs = peer_devices(paddr, pscope or lscope)
    return paddr, devs


def nm_active() -> bool:
    return unit_active("NetworkManager.service") == "active" and have("nmcli")


def nm_states() -> dict[str, str]:
    """{device: state} as NetworkManager sees them."""
    p = run(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])
    out = {}
    for line in p.stdout.splitlines():
        dev, _, state = line.rpartition(":")
        if dev:
            out[dev.replace("\\:", ":")] = state
    return out


def forwarding(ifname: str) -> list[str]:
    """Which IP families forward packets arriving on ifname."""
    on = []
    for fam in ("ipv4", "ipv6"):
        if read(f"/proc/sys/net/{fam}/conf/{ifname}/forwarding") == "1":
            on.append(fam)
    return on


OFFLOADS = {"gro": "generic-receive-offload", "lro": "large-receive-offload",
            "tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload"}


def features(ifname: str) -> dict[str, tuple[str, bool]]:
    """{short: (on|off, fixed)} for the offloads goatrope turns off."""
    p = run(["ethtool", "-k", ifname])
    found = {}
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*([a-z0-9-]+):\s+(on|off)(\s+\[fixed\])?", line)
        if m:
            found[m.group(1)] = (m.group(2), bool(m.group(3)))
    return {k: found[v] for k, v in OFFLOADS.items() if v in found}


def eee(ifname: str) -> str:
    """enabled, disabled or unsupported."""
    p = run(["ethtool", "--show-eee", ifname])
    if p.returncode != 0:
        return "unsupported"
    text = p.stdout.lower()
    if "not supported" in text:
        return "unsupported"
    m = re.search(r"eee status:\s*(\w+)", text)
    if not m:
        return "unsupported"
    return "disabled" if m.group(1) in ("disabled", "not") else "enabled"


def link_settings(ifname: str) -> dict:
    p = run(["ethtool", ifname])
    out = {"speed": None, "duplex": None, "autoneg": None}
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith("Speed:"):
            m = re.search(r"(\d+)", line)
            out["speed"] = int(m.group(1)) if m else None
        elif line.startswith("Duplex:"):
            out["duplex"] = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Auto-negotiation:"):
            out["autoneg"] = line.split(":", 1)[1].strip().lower()
    return out


def egress_drop(ifname: str) -> bool:
    p = run(["tc", "filter", "show", "dev", ifname, "egress"])
    text = p.stdout
    return "matchall" in text and "gact action drop" in text


def systemctl(*args: str) -> subprocess.CompletedProcess:
    return run(["systemctl", *args], timeout=120)


def unit_active(unit: str) -> str:
    return systemctl("is-active", unit).stdout.strip() or "unknown"


def unit_enabled(unit: str) -> str:
    return systemctl("is-enabled", unit).stdout.strip() or "unknown"


def sysctl_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")
