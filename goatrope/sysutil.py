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
    devs = []
    for fam in ("-4", "-6"):
        p = run(["ip", "-j", fam, "route", "show", "default"])
        if p.returncode == 0 and p.stdout.strip():
            devs += [r.get("dev") for r in json.loads(p.stdout) if r.get("dev")]
    return devs


def established_peers() -> list[str]:
    """Peer addresses of every established TCP connection (an SSH session among them)."""
    p = run(["ss", "-Htn", "state", "established"])
    peers = []
    for line in p.stdout.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            host = cols[-1].rsplit(":", 1)[0].strip("[]")
            host = host.split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if not ip.is_loopback:
                peers.append(str(ip))
    return sorted(set(peers))


def session_peer() -> str | None:
    s = os.environ.get("SSH_CONNECTION") or os.environ.get("GOATROPE_SSH_CONNECTION")
    return s.split()[0] if s else None


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
