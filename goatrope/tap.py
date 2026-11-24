# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""The tap role: render, install, check, show and remove.

One rendering function produces every file the tap needs from the declaration.
install writes exactly those files; check compares them, and the running state,
with the declaration; uninstall removes exactly the files install recorded and
restores the interface settings it saved before changing them.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time

from . import VERSION, config as cfgmod, sysutil as su

BRIDGE = "goatrope0"
STATE_DIR = "/var/lib/goatrope"
STATE = f"{STATE_DIR}/state.json"
LIB = "/usr/local/lib/goatrope"
BIN = "/usr/local/sbin/goatrope"
ETC = "/etc/goatrope"
NET = "/etc/systemd/network"
UNITS = "/etc/systemd/system"
WATCHDOG_DROPIN = "/etc/systemd/system.conf.d/90-goatrope-watchdog.conf"
SYSCTL = "/etc/sysctl.d/90-goatrope.conf"
NM = "/etc/NetworkManager/conf.d/90-goatrope.conf"
WATCHDOG_SEC = 15
HEADER = "# Written by goatrope {v} from {cfg}. goatrope uninstall removes it; do not edit.\n"
LLDP_MASK = 1 << 14  # 01:80:C2:00:00:0E


class Refusal(Exception):
    """install will not proceed; nothing has been changed. Exit code 2."""


def banner(tap: cfgmod.Tap) -> str:
    if tap.mode == "inline":
        return ("tap: inline, fail-closed. Every frame of the link passes through this machine; "
                "the link is down whenever it is off, restarting or hung.")
    return (f"tap: listen ({tap.source}), receive only. The link does not pass through this machine; "
            "while it is off only the recording has a gap.")


# ---------------------------------------------------------------- rendering

def _network_port(cfg: cfgmod.Config, port: str) -> str:
    tap = cfg.tap
    lines = [HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml").rstrip("\n"),
             f"# {'inline bridge port' if tap.mode == 'inline' else 'listen port'}: no address of its own",
             "[Match]", f"Name={port}", "",
             "[Link]", "RequiredForOnline=no",
             # Listen: goatrope-ports.service raises the link only after the egress drop is in place.
             f"ActivationPolicy={'always-up' if tap.mode == 'inline' else 'manual'}",
             ]
    if tap.mode == "listen":
        lines.append("ARP=no")
    lines += ["", "[Network]"]
    if tap.mode == "inline":
        lines.append(f"Bridge={BRIDGE}")
    lines += ["LinkLocalAddressing=no", "IPv6AcceptRA=no", "IPv6SendRA=no", "LLDP=no", "EmitLLDP=no",
              "DHCP=no", "ConfigureWithoutCarrier=yes", ""]
    return "\n".join(lines)


def _bridge_files(cfg: cfgmod.Config) -> dict[str, str]:
    h = HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml")
    netdev = h + f"""# inline: a bridge of exactly the two tap ports; STP off, LLDP forwarded
[NetDev]
Name={BRIDGE}
Kind=bridge

[Bridge]
STP=no
ForwardDelaySec=0
MulticastSnooping=no
MulticastQuerier=no
VLANFiltering=no
GroupForwardMask={LLDP_MASK}
"""
    network = h + f"""# inline: the bridge has no address, so this machine sends nothing on the link
[Match]
Name={BRIDGE}

[Link]
RequiredForOnline=no
ActivationPolicy=always-up

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
IPv6SendRA=no
LLDP=no
EmitLLDP=no
DHCP=no
ConfigureWithoutCarrier=yes
"""
    return {f"{NET}/04-goatrope-{BRIDGE}.netdev": netdev, f"{NET}/04-goatrope-{BRIDGE}.network": network}


def _sysctl(cfg: cfgmod.Config) -> str:
    names = list(cfg.tap.ports) + ([BRIDGE] if cfg.tap.mode == "inline" else [])
    lines = [HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml").rstrip("\n"), "# no IPv6 on tap interfaces"]
    for n in names:
        lines.append(f"net/ipv6/conf/{n}/disable_ipv6 = 1")
    if cfg.tap.mode == "inline":
        lines += ["# bridged frames do not pass through iptables (the '-' ignores a missing key)",
                  "-net.bridge.bridge-nf-call-iptables = 0",
                  "-net.bridge.bridge-nf-call-ip6tables = 0",
                  "-net.bridge.bridge-nf-call-arptables = 0"]
    return "\n".join(lines) + "\n"


def _ports_unit(cfg: cfgmod.Config) -> str:
    return HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml") + f"""[Unit]
Description=goatrope: prepare the tap ports (IPv6, offloads, EEE, speed; listen: egress drop, then link up)
After=systemd-networkd.service
Wants=systemd-networkd.service

[Service]
# exec, not oneshot: boot does not wait while a port that is late (a USB adapter) is awaited.
Type=exec
RemainAfterExit=yes
ExecStart={BIN} apply-ports --config {ETC}/goatrope.toml

[Install]
WantedBy=multi-user.target
"""


def recorder_argv(cfg: cfgmod.Config, port: str) -> list[str]:
    r = cfg.tap.record
    argv = ["/usr/bin/tcpdump", "-n", "-i", port, "-s", "0", "-B", "8192",
            "-C", str(r.file_mb), "-W", str(r.files), "-Z", "tcpdump", "-w", f"{r.directory}/{port}.pcap"]
    if r.filter:
        argv += ["--", r.filter]  # after "--": a filter is never read as a tcpdump option
    return argv


def _record_unit(cfg: cfgmod.Config) -> str:
    r = cfg.tap.record
    argv = recorder_argv(cfg, "%i")
    if r.filter:
        # the declaration refuses quotes, backslashes and control characters; escape systemd's specifiers
        argv[-1] = "'" + r.filter.replace("%", "%%").replace("$", "$$") + "'"
    return HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml") + f"""[Unit]
Description=goatrope: bounded recording ring on %i ({r.files} files of {r.file_mb} MB)
After=goatrope-ports.service
Wants=goatrope-ports.service

[Service]
ExecStart={' '.join(argv)}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def _watchdog() -> str:
    return (HEADER.format(v=VERSION, cfg="the tap role")
            + f"# hardware watchdog: a hung machine restarts\n[Manager]\nRuntimeWatchdogSec={WATCHDOG_SEC}s\n"
            "RebootWatchdogSec=2min\n")


def _nm(cfg: cfgmod.Config) -> str:
    names = list(cfg.tap.ports) + ([BRIDGE] if cfg.tap.mode == "inline" else [])
    # "+=" adds to what other files set; "=" would replace it, and NetworkManager would take every
    # device those files keep from it (on Ubuntu: every wired port, the management port among them).
    return (HEADER.format(v=VERSION, cfg=f"{ETC}/goatrope.toml") + "[keyfile]\nunmanaged-devices+="
            + ";".join(f"interface-name:{n}" for n in names) + "\n")


def render(cfg: cfgmod.Config, nm_present: bool) -> dict[str, str]:
    files = {}
    for p in cfg.tap.ports:
        files[f"{NET}/05-goatrope-{p}.network"] = _network_port(cfg, p)
    if cfg.tap.mode == "inline":
        files.update(_bridge_files(cfg))
    files[SYSCTL] = _sysctl(cfg)
    files[f"{UNITS}/goatrope-ports.service"] = _ports_unit(cfg)
    files[f"{UNITS}/goatrope-record@.service"] = _record_unit(cfg)
    files[WATCHDOG_DROPIN] = _watchdog()
    if nm_present:
        files[NM] = _nm(cfg)
    return files


def units(cfg: cfgmod.Config) -> list[str]:
    return ["goatrope-ports.service"] + [f"goatrope-record@{p}.service" for p in cfg.tap.record.ports]


# ---------------------------------------------------------------- refusals

def _os_release() -> dict[str, str]:
    path = os.environ.get("GOATROPE_OS_RELEASE", "/etc/os-release")
    out = {}
    for line in (su.read(path, "") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"')
    return out


def preflight(cfg: cfgmod.Config, prior_state: dict | None) -> None:
    tap = cfg.tap
    osr = _os_release()
    if osr.get("ID") != "ubuntu" or osr.get("VERSION_ID") not in ("24.04", "26.04"):
        raise Refusal(f"this is {osr.get('PRETTY_NAME', 'an unknown system')}; goatrope supports Ubuntu 24.04 and 26.04")
    if os.uname().machine not in ("aarch64", "x86_64"):
        raise Refusal(f"architecture {os.uname().machine} is not supported (arm64 and amd64 are)")
    for tool in ("tcpdump", "ethtool", "tc", "ip", "ss", "networkctl", "systemctl"):
        if not su.have(tool):
            raise Refusal(f"{tool} is not installed: sudo apt-get install -y tcpdump ethtool iproute2 systemd")
    if not su.exists(tap.management):
        raise Refusal(f"the management interface {tap.management} does not exist (see: ip -br link)")
    ours = {BRIDGE}
    for p in tap.ports:
        if not su.exists(p):
            raise Refusal(f"no interface {p} (see: ip -br link)")
        if p == "lo" or su.kind(p) in ("bridge", "bond", "wireguard", "tun", "vlan"):
            raise Refusal(f"{p} is a {su.kind(p) or 'loopback'} interface, not an Ethernet port")
        if os.path.exists(f"{su.SYS_NET}/{p}/wireless"):
            raise Refusal(f"{p} is wireless; a tap port is wired")
        m = su.master(p)
        if m and m not in ours:
            raise Refusal(f"{p} is already a member of {m}; remove it from there first")
        stacked = [u for u in su.uppers(p) if u not in ours]
        if stacked:
            raise Refusal(f"{p} carries {', '.join(stacked)} (a VLAN or other device on top of it); "
                          "remove it first, or what uses it loses the link")
    taken = set(tap.ports) | ({BRIDGE} if su.exists(BRIDGE) else set())
    for p in sorted(taken):
        addrs = [a for a in su.addresses(p) if not a.lower().startswith("fe80:")]  # link-local goes with IPv6
        if addrs:
            raise Refusal(f"{p} has address(es) {', '.join(addrs)}: it is in use. A tap port has no address; "
                          "move what uses it to the management interface first")
    for dev in su.default_route_devs():
        if dev in taken:
            raise Refusal(f"the default route leaves through {dev}; it cannot become a tap port")
    sess = su.session()
    if sess and sess[1] & taken:
        raise Refusal(f"{', '.join(sorted(sess[1] & taken))} carries this session (from {sess[0]}); "
                      f"manage the machine over {tap.management} first")
    for peer, devs in su.established():
        if devs & taken:
            raise Refusal(f"{', '.join(sorted(devs & taken))} carries an established connection to {peer}; "
                          "it cannot become a tap port")
    r = tap.record
    # one ring per recorded port, plus what file destinations may hold (twice max_mb each)
    need = len(r.ports) * r.files * r.file_mb * 1_000_000
    need += sum(2 * d.max_mb * 1_000_000 for s in cfg.sends for d in s.to if d.scheme == "file")
    probe = r.directory
    while not os.path.exists(probe):
        probe = os.path.dirname(probe)
    st = os.statvfs(probe)
    free = st.f_bavail * st.f_frsize
    used = 0
    if os.path.isdir(r.directory):
        used = sum(os.path.getsize(os.path.join(r.directory, f)) for f in os.listdir(r.directory))
    # leave 10% of what is available, and at least 5% of the filesystem, for the system
    room = min(0.9 * (free + used), free + used - 0.05 * st.f_blocks * st.f_frsize)
    if need > room:
        raise Refusal(f"the recording ({len(r.ports)} ring(s) of {r.files} x {r.file_mb} MB"
                      f"{' plus file destinations' if any(d.scheme == 'file' for s in cfg.sends for d in s.to) else ''}"
                      f" = {need / 1e9:.1f} GB) does not fit in the {max(room, 0) / 1e9:.1f} GB goatrope may use "
                      f"at {probe}; declare fewer or smaller files")
    if cfg.relay and tap.mode == "listen":
        for n in (cfg.relay.link_interface, cfg.relay.remote_interface):
            if n in tap.ports:
                raise Refusal(f"{n} is a listen port and also a relay interface")


# ---------------------------------------------------------------- port preparation (boot and install)

def _wait_for(ifname: str, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if su.exists(ifname):
            return True
        time.sleep(0.5)
    return su.exists(ifname)


def apply_ports(cfg: cfgmod.Config, wait: float = 120) -> list[str]:
    """Idempotent. Returns the problems found; an empty list is success."""
    tap = cfg.tap
    problems = []
    for p in tap.ports:
        if not _wait_for(p, wait):
            problems.append(f"{p} did not appear within {wait:.0f} s")
            continue
        su.write(f"/proc/sys/net/ipv6/conf/{p}/disable_ipv6", "1")
        for short in su.OFFLOADS:
            su.run(["ethtool", "-K", p, short, "off"])
        su.run(["ethtool", "--set-eee", p, "eee", "off"])
        if tap.speed_mbps:
            r = su.run(["ethtool", "-s", p, "speed", str(tap.speed_mbps), "duplex", "full", "autoneg", "off"])
            if r.returncode != 0:
                problems.append(f"{p}: could not force {tap.speed_mbps} Mb/s full duplex: {r.stderr.strip()}")
        if tap.mode == "listen":
            if not su.egress_drop(p):
                su.run(["tc", "qdisc", "replace", "dev", p, "clsact"])
                su.run(["tc", "filter", "add", "dev", p, "egress", "pref", "1", "handle", "1",
                        "matchall", "action", "drop"])
            if not su.egress_drop(p):
                problems.append(f"{p}: the egress drop could not be installed; the link stays down")
                su.run(["ip", "link", "set", p, "down"])
                continue
            su.run(["ip", "link", "set", p, "arp", "off"])
            su.run(["ip", "link", "set", p, "up"])
    if tap.mode == "inline" and _wait_for(BRIDGE, 10):
        su.write(f"/proc/sys/net/ipv6/conf/{BRIDGE}/disable_ipv6", "1")
        # networkd sets these when it creates the bridge, not on an existing one; assert them every time.
        # STP off first: the kernel refuses a forward delay under 2 s while STP is on.
        su.run(["ip", "link", "set", BRIDGE, "type", "bridge", "stp_state", "0"])
        su.run(["ip", "link", "set", BRIDGE, "type", "bridge", "forward_delay", "0",
                "group_fwd_mask", hex(LLDP_MASK), "mcast_snooping", "0"])
    return problems


# ---------------------------------------------------------------- install

def _snapshot_port(p: str) -> dict:
    fl = su.flags(p)
    return {"features": {k: v[0] for k, v in su.features(p).items() if not v[1]},
            "eee": su.eee(p), "link": su.link_settings(p), "up": "UP" in fl, "noarp": "NOARP" in fl,
            "disable_ipv6": su.read(f"/proc/sys/net/ipv6/conf/{p}/disable_ipv6"),
            "addr_gen_mode": su.read(f"/proc/sys/net/ipv6/conf/{p}/addr_gen_mode"),
            "clsact": "clsact" in su.run(["tc", "qdisc", "show", "dev", p]).stdout}


def _load_state() -> dict | None:
    """None when goatrope is not installed. An unreadable state file is never taken for "not installed"."""
    if not os.path.exists(STATE):
        return None
    for path in (STATE, STATE + ".bak"):
        try:
            with open(path, encoding="utf-8") as f:
                state = json.load(f)
            if isinstance(state, dict) and "ports" in state:
                if path != STATE:
                    print(f"goatrope: {STATE} is unreadable; using the previous copy {path}", file=sys.stderr)
                return state
        except (OSError, ValueError):
            continue
    raise Refusal(f"{STATE} is unreadable or empty (a power cut during install?) and has no readable "
                  f"previous copy; goatrope will not guess what to restore. Inspect it, restore the "
                  "ports by hand, then remove it")


def _install_software() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(LIB, "goatrope")
    if os.path.realpath(here) != os.path.realpath(target):
        tmp = LIB + ".new"
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(here, os.path.join(tmp, "goatrope"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(os.path.join(os.path.dirname(here), "VERSION") if os.path.exists(
            os.path.join(os.path.dirname(here), "VERSION")) else os.path.join(here, "VERSION"),
            os.path.join(tmp, "goatrope", "VERSION"))
        old = LIB + ".old"
        shutil.rmtree(old, ignore_errors=True)
        su.run(["sync"])
        if os.path.isdir(LIB):
            os.rename(LIB, old)  # LIB is missing only between these two renames
        os.rename(tmp, LIB)
        su.fsync_dir(os.path.dirname(LIB))
        shutil.rmtree(old, ignore_errors=True)
    wrapper = ("#!/usr/bin/python3 -I\n# Written by goatrope install; goatrope uninstall removes it.\n"
               f"import sys\nsys.path.insert(0, {LIB!r})\nfrom goatrope.cli import main\nsys.exit(main())\n")
    su.write_file(BIN, wrapper, 0o755)


def install(cfg: cfgmod.Config, log=print) -> None:
    prior_state = _load_state()
    preflight(cfg, prior_state)
    from . import send as sendmod
    bad = sendmod.refuse_tap_routes(cfg)
    if bad:
        raise Refusal("; ".join(bad) + ": decode-and-send never transmits on the tapped link")
    tap = cfg.tap
    nm_present = os.path.isdir("/etc/NetworkManager")
    files = render(cfg, nm_present)
    files.update(sendmod.render(cfg))

    state = prior_state or {
        "ports": {},
        "networkd": {"enabled": su.unit_enabled("systemd-networkd.service"),
                     "active": su.unit_active("systemd-networkd.service"),
                     "links": _networkd_links()},
        "created_dirs": [],
        "var_lib_private_existed": os.path.isdir("/var/lib/private"),  # systemd makes it for DynamicUser
    }
    for p in tap.ports:  # first sight of a port: remember how it was
        state["ports"].setdefault(p, _snapshot_port(p))
    state["version"] = VERSION
    state["mode"] = tap.mode
    state["record_directory"] = tap.record.directory
    stale = [f for f in state.get("files", []) if f not in files]

    for d in (STATE_DIR, ETC, tap.record.directory) + tuple(sorted({os.path.dirname(f) for f in files})):
        _makedirs(d, state)  # every directory install creates is in the state before anything is written
    shutil.chown(tap.record.directory, "tcpdump", "tcpdump") if _user("tcpdump") else None
    os.chmod(tap.record.directory, 0o750)
    state["files"] = sorted(files)
    _save_state(state)  # before any change, so uninstall can always undo

    _install_software()
    if os.path.realpath(cfg.path) != os.path.realpath(f"{ETC}/goatrope.toml"):
        with open(cfg.path, encoding="utf-8") as f:
            text = f.read()
        prev = su.read(f"{ETC}/goatrope.toml")
        if prev is not None and prev != text.strip():
            su.write_file(f"{ETC}/goatrope.toml.prev", prev + "\n")
            log(f"  the previous declaration is kept as {ETC}/goatrope.toml.prev")
        su.write_file(f"{ETC}/goatrope.toml", text)
    for f in stale:
        _remove(f)
    for path, content in files.items():
        su.write_file(path, content, sendmod.MODES.get(path, 0o644))
    for unit in [u for u in state.get("units", []) if u not in units(cfg) + sendmod.units(cfg)]:
        su.systemctl("disable", "--now", unit)
    state["units"] = units(cfg) + sendmod.units(cfg)
    _save_state(state)

    su.systemctl("daemon-reload")
    su.run(["sysctl", "-q", "-p", SYSCTL])
    if nm_present and su.nm_active():
        su.run(["nmcli", "general", "reload", "conf"])  # NetworkManager lets go of the tap ports now, not at reboot
        _nm_wait_unmanaged(cfg)
    su.systemctl("enable", "--now", "systemd-networkd.service")
    su.run(["networkctl", "reload"])
    if tap.mode == "listen" and su.exists(BRIDGE):
        su.run(["ip", "link", "del", BRIDGE])  # left from an earlier inline declaration
    for p in tap.ports:
        su.run(["networkctl", "reconfigure", p])
    problems = apply_ports(cfg, wait=10)
    for p in problems:
        log(f"  warning: {p}")
    su.systemctl("enable", "goatrope-ports.service")
    su.systemctl("restart", "goatrope-ports.service")
    for p in tap.record.ports:
        su.systemctl("enable", f"goatrope-record@{p}.service")
        su.systemctl("restart", f"goatrope-record@{p}.service")
    sendmod.start(cfg, log)
    su.systemctl("daemon-reexec")  # applies the watchdog setting
    _settle(cfg)


def _networkd_links() -> list[str]:
    """The enable links of systemd-networkd and the units enabled with it, under /etc/systemd/system."""
    out = []
    for dirpath, dirnames, names in os.walk("/etc/systemd/system"):
        for n in dirnames + names:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) and os.path.basename(os.readlink(p)).startswith("systemd-network"):
                out.append(p)
    return sorted(out)


def _nm_wait_unmanaged(cfg: cfgmod.Config, seconds: float = 10) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        st = su.nm_states()
        if all(st.get(p, "unmanaged") == "unmanaged" for p in cfg.tap.ports):
            return
        time.sleep(0.5)


def _settle(cfg: cfgmod.Config, seconds: float = 15) -> None:
    """Wait until networkd has built the declared shape, or give up quietly."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cfg.tap.mode == "listen":
            if all("UP" in su.flags(p) for p in cfg.tap.ports):
                return
        elif su.exists(BRIDGE) and all(su.master(p) == BRIDGE for p in cfg.tap.ports):
            return
        time.sleep(0.5)


def _user(name: str) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _save_state(state: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    text = json.dumps(state, indent=2, sort_keys=True) + "\n"
    if os.path.exists(STATE):
        try:
            with open(STATE, encoding="utf-8") as f:
                json.load(f)
            shutil.copyfile(STATE, STATE + ".bak")  # the previous good copy
        except (OSError, ValueError):
            pass
    su.write_file(STATE, text, 0o600)


def _makedirs(d: str, state: dict) -> None:
    """Create d and any missing parents, remembering each so uninstall can remove it."""
    missing = []
    while d and not os.path.isdir(d):
        missing.append(d)
        d = os.path.dirname(d)
    for m in reversed(missing):
        os.mkdir(m, 0o755)
        if m not in state["created_dirs"]:
            state["created_dirs"].append(m)


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------- uninstall

def uninstall(purge: bool, log=print) -> None:
    state = _load_state()
    if state is None:
        if purge:
            _purge_leftovers(log)
        else:
            log("goatrope is not installed (no state file); nothing to remove")
        return
    for unit in reversed(state.get("units", [])):
        su.systemctl("disable", "--now", unit)
    for f in state.get("files", []):
        _remove(f)
    su.systemctl("daemon-reload")
    if su.nm_active():
        su.run(["nmcli", "general", "reload", "conf"])
    su.run(["networkctl", "reload"])
    if su.exists(BRIDGE):
        su.run(["ip", "link", "del", BRIDGE])
    for p, prior in state.get("ports", {}).items():
        if not su.exists(p):
            continue
        if not prior.get("up"):
            su.run(["ip", "link", "set", p, "down"])  # down before the egress drop goes
        if prior.get("clsact"):
            su.run(["tc", "filter", "del", "dev", p, "egress", "pref", "1", "handle", "1", "matchall"])
        else:
            su.run(["tc", "qdisc", "del", "dev", p, "clsact"])
        for short, val in prior.get("features", {}).items():
            su.run(["ethtool", "-K", p, short, val])
        if prior.get("eee") == "enabled":
            su.run(["ethtool", "--set-eee", p, "eee", "on"])
        link = prior.get("link", {})
        if link.get("autoneg") == "on" and su.link_settings(p).get("autoneg") == "off":
            su.run(["ethtool", "-s", p, "autoneg", "on"])
        su.run(["ip", "link", "set", p, "arp", "off" if prior.get("noarp") else "on"])
        if prior.get("addr_gen_mode") is not None:
            su.write(f"/proc/sys/net/ipv6/conf/{p}/addr_gen_mode", prior["addr_gen_mode"])
        if prior.get("disable_ipv6") is not None:
            su.write(f"/proc/sys/net/ipv6/conf/{p}/disable_ipv6", prior["disable_ipv6"])
        su.run(["ip", "link", "set", p, "up" if prior.get("up") else "down"])
        su.run(["networkctl", "reconfigure", p])
    nd = state.get("networkd", {})
    if "links" in nd:  # netplan enables networkd under /run only, so `disable` alone cannot say what to undo
        for link in set(_networkd_links()) - set(nd["links"]):
            _remove(link)
    elif nd.get("enabled") in ("disabled", "masked"):
        su.systemctl("disable", "systemd-networkd.service")
    if nd.get("active") != "active":
        su.systemctl("stop", "systemd-networkd.service", "systemd-networkd.socket")
    su.systemctl("daemon-reexec")
    if os.path.isdir(LIB):
        shutil.rmtree(LIB)
    _remove(BIN)
    # verified component copies, and the state systemd kept for the decoders' dynamic users
    import glob
    for d in [f"{STATE_DIR}/components"] + glob.glob("/var/lib/private/goatrope-decode-*"):
        shutil.rmtree(d, ignore_errors=True)
    for link in glob.glob("/var/lib/goatrope-decode-*"):
        _remove(link)
    if os.path.isdir("/var/lib/private") and not os.listdir("/var/lib/private") \
            and state.get("var_lib_private_existed") is False:
        os.rmdir("/var/lib/private")
    kept = []
    rec = state.get("record_directory")
    if os.path.exists(f"{ETC}/goatrope.toml"):
        if purge:
            _remove(f"{ETC}/goatrope.toml")
        else:
            kept.append(f"{ETC}/goatrope.toml")
    for prev in (f"{ETC}/goatrope.toml.prev",):
        if os.path.exists(prev):
            _remove(prev) if purge else kept.append(prev)
    for d in [x for x in (rec, f"{STATE_DIR}/send") if x and x.startswith(STATE_DIR + "/")]:
        if os.path.isdir(d):
            if purge:
                shutil.rmtree(d)
            elif os.listdir(d):
                kept.append(d)
    _remove(STATE)
    _remove(STATE + ".bak")
    if purge:
        for f in (f"{STATE_DIR}/relay.health",):
            _remove(f)
    # Directories install created, deepest first, when empty.
    for d in sorted(state.get("created_dirs", []), key=len, reverse=True):
        if os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)
        elif os.path.isdir(d) and d not in kept and not any(k.startswith(d + "/") for k in kept):
            kept.append(d)
    log("goatrope removed: units, network files, sysctl, watchdog drop-in, software; interface settings restored")
    if kept:
        log("kept (goatrope uninstall --purge removes them): " + ", ".join(kept))


def _purge_leftovers(log=print) -> None:
    """After a plain uninstall: the declaration and the recordings are all that remain."""
    removed = []
    rec = None
    try:
        rec = cfgmod.load(f"{ETC}/goatrope.toml").tap.record.directory
    except (cfgmod.ConfigError, AttributeError):
        pass
    for d in [x for x in (rec, f"{STATE_DIR}/record", f"{STATE_DIR}/send") if x and x.startswith(STATE_DIR + "/")]:
        if os.path.isdir(d):
            shutil.rmtree(d)
            removed.append(d)
    for f in (f"{ETC}/goatrope.toml", f"{ETC}/goatrope.toml.prev", f"{STATE_DIR}/relay.health"):
        if os.path.exists(f):
            _remove(f)
            removed.append(f)
    for d in (ETC, STATE_DIR):
        if os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)
            removed.append(d)
    log("purged: " + (", ".join(removed) if removed else "nothing was left"))


# ---------------------------------------------------------------- check

def _item(items: list, id_: str, ok, want, have) -> None:
    items.append({"id": id_, "ok": ok, "want": want, "have": have})


def check(cfg: cfgmod.Config) -> list[dict]:
    """Every property the declaration implies, compared with the machine. ok is True, False or None (info)."""
    tap = cfg.tap
    items: list[dict] = []
    state = _load_state()
    _item(items, "installed", state is not None, "goatrope state present", "present" if state else "absent")
    inst = su.read(os.path.join(LIB, "goatrope", "VERSION"))
    _item(items, "software", inst == VERSION, VERSION, inst or "absent")
    nm_present = os.path.isdir("/etc/NetworkManager")
    from . import send as sendmod
    expected = render(cfg, nm_present)
    expected.update(sendmod.render(cfg))
    for path, content in sorted(expected.items()):
        have = su.read(path)
        _item(items, f"file:{path}", have is not None and have == content.strip(),
              "as declared", "absent" if have is None else ("as declared" if have == content.strip() else "differs"))
    for unit in units(cfg) + sendmod.units(cfg):
        a = su.unit_active(unit)
        _item(items, f"unit:{unit}", a == "active", "active", a)
        e = su.unit_enabled(unit)
        _item(items, f"enabled:{unit}", e == "enabled", "enabled", e)
    a = su.unit_active("systemd-networkd.service")
    _item(items, "unit:systemd-networkd.service", a == "active", "active", a)

    mg = tap.management
    _item(items, f"management:{mg}", su.exists(mg) and mg not in tap.ports, "exists, not a tap port",
          "exists" if su.exists(mg) else "absent")
    taken = set(tap.ports) | {BRIDGE}
    bad = [d for d in su.default_route_devs() if d in taken]
    _item(items, "default-route", not bad, "not through a tap port", ", ".join(bad) or "not through a tap port")

    for p in tap.ports:
        if not su.exists(p):
            _item(items, f"port:{p}", False, "exists", "absent")
            continue
        addrs = su.addresses(p)
        _item(items, f"address:{p}", not addrs, "none", ", ".join(addrs) or "none")
        v6 = su.read(f"/proc/sys/net/ipv6/conf/{p}/disable_ipv6")
        _item(items, f"ipv6-disabled:{p}", v6 == "1", "1", v6)
        nf = su.run(["networkctl", "status", p, "--no-pager"]).stdout
        nfile = next((ln.split(":", 1)[1].strip() for ln in nf.splitlines()
                      if ln.strip().startswith("Network File:")), "none")
        want_file = f"{NET}/05-goatrope-{p}.network"
        _item(items, f"network-file:{p}", nfile == want_file, want_file, nfile)
        for short, (val, fixed) in sorted(su.features(p).items()):
            _item(items, f"offload:{p}:{short}", val == "off" or fixed, "off",
                  val + (" (fixed by the driver)" if fixed and val == "on" else ""))
        e = su.eee(p)
        _item(items, f"eee:{p}", e != "enabled", "off", e)
        if tap.speed_mbps:
            ls = su.link_settings(p)
            ok = ls["autoneg"] == "off" and (ls["speed"] in (None, tap.speed_mbps))
            _item(items, f"speed:{p}", ok, f"{tap.speed_mbps} Mb/s full, autonegotiation off",
                  f"{ls['speed']} Mb/s {ls['duplex']}, autonegotiation {ls['autoneg']}")
        fl = su.flags(p)
        _item(items, f"up:{p}", "UP" in fl, "up", "up" if "UP" in fl else "down")
        if tap.mode == "listen":
            m = su.master(p)
            _item(items, f"no-bridge:{p}", m is None, "in no bridge", m or "in no bridge")
            _item(items, f"egress-drop:{p}", su.egress_drop(p), "every outgoing frame dropped",
                  "present" if su.egress_drop(p) else "absent")
            _item(items, f"noarp:{p}", "NOARP" in fl, "ARP off", "ARP off" if "NOARP" in fl else "ARP on")
        else:
            m = su.master(p)
            _item(items, f"bridge-member:{p}", m == BRIDGE, BRIDGE, m or "none")

    if su.nm_active():
        st = su.nm_states()
        for p in tap.ports:
            _item(items, f"networkmanager-unmanaged:{p}", st.get(p, "unmanaged") == "unmanaged",
                  "unmanaged", st.get(p, "absent"))
    for p in tap.ports:
        stacked = [u for u in su.uppers(p) if u != BRIDGE]
        _item(items, f"nothing-stacked:{p}", not stacked, "no VLAN or other device on top", ", ".join(stacked) or "none")

    if tap.mode == "inline":
        b = f"{su.SYS_NET}/{BRIDGE}/bridge"
        if not su.exists(BRIDGE):
            _item(items, f"bridge:{BRIDGE}", False, "exists", "absent")
        else:
            members = sorted(os.listdir(f"{su.SYS_NET}/{BRIDGE}/brif"))
            _item(items, "bridge-members", members == sorted(tap.ports), sorted(tap.ports), members)
            stp = su.read(f"{b}/stp_state")
            _item(items, "bridge-stp", stp == "0", "0 (off)", stp)
            fd = su.read(f"{b}/forward_delay")
            _item(items, "bridge-forward-delay", fd == "0", "0", fd)
            for p in members:
                st = su.read(f"{su.SYS_NET}/{BRIDGE}/brif/{p}/state")
                _item(items, f"bridge-port-forwarding:{p}", st == "3", "3 (forwarding)", st)
            mask = int(su.read(f"{b}/group_fwd_mask", "0") or "0", 0)
            _item(items, "bridge-lldp-forwarded", bool(mask & LLDP_MASK), f"bit 14 set ({LLDP_MASK:#x})", hex(mask))
            addrs = su.addresses(BRIDGE)
            _item(items, "bridge-address", not addrs, "none", ", ".join(addrs) or "none")
            v6 = su.read(f"/proc/sys/net/ipv6/conf/{BRIDGE}/disable_ipv6")
            _item(items, "bridge-ipv6-disabled", v6 == "1", "1", v6)
            fl = su.flags(BRIDGE)
            _item(items, "bridge-up", "UP" in fl, "up", "up" if "UP" in fl else "down")
        for key in ("iptables", "ip6tables", "arptables"):
            v = su.read(f"/proc/sys/net/bridge/bridge-nf-call-{key}")
            if v is not None:
                _item(items, f"bridge-nf-call-{key}", v == "0", "0", v)

    r = tap.record
    for p in r.ports:
        _item(items, f"record-port:{p}", p in tap.ports and p != BRIDGE, "a tap port, not the bridge", p)
    if os.path.isdir(r.directory):
        n = {p: len([f for f in os.listdir(r.directory) if f.startswith(f"{p}.pcap")]) for p in r.ports}
        for p, count in n.items():
            _item(items, f"ring:{p}", count <= r.files, f"at most {r.files} files of {r.file_mb} MB", f"{count} files")
    else:
        _item(items, "ring-directory", False, r.directory, "absent")

    rt = su.systemctl("show", "-p", "RuntimeWatchdogUSec", "--value").stdout.strip()
    _item(items, "watchdog-runtime", rt in (f"{WATCHDOG_SEC}s", f"{WATCHDOG_SEC * 1_000_000}"),
          f"{WATCHDOG_SEC}s", rt or "unknown")
    dev = os.environ.get("GOATROPE_TEST_WATCHDOG_DEVICE")
    if dev:
        _item(items, "watchdog-device", os.path.exists(dev), "a watchdog device",
              f"test stand-in {dev}, the hardware was not checked")
    else:
        devs = sorted(d for d in os.listdir("/dev") if d.startswith("watchdog"))
        _item(items, "watchdog-device", bool(devs), "a watchdog device", ", ".join(devs) or "none")
    if cfg.relay is not None and tap.mode == "listen":
        clash = [n for n in (cfg.relay.link_interface, cfg.relay.remote_interface) if n in tap.ports]
        _item(items, "relay-not-on-listen-port", not clash, "no relay interface is a listen port", ", ".join(clash) or "none")

    root_crypt = "dm-crypt" if "crypt" in su.run(["lsblk", "-no", "TYPE", "-s",
                                                    su.run(["findmnt", "-no", "SOURCE", "/"]).stdout.strip()]
                                                   ).stdout else "not encrypted (or not detected)"
    _item(items, "root-encryption", None, "encrypted root (deferred; not a check yet)", root_crypt)
    items.extend(sendmod.check(cfg))
    return items


# ---------------------------------------------------------------- status

def status(cfg: cfgmod.Config, log=print) -> int:
    tap = cfg.tap
    log(f"goatrope {VERSION}  config {cfg.path}")
    log(banner(tap))
    for p in tap.ports:
        if not su.exists(p):
            log(f"  port {p:<16} absent")
            continue
        carrier = su.read(f"{su.SYS_NET}/{p}/carrier", "?")
        speed = su.read(f"{su.SYS_NET}/{p}/speed", "?")
        log(f"  port {p:<16} carrier={carrier} speed={speed} Mb/s  addresses={len(su.addresses(p))}"
            + (f"  egress-drop={'yes' if su.egress_drop(p) else 'NO'}" if tap.mode == "listen" else ""))
    if tap.mode == "inline":
        if su.exists(BRIDGE):
            members = sorted(os.listdir(f"{su.SYS_NET}/{BRIDGE}/brif"))
            log(f"  bridge {BRIDGE} {su.read(f'{su.SYS_NET}/{BRIDGE}/operstate')}  members={' '.join(members)}  "
                f"stp={su.read(f'{su.SYS_NET}/{BRIDGE}/bridge/stp_state')}")
        else:
            log(f"  bridge {BRIDGE} absent")
    r = tap.record
    for p in r.ports:
        files = sorted(f for f in os.listdir(r.directory) if f.startswith(f"{p}.pcap")) \
            if os.path.isdir(r.directory) else []
        size = sum(os.path.getsize(os.path.join(r.directory, f)) for f in files)
        log(f"  record {p:<14} {su.unit_active(f'goatrope-record@{p}.service'):<9} {len(files)} of {r.files} files, "
            f"{size / 1e6:.1f} MB, filter {r.filter or '(every frame)'!r}")
    from . import send as sendmod
    sendmod.status(cfg, log)
    items = check(cfg)
    bad = [i for i in items if i["ok"] is False]
    log(f"  check  {'match' if not bad else f'differs in {len(bad)} of {len(items)} items (goatrope check)'}")
    return 0
