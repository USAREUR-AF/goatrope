#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Network-namespace tests of the tap role, run inside a privileged container with
systemd as PID 1 (tests/netns/run.sh starts it).

Topology. The container is the tap machine; its eth0 (Docker's) is the management
interface and carries the default route.

  inline:  ns a [a0 192.0.2.1] ==veth== tp0 ]-bridge-[ tp1 ==veth== [b0 192.0.2.2] ns b
  listen:  ns feed [f0] ==veth== tp0      ns feed [f1] ==veth== tp1   (f0, f1 stand for a passive
           tap's two outputs: frames are injected there and must only ever flow toward the tap)

Phases: refusals, inline, reboot-prepare, reboot-verify, listen, send. Each prints one
line per assertion (ok / not ok / limit) and exits non-zero when any assertion failed.
Addresses are documentation addresses (RFC 5737); nothing here names a real network.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GR = [sys.executable, "-I", os.path.join(SRC, "bin", "goatrope")]
WORK = "/root/gt"
CFG = f"{WORK}/goatrope.toml"
RING = "/var/lib/goatrope/record"
MAGIC = b"GTROPE"
os.environ["GOATROPE_TEST_WATCHDOG_DEVICE"] = f"{WORK}/watchdog-stand-in"
FAILED = []
RESULTS = []


def sh(cmd: str, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def gr(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(GR + list(args), capture_output=True, text=True, env=e)


def result(ok: bool | None, name: str, detail: str = "") -> None:
    tag = {True: "ok", False: "not ok", None: "limit"}[ok]
    line = f"{tag} - {name}" + (f"  [{detail}]" if detail else "")
    print(line, flush=True)
    RESULTS.append({"result": tag, "name": name, "detail": detail})
    if ok is False:
        FAILED.append(name)


def write_cfg(text: str, path: str = CFG) -> str:
    os.makedirs(WORK, exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


INLINE = """schema = 1
[tap]
mode = "inline"
ports = ["tp0", "tp1"]
management = "eth0"
[tap.record]
ports = ["tp0"]
filter = ""
file_mb = 5
files = 4
"""

LISTEN = """schema = 1
[tap]
mode = "listen"
source = "mirror-port"
ports = ["tp0", "tp1"]
management = "eth0"
[tap.record]
ports = ["tp0", "tp1"]
filter = ""
file_mb = 5
files = 4
"""


# ---------------------------------------------------------------- topology

def topo_inline() -> None:
    for ns, peer, port, addr in (("a", "a0", "tp0", "192.0.2.1/24"), ("b", "b0", "tp1", "192.0.2.2/24")):
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip link del {port}", check=False)
        sh(f"ip netns add {ns}")
        sh(f"ip link add {port} type veth peer name {peer}")
        sh(f"ip link set {peer} netns {ns}")
        sh(f"ip -n {ns} link set lo up")
        sh(f"ip -n {ns} addr add {addr} dev {peer}")
        sh(f"ip -n {ns} link set {peer} up")
        sh(f"ip netns exec {ns} ethtool -K {peer} tso off gso off gro off", check=False)


def topo_listen() -> None:
    sh("ip netns del feed", check=False)
    sh("ip netns add feed")
    sh("ip -n feed link set lo up")
    for peer, port in (("f0", "tp0"), ("f1", "tp1")):
        sh(f"ip link del {port}", check=False)
        sh(f"ip link add {port} type veth peer name {peer}")
        sh(f"ip link set {peer} netns feed")
        sh(f"ip -n feed link set {peer} up")
        # f0 and f1 stand for the outputs of a tap device: they send, never answer.
        sh(f"ip netns exec feed sysctl -qw net.ipv6.conf.{peer}.disable_ipv6=1")
        sh(f"ip -n feed link set {peer} arp off")


def snapshot() -> dict:
    """Files under /etc, /usr/local and /var/lib (minus package and journal state), units, and port state."""
    files = {}
    for root in ("/etc", "/usr/local", "/var/lib"):
        for dp, dn, fn in os.walk(root):
            if dp.startswith(("/var/lib/systemd", "/var/lib/dpkg", "/var/lib/apt", "/etc/ld.so.cache")):
                continue
            for d in dn:
                p = os.path.join(dp, d)
                files[p] = "dir"
            for f in fn:
                p = os.path.join(dp, f)
                if p in ("/etc/ld.so.cache", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/etc/mtab"):
                    continue
                try:
                    if os.path.islink(p):
                        files[p] = "->" + os.readlink(p)
                    else:
                        with open(p, "rb") as fh:
                            files[p] = hashlib.sha256(fh.read()).hexdigest()
                except OSError:
                    files[p] = "unreadable"
    ports = {}
    for p in ("tp0", "tp1"):
        if not os.path.exists(f"/sys/class/net/{p}"):
            continue
        link = json.loads(sh(f"ip -j -d link show dev {p}").stdout)[0]
        ports[p] = {
            "flags": sorted(link.get("flags", [])), "master": link.get("master"),
            "addr": sh(f"ip -br addr show dev {p}").stdout.split()[2:],
            "tc": " ".join(ln for ln in sh(f"tc qdisc show dev {p}").stdout.splitlines() if "noqueue" not in ln),
            "features": sh(f"ethtool -k {p} | grep -E '^(generic-receive|large-receive|tcp-segmentation|generic-segmentation)-offload'").stdout,
            "disable_ipv6": open(f"/proc/sys/net/ipv6/conf/{p}/disable_ipv6").read().strip(),
        }
    return {"files": files, "ports": ports,
            "bridge": os.path.exists("/sys/class/net/goatrope0"),
            "units": sh("systemctl list-unit-files 'goatrope*' --no-legend", check=False).stdout.strip(),
            "networkd": sh("systemctl is-enabled systemd-networkd.service", check=False).stdout.strip() + "/"
                        + sh("systemctl is-active systemd-networkd.service", check=False).stdout.strip(),
            "watchdog": sh("systemctl show -p RuntimeWatchdogUSec --value").stdout.strip()}


def diff(a: dict, b: dict) -> list[str]:
    out = []
    for k in sorted(set(a["files"]) | set(b["files"])):
        if a["files"].get(k) != b["files"].get(k):
            out.append(f"file {k}: {a['files'].get(k, 'absent')[:16]} -> {b['files'].get(k, 'absent')[:16]}")
    for k in ("ports", "bridge", "units", "networkd", "watchdog"):
        if a[k] != b[k]:
            out.append(f"{k}: {a[k]} -> {b[k]}")
    return out


# ---------------------------------------------------------------- frames and pcap

def read_pcaps(paths: list[str]) -> list[bytes]:
    frames = []
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 24:
            continue
        magic = data[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        off = 24
        while off + 16 <= len(data):
            _, _, incl, _ = struct.unpack_from(endian + "IIII", data, off)
            off += 16
            frames.append(data[off:off + incl])
            off += incl
    return frames


def ring_frames(port: str) -> list[bytes]:
    return read_pcaps(sorted(glob.glob(f"{RING}/{port}.pcap*")))


def flush_recorders(ports: list[str]) -> None:
    for p in ports:
        sh(f"systemctl stop goatrope-record@{p}.service")


def start_recorders(ports: list[str]) -> None:
    for p in ports:
        sh(f"systemctl start goatrope-record@{p}.service")


class Capture:
    """tcpdump -Q in on an interface inside a namespace, written to a pcap file."""

    def __init__(self, ns: str, ifname: str, name: str):
        self.path = f"{WORK}/{name}.pcap"
        self._start(["ip", "netns", "exec", ns, "tcpdump", "--immediate-mode", "-n", "-i", ifname, "-Q", "in",
                     "-s", "0", "-U", "-w", self.path])

    def _start(self, argv: list[str]) -> None:
        # Wait for tcpdump to say it is listening; a fixed sleep missed frames right after boot.
        self.p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        import select
        end = time.monotonic() + 15
        while time.monotonic() < end:
            r, _, _ = select.select([self.p.stderr], [], [], 0.5)
            if r and "listening on" in self.p.stderr.readline():
                break
        time.sleep(0.2)

    def stop(self) -> list[bytes]:
        time.sleep(0.5)
        self.p.send_signal(signal.SIGINT)
        self.p.wait(timeout=10)
        return read_pcaps([self.path])


class RootCapture(Capture):
    """The same, in the tap machine's own namespace, both directions."""

    def __init__(self, ifname: str, name: str):
        self.path = f"{WORK}/{name}.pcap"
        self._start(["tcpdump", "--immediate-mode", "-n", "-i", ifname, "-s", "0", "-U", "-w", self.path])


def udp_send(ns: str, src: str, dst: str, port: int, n: int, tag: bytes) -> None:
    code = (f"import socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            f"s.bind(({src!r},0))\n"
            f"for i in range({n}):\n s.sendto({MAGIC!r}+{tag!r}+i.to_bytes(4,'big')+b'x'*40,({dst!r},{port}))\n"
            f" time.sleep(0.002)\n")
    sh(f"ip netns exec {ns} python3 -c \"{code}\"")


def raw_inject(ns: str, ifname: str, n: int, tag: bytes, dst_mac: bytes = b"\xff" * 6) -> None:
    code = (f"import socket\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(({ifname!r},0))\n"
            f"for i in range({n}):\n s.send({dst_mac!r}+b'\\x02\\x00\\x00\\x00\\x00\\x01'+b'\\x88\\xb5'+"
            f"{MAGIC!r}+{tag!r}+i.to_bytes(4,'big')+b'y'*40)\n")
    sh(f"ip netns exec {ns} python3 -c \"{code}\"")


def tagged(frames: list[bytes], tag: bytes) -> set[int]:
    out = set()
    key = MAGIC + tag
    for f in frames:
        i = f.find(key)
        if i >= 0 and len(f) >= i + len(key) + 4:
            out.add(int.from_bytes(f[i + len(key):i + len(key) + 4], "big"))
    return out


def macs(*ifs: str) -> set[bytes]:
    out = set()
    for i in ifs:
        if os.path.exists(f"/sys/class/net/{i}/address"):
            out.add(bytes.fromhex(open(f"/sys/class/net/{i}/address").read().strip().replace(":", "")))
    return out


def ports_settled() -> None:
    """goatrope-ports.service is Type=exec (boot does not wait for it); wait for its run to end."""
    for _ in range(60):
        if sh("systemctl show -p SubState --value goatrope-ports.service", check=False).stdout.strip() != "running":
            return
        time.sleep(0.5)


def check_exit(expect: int, name: str, *extra: str) -> dict | None:
    p = gr("check", "--config", CFG, *extra)
    detail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr.strip()[:200]
    if p.returncode != expect and "--json" not in extra:
        bad = [ln for ln in p.stdout.splitlines() if "DIFF" in ln]
        detail = "; ".join(bad[:6]) or detail
    result(p.returncode == expect, f"{name}: check exits {expect}", f"got {p.returncode}: {detail[:400]}")
    if "--json" in extra and p.stdout.strip().startswith("{"):
        return json.loads(p.stdout)
    return None


# ---------------------------------------------------------------- phases

def phase_refusals() -> None:
    topo_inline()
    before = snapshot()
    ok_cfg = INLINE

    def refused(name: str, text: str | None, expect_in: str, env: dict | None = None, setup=None, undo=None,
                cmd: str = "install") -> None:
        if text is not None:
            write_cfg(text)
        if setup:
            setup()
        try:
            p = gr(cmd, "--config", CFG, env=env)
        finally:
            if undo:
                undo()
        msg = (p.stderr + p.stdout).strip()
        changed = diff(before, snapshot())
        result(p.returncode == 2 and expect_in.lower() in msg.lower() and not changed,
               f"refused: {name}", f"exit {p.returncode}; {msg.splitlines()[-1][:160] if msg else ''}"
               + (f"; CHANGED {changed[:3]}" if changed else ""))

    refused("mode missing", ok_cfg.replace('mode = "inline"\n', ""), "missing required key(s) mode")
    refused("mode unknown", ok_cfg.replace('"inline"', '"fail-open"'), "must be \"inline\" or \"listen\"")
    refused("inline with one port", ok_cfg.replace('["tp0", "tp1"]', '["tp0"]'), "exactly 2")
    refused("listen with three ports", LISTEN.replace('["tp0", "tp1"]\nmanagement', '["tp0", "tp1", "eth0"]\nmanagement'),
            "1 to 2")
    refused("a port listed twice", ok_cfg.replace('["tp0", "tp1"]', '["tp0", "tp0"]'), "listed twice")
    refused("management is a tap port", ok_cfg.replace('management = "eth0"', 'management = "tp1"'),
            "also a tap port")
    refused("port does not exist", ok_cfg.replace('["tp0", "tp1"]', '["tp0", "tp9"]'), "no interface tp9")
    refused("port has an address", ok_cfg, "has address",
            setup=lambda: sh("ip addr add 198.51.100.7/32 dev tp1"),
            undo=lambda: sh("ip addr del 198.51.100.7/32 dev tp1"))

    def add_default():
        sh("sysctl -qw net.ipv6.conf.tp1.disable_ipv6=1; ip link set tp1 up")
        sh("ip route add 203.0.113.0/24 dev tp1")
        sh("ip route replace default dev tp1 metric 1")

    def del_default():
        sh("ip route del default dev tp1 metric 1")
        sh("ip route del 203.0.113.0/24 dev tp1")
        sh("ip link set tp1 down; sysctl -qw net.ipv6.conf.tp1.disable_ipv6=0")
    refused("default route through a port", ok_cfg, "default route leaves through tp1", setup=add_default,
            undo=del_default)
    refused("port carries this SSH session", ok_cfg, "carries this session",
            env={"SSH_CONNECTION": "203.0.113.9 50000 203.0.113.1 22"},
            setup=lambda: sh("ip link set tp0 up && ip route add 203.0.113.0/24 dev tp0"),
            undo=lambda: sh("ip route del 203.0.113.0/24 dev tp0; ip link set tp0 down"))
    refused("listen without a source", LISTEN.replace('source = "mirror-port"\n', ""), "source is required")
    refused("copper tap without a declared speed", LISTEN.replace('"mirror-port"', '"copper-tap"'),
            "speed_mbps is required")
    refused("record port not a tap port", ok_cfg.replace('ports = ["tp0"]\nfilter', 'ports = ["eth0"]\nfilter'),
            "is not one of [tap].ports")
    refused("inline records on the bridge device", ok_cfg.replace('ports = ["tp0"]\nfilter', 'ports = ["goatrope0"]\nfilter'),
            "is not one of [tap].ports")
    refused("no filter declared", ok_cfg.replace('filter = ""\n', ""), "missing required key(s) filter")
    refused("unknown key", ok_cfg + "\n[tap.extra]\nx = 1\n", "unknown key")
    refused("ring larger than the disk", ok_cfg.replace("file_mb = 5", "file_mb = 4096").replace("files = 4", "files = 10000"),
            "does not fit")
    refused("relay on a listen port", LISTEN + """
[relay]
wip = true
remote_interface = "eth0"
link_interface = "tp1"
link_address = "192.0.2.50/24"
allow = [{ direction = "remote-to-link", protocol = "udp", remote = "198.51.100.5", listen_port = 7000, target = "192.0.2.2", target_port = 7000 }]
""", "listen port")
    refused("relay not marked work in progress", ok_cfg + """
[relay]
wip = false
remote_interface = "eth0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [{ direction = "remote-to-link", protocol = "udp", remote = "198.51.100.5", listen_port = 7000, target = "192.0.2.2", target_port = 7000 }]
""", "wip must be true")
    refused("send destination reached through a tap port", ok_cfg + """
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp", dst_port = 5000 }
to = ["udp://203.0.113.20:5000"]
""", "a tap port", setup=lambda: sh("ip link set tp1 up && ip route add 203.0.113.0/24 dev tp1"),
            undo=lambda: sh("ip route del 203.0.113.0/24 dev tp1; ip link set tp1 down"))
    refused("Zenoh destination without a component", ok_cfg + """
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp", dst_port = 5000 }
to = ["zenoh://203.0.113.20:7447"]
""", "sends no Zenoh itself")
    refused("send with no address or port to match", ok_cfg + """
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp" }
to = ["udp://127.0.0.1:5000"]
""", "names nothing but the protocol")
    write_cfg(f"ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian 12\"\n", f"{WORK}/os-release")
    refused("unsupported operating system", ok_cfg, "supports Ubuntu 24.04 and 26.04",
            env={"GOATROPE_OS_RELEASE": f"{WORK}/os-release"})

    def enslave():
        sh("ip link add other0 type bridge")
        sh("ip link set tp1 master other0")

    def free():
        sh("ip link del other0")
    refused("port already in another bridge", ok_cfg, "already a member of other0", setup=enslave, undo=free)
    write_cfg(ok_cfg)
    p = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + GR
                       + ["install", "--config", CFG], capture_output=True, text=True)
    result(p.returncode == 2 and "root" in p.stderr, "refused: not root", f"exit {p.returncode}")
    check_exit(3, "before install")
    write_cfg("schema = 1\n[tap]\nmode = \"inline\"\n")
    check_exit(2, "invalid declaration")
    p = gr("check", "--config", f"{WORK}/does-not-exist.toml")
    result(p.returncode == 2, "check of a missing declaration exits 2 (error)", f"exit {p.returncode}")
    result(not diff(before, snapshot()), "refusals changed nothing", "; ".join(diff(before, snapshot())[:5]))


def phase_inline() -> None:
    topo_inline()
    before = snapshot()
    with open(f"{WORK}/before.json", "w") as f:
        json.dump(before, f)
    write_cfg(INLINE)
    open(os.environ["GOATROPE_TEST_WATCHDOG_DEVICE"], "w").close()
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "install inline", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-600:]}")
    print("    " + "\n    ".join(p.stdout.strip().splitlines()[-12:]), flush=True)
    j = check_exit(0, "after install", "--json")
    if j:
        bad = [i for i in j["items"] if i["ok"] is False]
        result(j["result"] == "match" and not bad, "check --json reports match", json.dumps(bad)[:400])
        info = [f"{i['id']}={i['have']}" for i in j["items"] if i["ok"] is None]
        result(None, "informational items", "; ".join(info))
    p = gr("status", "--config", CFG)
    result(p.returncode == 0 and "fail-closed" in p.stdout and "the link is down" in p.stdout,
           "status says inline is fail-closed", p.stdout.splitlines()[1] if p.stdout else p.stderr[:200])

    tapmacs = macs("tp0", "tp1", "goatrope0")
    cap_a, cap_b = Capture("a", "a0", "cap-a"), Capture("b", "b0", "cap-b")
    cap_t0, cap_t1 = RootCapture("tp0", "cap-tp0"), RootCapture("tp1", "cap-tp1")
    ping = sh("ip netns exec a ping -c 3 -i 0.2 -W 2 192.0.2.2", check=False)
    udp_send("a", "192.0.2.1", "192.0.2.2", 5000, 500, b"AB")
    udp_send("b", "192.0.2.2", "192.0.2.1", 5000, 500, b"BA")
    lldp = b"\x01\x80\xc2\x00\x00\x0e"
    code = ("import socket\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(('a0',0))\n"
            f"for i in range(5):\n s.send({lldp!r}+b'\\x02\\x00\\x00\\x00\\x00\\x0a'+b'\\x88\\xcc'+{MAGIC!r}+b'LL'+i.to_bytes(4,'big')+b'z'*40)\n")
    sh(f"ip netns exec a python3 -c \"{code}\"")
    fa, fb = cap_a.stop(), cap_b.stop()
    t0, t1 = cap_t0.stop(), cap_t1.stop()
    flush_recorders(["tp0"])
    ring = ring_frames("tp0")
    start_recorders(["tp0"])

    result(ping.returncode == 0, "inline: ping a -> b through the bridge", ping.stdout.strip().splitlines()[-2][:80]
           if ping.stdout else ping.stderr[:100])
    ab, ba = tagged(fb, b"AB"), tagged(fa, b"BA")
    # Where each direction was seen: entering the tap, leaving it, arriving at the far end.
    ab_in, ab_out = tagged(t0, b"AB"), tagged(t1, b"AB")
    ba_in, ba_out = tagged(t1, b"BA"), tagged(t0, b"BA")
    result(ab_in <= ab_out and ba_in <= ba_out, "inline: every datagram that entered the tap left it",
           f"a->b in {len(ab_in)} out {len(ab_out)}; b->a in {len(ba_in)} out {len(ba_out)}")
    result(len(ab) == 500, "inline: 500 of 500 datagrams a -> b arrived",
           f"{len(ab)} (entered the tap {len(ab_in)}, left it {len(ab_out)})")
    result(len(ba) == 500, "inline: 500 of 500 datagrams b -> a arrived",
           f"{len(ba)} (entered the tap {len(ba_in)}, left it {len(ba_out)})")
    ll = tagged(fb, b"LL")
    result(len(ll) == 5, "inline: LLDP frames (01:80:c2:00:00:0e) forwarded", f"{len(ll)} of 5")
    ring_set = {}
    for f in ring:
        ring_set[f] = ring_set.get(f, 0) + 1
    missing = 0
    for f in fa + fb:
        if ring_set.get(f, 0) > 0:
            ring_set[f] -= 1
        else:
            missing += 1
    result(missing == 0, "inline: every frame received at either end is in the recording on tp0",
           f"{len(fa) + len(fb)} frames received at the ends, {missing} not recorded; ring holds {len(ring)}")
    result(tagged(ring, b"AB") == set(range(500)) and tagged(ring, b"BA") == set(range(500)),
           "inline: the recording on one port holds both directions", f"{len(tagged(ring, b'AB'))} + {len(tagged(ring, b'BA'))}")
    own = [f for f in fa + fb if f[6:12] in tapmacs]
    result(not own, "inline: no frame from the tap's own addresses reached either end", f"{len(own)} frames")
    nonv4 = [f for f in fa + fb if f[12:14] == b"\x86\xdd" and f[6:12] in tapmacs]
    result(not nonv4, "inline: no IPv6 (RA, NDP) sent by the tap", f"{len(nonv4)}")

    # check notices differences, and exit 0 again when they are undone
    sh("ip addr add 198.51.100.7/32 dev tp0")
    check_exit(3, "address added to a port")
    sh("ip addr del 198.51.100.7/32 dev tp0")
    sh("ethtool -K tp1 gro on")
    check_exit(3, "GRO turned on")
    sh("ethtool -K tp1 gro off")
    sh("systemctl stop goatrope-record@tp0.service")
    check_exit(3, "recorder stopped")
    sh("systemctl start goatrope-record@tp0.service")
    sh("ip link set goatrope0 type bridge stp_state 1")
    check_exit(3, "STP turned on")
    sh("ip link set goatrope0 type bridge stp_state 0 && ip link set goatrope0 type bridge forward_delay 0")
    sh("ip link set tp1 nomaster")
    time.sleep(2)
    m = os.path.basename(os.path.realpath("/sys/class/net/tp1/master")) if os.path.exists("/sys/class/net/tp1/master") else None
    result(m == "goatrope0", "a port taken out of the bridge is put back by networkd", f"master {m}")
    check_exit(0, "after the differences are undone")
    p = sh("networkctl status tp0 --no-pager", check=False).stdout
    rfo = next((ln.strip() for ln in p.splitlines() if "Required For Online" in ln), "field not shown")
    result("yes" not in rfo.lower(), "boot waits for no tap port (networkd: required for online)", rfo)

    # re-install is idempotent
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "re-install is idempotent", f"exit {p.returncode}")


def phase_reboot_verify() -> None:
    """After `docker restart`: run.sh recreated the veths after boot (ports appear late, as USB adapters do)."""
    deadline = time.monotonic() + 90
    p = None
    while time.monotonic() < deadline:
        p = gr("check", "--config", "/etc/goatrope/goatrope.toml")
        if p.returncode == 0:
            break
        time.sleep(3)
    bad = [ln for ln in p.stdout.splitlines() if "DIFF" in ln]
    result(p.returncode == 0, "after a restart with late ports, check exits 0 without anyone touching it",
           f"exit {p.returncode}; {'; '.join(bad[:5])}")
    # UDP first, with no ping to warm anything up; tp1 is watched too, to show where a frame stops.
    cap_b, cap_t = Capture("b", "b0", "cap-b2"), RootCapture("tp1", "cap-tp1")
    udp_send("a", "192.0.2.1", "192.0.2.2", 5000, 100, b"RB")
    frames, tframes = cap_b.stop(), cap_t.stop()
    got, at_tp1 = tagged(frames, b"RB"), tagged(tframes, b"RB")
    result(len(got) == 100, "after the restart, traffic passes a -> b (first traffic after boot)",
           f"{len(got)} of 100 at b0, {len(at_tp1)} leaving tp1")
    ping = sh("ip netns exec a ping -c 3 -i 0.2 -W 2 192.0.2.2", check=False)
    result(ping.returncode == 0, "after the restart, ping a -> b", f"rc {ping.returncode}")


def phase_uninstall(config_kept: bool) -> None:
    before = json.load(open(f"{WORK}/before.json"))
    p = gr("uninstall")
    result(p.returncode == 0, "uninstall", p.stdout.strip()[-300:])
    after = snapshot()
    d = diff(before, after)
    allowed = [x for x in d if x.startswith(("file /etc/goatrope", "file /var/lib/goatrope"))]
    result(set(d) == set(allowed), "uninstall: only the declaration and the recordings remain",
           "; ".join(x for x in d if x not in allowed)[:600])
    p = subprocess.run(["/usr/bin/python3", "-I", f"{SRC}/bin/goatrope", "uninstall", "--purge"],
                       capture_output=True, text=True)
    d = diff(before, snapshot())
    result(not d, "uninstall --purge leaves nothing", "; ".join(d)[:600])
    result(not os.path.exists("/sys/class/net/goatrope0"), "uninstall: no bridge remains")


def phase_listen() -> None:
    topo_listen()
    before = snapshot()
    with open(f"{WORK}/before.json", "w") as f:
        json.dump(before, f)
    write_cfg(LISTEN)
    open(os.environ["GOATROPE_TEST_WATCHDOG_DEVICE"], "w").close()
    # Watch the feed side from before install: nothing may come back toward it, ever.
    c0, c1 = Capture("feed", "f0", "listen-f0"), Capture("feed", "f1", "listen-f1")
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "install listen", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-600:]}")
    check_exit(0, "listen after install")
    p = gr("status", "--config", CFG)
    result("receive only" in p.stdout and "egress-drop=yes" in p.stdout, "status shows listen and the egress drop",
           p.stdout.splitlines()[1] if p.stdout else "")
    raw_inject("feed", "f0", 500, b"F0")
    raw_inject("feed", "f1", 500, b"F1")
    udp_inject = ("import socket,struct\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(('f0',0))\n"
                  "def ck(h):\n s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);return (~(s+(s>>16)))&0xffff\n"
                  "for i in range(200):\n"
                  " pl=b'GTROPEUD'+i.to_bytes(4,'big')+b'u'*30\n"
                  " u=struct.pack('!HHHH',40000,5000,8+len(pl),0)+pl\n"
                  " h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),i,0,64,17,0,bytes([192,0,2,10]),bytes([192,0,2,20]))\n"
                  " h=h[:10]+struct.pack('!H',ck(h))+h[12:]\n"
                  " s.send(b'\\x02\\x00\\x00\\x00\\x00\\x20'+b'\\x02\\x00\\x00\\x00\\x00\\x10'+b'\\x08\\x00'+h+u)\n")
    sh(f"ip netns exec feed python3 -c \"{udp_inject}\"")
    # Try to make the tap transmit, every way an ordinary process or the kernel would.
    attempts = []
    for port in ("tp0", "tp1"):
        attempts.append(sh(f"ping -c 2 -W 1 -I {port} -b 255.255.255.255", check=False).returncode)
        code = (f"import socket\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(('{port}',0))\n"
                "n=0\nfor i in range(20):\n try:\n  s.send(b'\\xff'*6+b'\\x02'*6+b'\\x88\\xb5'+b'tap-tx'*10); n+=1\n"
                " except OSError: pass\nprint(n)\n")
        attempts.append(sh(f"python3 -c \"{code}\"", check=False).stdout.strip())
    sh("systemctl restart systemd-networkd.service")
    sh("systemctl restart goatrope-ports.service"); ports_settled()
    time.sleep(3)
    f0, f1 = c0.stop(), c1.stop()
    result(not f0 and not f1, "listen: no frame sent on either listen port (install, traffic, provocation, restarts)",
           f"{len(f0)} + {len(f1)} frames reached the feed side; provocations {attempts}")
    flush_recorders(["tp0", "tp1"])
    r0, r1 = ring_frames("tp0"), ring_frames("tp1")
    start_recorders(["tp0", "tp1"])
    result(tagged(r0, b"F0") == set(range(500)), "listen: every frame on output 1 recorded (tp0)", f"{len(tagged(r0, b'F0'))} of 500")
    result(tagged(r1, b"F1") == set(range(500)), "listen: every frame on output 2 recorded (tp1)", f"{len(tagged(r1, b'F1'))} of 500")
    result(not tagged(r0, b"F1") and not tagged(r1, b"F0"), "listen: each output recorded only on its own port")
    # Known limit: a root process can ask the kernel to skip the transmit queue entirely.
    c0 = Capture("feed", "f0", "listen-bypass")
    code = ("import socket\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.setsockopt(263,20,1)\n"
            "s.bind(('tp0',0))\nn=0\nfor i in range(3):\n try:\n  s.send(b'\\xff'*6+b'\\x02'*6+b'\\x88\\xb5'+b'bypass'*10); n+=1\n"
            " except OSError as e: print(e)\nprint('sent', n)\n")
    out = sh(f"python3 -c \"{code}\"", check=False)
    leaked = c0.stop()
    result(None, "listen: frames sent with PACKET_QDISC_BYPASS (skips the transmit queue, where the drop sits)",
           f"{len(leaked)} of 3 reached the feed side; sender: {(out.stdout + out.stderr).strip()[-120:]}")
    sh("ip link set tp0 arp on")
    check_exit(3, "listen: ARP turned on")
    sh("systemctl restart goatrope-ports.service"); ports_settled()
    sh("tc qdisc del dev tp1 clsact")
    check_exit(3, "listen: egress drop removed")
    sh("systemctl restart goatrope-ports.service"); ports_settled()
    check_exit(0, "listen: after goatrope-ports restores them")


def phase_send() -> None:
    """Decode-and-send on the listen tap: UDP and file destinations, a pinned converter stand-in."""
    os.makedirs("/opt/gt-test", exist_ok=True)
    xf = "/opt/gt-test/fake-goat-xf"  # not under /root: the send unit runs with ProtectHome
    with open(xf, "w") as f:
        f.write("#!/bin/sh\n# stand-in for goat-xf convert: upper-cases the hex it reads\ntr a-f A-F\n")
    os.chmod(xf, 0o755)
    pin = hashlib.sha256(open(xf, "rb").read()).hexdigest()
    cfg = LISTEN + f"""
[[send]]
name = "plain"
port = "tp0"
match = {{ protocol = "udp", src = "192.0.2.10", dst_port = 5000 }}
to = ["udp://127.0.0.1:9101", {{ url = "file:///var/lib/goatrope/send/plain.jsonl", format = "jsonl" }},
      {{ url = "tcp://127.0.0.1:9102", framing = "len32be" }}, "http://127.0.0.1:9103/in"]

[[send]]
name = "converted"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
convert = {{ component = "goat-transformers", binary = "{xf}", version = "stand-in", sha256 = "{pin}", from = "a", to = "b" }}
to = ["udp://127.0.0.1:9104"]
"""
    write_cfg(cfg)
    rx = subprocess.Popen([sys.executable, "-c", """
import socket, threading, json, http.server, struct, sys
got = {"udp": [], "tcp": [], "http": [], "conv": []}
def udp(port, key):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port)); s.settimeout(20)
    try:
        while True: got[key].append(s.recv(65535).hex())
    except socket.timeout: pass
def tcp():
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("127.0.0.1", 9102)); l.listen(1); l.settimeout(20)
    try:
        c, _ = l.accept(); c.settimeout(10); buf = b""
        while True:
            d = c.recv(65535)
            if not d: break
            buf += d
            while len(buf) >= 4 and len(buf) >= 4 + struct.unpack("!I", buf[:4])[0]:
                n = struct.unpack("!I", buf[:4])[0]; got["tcp"].append(buf[4:4+n].hex()); buf = buf[4+n:]
    except socket.timeout: pass
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        got["http"].append(self.rfile.read(int(self.headers["Content-Length"])).hex()); self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 9103), H); srv.timeout = 1
ts = [threading.Thread(target=udp, args=(9101, "udp")), threading.Thread(target=udp, args=(9104, "conv")), threading.Thread(target=tcp)]
[t.start() for t in ts]
import time; end = time.time() + 20
while time.time() < end: srv.handle_request()
[t.join() for t in ts]
print(json.dumps({k: len(v) for k, v in got.items()} | {"sample_conv": got["conv"][:1], "sample_udp": got["udp"][:1]}))
"""], stdout=subprocess.PIPE, text=True)
    time.sleep(1)
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "install listen with two [[send]] sections", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-400:]}")
    time.sleep(3)
    code = ("import socket,struct,time\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(('f0',0))\n"
            "def ck(h):\n s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);return (~(s+(s>>16)))&0xffff\n"
            "def frame(src,ident,pl,off=0,more=False,udp=True):\n"
            " h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(pl),ident,(0x2000 if more else 0)|(off//8),64,17,0,bytes(src),bytes([192,0,2,20]))\n"
            " h=h[:10]+struct.pack('!H',ck(h))+h[12:]\n"
            " return b'\\x02\\x00\\x00\\x00\\x00\\x20'+b'\\x02\\x00\\x00\\x00\\x00\\x10'+b'\\x08\\x00'+h+pl\n"
            "for i in range(100):\n"
            " pl=b'SEND'+i.to_bytes(4,'big')\n"
            " s.send(frame([192,0,2,10],1000+i,struct.pack('!HHHH',40000,5000,8+len(pl),0)+pl)); time.sleep(0.005)\n"
            "for i in range(50):\n"
            " pl=b'OTHR'+i.to_bytes(4,'big')\n"
            " s.send(frame([192,0,2,11],2000+i,struct.pack('!HHHH',40000,5000,8+len(pl),0)+pl)); time.sleep(0.005)\n"
            "pl=b'FRAG'+b'q'*2000\n"
            "u=struct.pack('!HHHH',40000,5000,8+len(pl),0)+pl\n"
            "s.send(frame([192,0,2,10],3000,u[:1480],0,True)); s.send(frame([192,0,2,10],3000,u[1480:],1480,False))\n")
    sh(f"ip netns exec feed python3 -c \"{code}\"")
    got = json.loads(rx.communicate(timeout=60)[0])
    result(got["udp"] == 101, "send: UDP destination got the 100 matching datagrams and 1 reassembled from 2 fragments",
           f"{got['udp']}")
    result(got["tcp"] == 101, "send: TCP destination (len32be) got the same 101", f"{got['tcp']}")
    result(got["http"] == 101, "send: HTTP destination got the same 101", f"{got['http']}")
    lines = open("/var/lib/goatrope/send/plain.jsonl").read().splitlines()
    result(len(lines) == 101, "send: file destination holds 101 JSON lines", f"{len(lines)}")
    result(got["conv"] == 151, "send: the converted feed (wider match) got 151 converted messages", f"{got['conv']}")
    sample = bytes.fromhex(got["sample_conv"][0]).decode() if got["sample_conv"] else ""
    result(sample == b"SEND\x00\x00\x00\x00".hex().upper(), "send: the converter's output is what was sent", sample)
    check_exit(0, "send: check after install (pins and heartbeats)")
    with open(xf, "a") as f:
        f.write("# changed\n")
    check_exit(3, "send: converter binary no longer matches its pin")


PHASES = {"refusals": phase_refusals, "inline": phase_inline, "reboot-verify": phase_reboot_verify,
          "uninstall": lambda: phase_uninstall(True), "listen": phase_listen, "send": phase_send}

if __name__ == "__main__":
    os.makedirs(WORK, exist_ok=True)
    for name in sys.argv[1:]:
        if name == "topo-inline":
            topo_inline()
            continue
        print(f"# phase {name}", flush=True)
        try:
            PHASES[name]()
        except Exception as e:  # a crash is a failure of the phase, reported as such
            result(False, f"phase {name} completed", f"{type(e).__name__}: {e}"[:800])
    with open(f"{WORK}/results.jsonl", "a") as f:
        for r in RESULTS:
            f.write(json.dumps(r) + "\n")
    print(f"# {len(RESULTS)} results, {len(FAILED)} failed", flush=True)
    sys.exit(1 if FAILED else 0)
