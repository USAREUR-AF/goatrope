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
# A container has no watchdog device, so check is pointed at a stand-in file. A VM with an
# emulated watchdog sets GOATROPE_TEST_REAL_WATCHDOG=1 and check reads /dev/watchdog*.
REAL_WATCHDOG = os.environ.pop("GOATROPE_TEST_REAL_WATCHDOG", "") == "1"
if not REAL_WATCHDOG:
    os.environ["GOATROPE_TEST_WATCHDOG_DEVICE"] = f"{WORK}/watchdog-stand-in"


def stand_in_watchdog() -> None:
    if not REAL_WATCHDOG:
        open(os.environ["GOATROPE_TEST_WATCHDOG_DEVICE"], "w").close()


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


# The management interface: eth0 in the container; a VM keeps its NIC's own name and sets this.
MGMT = os.environ.get("GOATROPE_TEST_MGMT", "eth0")


def write_cfg(text: str, path: str = CFG) -> str:
    os.makedirs(WORK, exist_ok=True)
    with open(path, "w") as f:
        f.write(text.replace('"eth0"', f'"{MGMT}"'))
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
            "addr_gen_mode": open(f"/proc/sys/net/ipv6/conf/{p}/addr_gen_mode").read().strip(),
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
    # A TCP connection through tp0 although tp0 has no address: a host route sends it out
    # tp0 with the management address as its source. Only the established-connection check
    # sees it (no address on the port, no default route, not the SSH session).
    held = []

    def hold_tcp():
        mgmt = sh(f"ip -4 -o addr show dev {MGMT}").stdout.split()[3].split("/")[0]
        sh("sysctl -qw net.ipv6.conf.tp0.disable_ipv6=1; ip link set tp0 up")
        sh(f"ip route add 192.0.2.1/32 dev tp0 src {mgmt}")
        sh(f"ip -n a route add {mgmt}/32 dev a0")
        held.append(subprocess.Popen(["ip", "netns", "exec", "a", sys.executable, "-c",
                                      "import socket,time\ns=socket.create_server(('192.0.2.1',7022))\n"
                                      "c=s.accept()\ntime.sleep(120)"]))
        time.sleep(1)
        held.append(subprocess.Popen([sys.executable, "-c",
                                      "import socket,time\nc=socket.create_connection(('192.0.2.1',7022),5)\n"
                                      "time.sleep(120)"]))
        for _ in range(50):
            if "192.0.2.1:7022" in sh("ss -Htn state established").stdout:
                break
            time.sleep(0.2)

    def drop_tcp():
        for proc in held:
            proc.kill()
            proc.wait()
        held.clear()
        mgmt = sh(f"ip -4 -o addr show dev {MGMT}").stdout.split()[3].split("/")[0]
        sh("ip route del 192.0.2.1/32 dev tp0", check=False)
        sh(f"ip -n a route del {mgmt}/32 dev a0", check=False)
        sh("ip link set tp0 down; sysctl -qw net.ipv6.conf.tp0.disable_ipv6=0")
    refused("port carries an established TCP connection", ok_cfg, "carries an established connection to 192.0.2.1",
            setup=hold_tcp, undo=drop_tcp)
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

    rec = 'ports = ["tp0"]\nfilter = ""\n'
    refused("recording directory is /var/lib itself", ok_cfg.replace(rec, rec + 'directory = "/var/lib/"\n'),
            "must be /var/lib/goatrope/<name>")
    refused("recording directory is a system directory", ok_cfg.replace(rec, rec + 'directory = "/var/lib/dpkg"\n'),
            "must be /var/lib/goatrope/<name>")
    refused("recording directory is goatrope's own state directory",
            ok_cfg.replace(rec, rec + 'directory = "/var/lib/goatrope/send"\n'), "must be /var/lib/goatrope/<name>")
    refused("a newline in the filter (a line injected into the unit file)",
            ok_cfg.replace('filter = ""', 'filter = "udp\\nExecStartPost=/bin/true"'), "control character")
    refused("a quote in the filter", ok_cfg.replace('filter = ""', 'filter = "udp\' or 1"'), "quote")
    refused("a VLAN on top of a port", ok_cfg, "carries tp1.100",
            setup=lambda: sh("ip link add link tp1 name tp1.100 type vlan id 100"),
            undo=lambda: sh("ip link del tp1.100"))
    refused("the SSH session over a port's link-local address", ok_cfg, "carries this session",
            env={"SSH_CONNECTION": "fe80::1%tp0 50000 fe80::2%tp0 22"})
    # A TCP connection to a link-local address through tp0, while another interface (dum0) also
    # has a link-local route: the route lookup alone would name dum0.
    ll = []

    def hold_ll():
        sh("ip link add dum0 type dummy && ip link set dum0 up && ip link set tp0 up")
        sh("ip -n a link set a0 up")
        for _ in range(50):
            out = sh("ip -n a -6 -o addr show dev a0 scope link").stdout
            if out and "tentative" not in out and "tentative" not in sh("ip -6 -o addr show dev tp0").stdout:
                break
            time.sleep(0.2)
        addr = sh("ip -n a -6 -o addr show dev a0 scope link").stdout.split()[3].split("/")[0]
        ll.append(subprocess.Popen(["ip", "netns", "exec", "a", sys.executable, "-c",
                                    "import socket,time\ns=socket.create_server(('::',7023),family=socket.AF_INET6)\n"
                                    "c=s.accept()\ntime.sleep(120)"]))
        time.sleep(1)
        ll.append(subprocess.Popen([sys.executable, "-c",
                                    f"import socket,time\nc=socket.create_connection(('{addr}%tp0',7023),5)\n"
                                    "time.sleep(120)"]))
        for _ in range(50):
            if ":7023" in sh("ss -Htn state established").stdout:
                break
            time.sleep(0.2)

    def drop_ll():
        for proc in ll:
            proc.kill()
            proc.wait()
        ll.clear()
        sh("ip link del dum0; ip link set tp0 down")
    refused("a TCP connection to a link-local address through a port", ok_cfg,
            "carries an established connection to fe80:", setup=hold_ll, undo=drop_ll)
    st = os.statvfs("/var/lib")
    room = min(0.9 * st.f_bavail * st.f_frsize, (st.f_bavail - 0.05 * st.f_blocks) * st.f_frsize)
    files = int(0.6 * room / 100e6)
    refused("two rings that do not fit although one would", LISTEN.replace("file_mb = 5", "file_mb = 100")
            .replace("files = 4", f"files = {files}"), "2 ring(s)")
    refused("an HTTP destination whose name does not resolve", ok_cfg + """
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp", dst_port = 5000 }
to = ["http://no-such-host.invalid/in"]
""", "cannot resolve")
    refused("a file destination without max_mb", ok_cfg + """
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp", dst_port = 5000 }
to = [{ url = "file:///var/lib/goatrope/send/s.jsonl", format = "jsonl" }]
""", "needs max_mb")
    # An unreadable state file (a power cut while it was first written) is never "not installed".
    os.makedirs("/var/lib/goatrope", exist_ok=True)
    for name, text in (("empty", ""), ("truncated", '{"ports": {"tp0": {"up": fal')):
        with open("/var/lib/goatrope/state.json", "w") as f:
            f.write(text)
        b1 = snapshot()
        p = gr("uninstall")
        p2 = gr("install", "--config", CFG)
        d = diff(b1, snapshot())
        result(p.returncode == 2 and p2.returncode == 2 and "unreadable" in p.stderr and not d,
               f"refused: uninstall and install with a {name} state file",
               f"exit {p.returncode}/{p2.returncode}; {(p.stderr + p2.stderr).strip()[-160:]}; {d[:2]}")
    shutil.rmtree("/var/lib/goatrope")
    write_cfg(ok_cfg)
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
    stand_in_watchdog()
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
    stand_in_watchdog()
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
to = ["udp://127.0.0.1:9101", {{ url = "file:///var/lib/goatrope/send/plain.jsonl", format = "jsonl", max_mb = 50 }},
      {{ url = "tcp://127.0.0.1:9102", framing = "len32be" }}, "http://127.0.0.1:9103/in"]

[[send]]
name = "converted"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
convert = {{ component = "goat-transformers", binary = "{xf}", version = "stand-in", sha256 = "{pin}", from = "a", to = "b", packs = "/opt/gt-test" }}
to = ["udp://127.0.0.1:9104"]

[[send]]
name = "bounded"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5001 }}
to = [{{ url = "file:///var/lib/goatrope/send/bounded.jsonl", format = "jsonl", max_mb = 1 }}]
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
            "s.send(frame([192,0,2,10],3000,u[:1480],0,True)); s.send(frame([192,0,2,10],3000,u[1480:],1480,False))\n"
            "for i in range(600):\n"
            " pl=b'BIG'+i.to_bytes(4,'big')+b'b'*1400\n"
            " s.send(frame([192,0,2,10],4000+i,struct.pack('!HHHH',40000,5001,8+len(pl),0)+pl)); time.sleep(0.002)\n")
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
    time.sleep(2)
    b = "/var/lib/goatrope/send/bounded.jsonl"
    sizes = [os.path.getsize(f) if os.path.exists(f) else -1 for f in (b, b + ".1")]
    n = sum(len(open(f).read().splitlines()) for f in (b, b + ".1") if os.path.exists(f))
    result(sizes[1] > 0 and max(sizes) < 1_000_000 + 4_000 and n == 600,
           "send: a file destination with max_mb = 1 is cut at 1 MB, one older file kept, nothing lost",
           f"sizes {sizes}, {n} of 600 lines")
    mode = oct(os.stat("/var/lib/goatrope/send/plain.jsonl").st_mode & 0o777)
    result(mode == "0o640", "send: file destinations are not world-readable", mode)
    check_exit(0, "send: check after install (pins and heartbeats)")
    with open(xf, "a") as f:
        f.write("# changed\n")
    check_exit(3, "send: converter binary no longer matches its pin")


PHASES = {"refusals": phase_refusals, "inline": phase_inline, "reboot-verify": phase_reboot_verify,
          "uninstall": lambda: phase_uninstall(True), "listen": phase_listen, "send": phase_send}

RELAY = """schema = 1
[relay]
wip = true
remote_interface = "wg0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [
  { direction = "both", protocol = "udp", remote = "10.99.0.2", listen_port = 7000, target = "192.0.2.2", target_port = 7000 },
  { direction = "remote-to-link", protocol = "udp", remote = "10.99.0.2", listen_port = 7002, target = "192.0.2.2", target_port = 7002 },
]
"""


def topo_relay() -> None:
    """remote ns: two WireGuard interfaces (an allowed peer and another peer); link ns: one host on the link."""
    for ns in ("remote", "linkhost"):
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip netns add {ns}")
        sh(f"ip -n {ns} link set lo up")
    sh("ip link add u0 type veth peer name u1 && ip link set u1 netns remote")
    sh("ip addr add 198.51.100.1/24 dev u0 && ip link set u0 up")
    sh("ip -n remote addr add 198.51.100.2/24 dev u1 && ip -n remote link set u1 up")
    sh("ip link add r0 type veth peer name l0 && ip link set l0 netns linkhost")
    sh("ip addr add 192.0.2.50/24 dev r0 && ip link set r0 up")  # IPv6 stays on here: the first run must refuse
    sh("ip -n linkhost addr add 192.0.2.2/24 dev l0 && ip -n linkhost link set l0 up")
    keys = {}
    for k in ("tap", "allowed", "other"):
        priv = sh("wg genkey").stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
        path = f"{WORK}/{k}.key"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, priv.encode() + b"\n")
        os.close(fd)
        keys[k] = pub
    sh("ip link add wg0 type wireguard")
    # Keys go in on standard input: the host's AppArmor profile for wg may refuse to open key files.
    sh(f"cat {WORK}/tap.key | wg set wg0 listen-port 51820 private-key /dev/stdin "
       f"peer {keys['allowed']} allowed-ips 10.99.0.2/32 peer {keys['other']} allowed-ips 10.99.0.3/32")
    sh("ip addr add 10.99.0.1/24 dev wg0 && ip link set wg0 up")
    for name, addr, port in (("wga", "10.99.0.2", 51821), ("wgo", "10.99.0.3", 51822)):
        sh(f"ip -n remote link add {name} type wireguard")
        key = "allowed" if name == "wga" else "other"
        sh(f"cat {WORK}/{key}.key | ip netns exec remote wg set {name} listen-port {port} private-key /dev/stdin "
           f"peer {keys['tap']} endpoint 198.51.100.1:51820 allowed-ips 10.99.0.1/32")
        sh(f"ip -n remote addr add {addr}/32 dev {name} && ip -n remote link set {name} up")
    # The other peer reaches the relay port through its own tunnel address.
    sh("ip -n remote route add 10.99.0.1/32 dev wga metric 1")
    sh("ip -n remote route add 10.99.0.1/32 dev wgo metric 2")


def phase_relay() -> None:
    topo_relay()
    write_cfg(RELAY)
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "IPv6 is on" in p.stderr, "relay refused: IPv6 on its link interface", p.stderr.strip()[-120:])
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=1")
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "IP forwarding is on" in p.stderr,
           "relay refused: IP forwarding on (the kernel would route around the allow rules)", p.stderr.strip()[-120:])
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 net.ipv6.conf.all.forwarding=0")
    cap = Capture("linkhost", "l0", "relay-link")
    rx = subprocess.Popen(["ip", "netns", "exec", "linkhost", sys.executable, "-c", """
import socket, json, select
socks = {}
for p in (7000, 7001, 7002):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.2", p)); socks[s] = p
got = {7000: [], 7001: [], 7002: []}
end = __import__("time").time() + 12
while __import__("time").time() < end:
    r, _, _ = select.select(list(socks), [], [], 0.5)
    for s in r:
        d, a = s.recvfrom(65535); got[socks[s]].append([d.decode(), a[0]])
        if socks[s] == 7000: s.sendto(b"reply-" + d, a)
print(json.dumps(got))
"""], stdout=subprocess.PIPE, text=True)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)
    sender = """
import socket, sys, time, json
src, port, n, tag, dev = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, 25, dev.encode())
s.bind((src, 0)); s.settimeout(0.3)
replies = 0
for i in range(n):
    s.sendto(f"{tag}{i}".encode(), ("10.99.0.1", port))
    try:
        if s.recv(65535).startswith(b"reply-"): replies += 1
    except socket.timeout: pass
print(replies)
"""
    rep = sh(f"ip netns exec remote python3 -c '{sender}' 10.99.0.2 7000 20 ok wga", check=False).stdout.strip()
    sh(f"ip netns exec remote python3 -c '{sender}' 10.99.0.2 7002 5 oneway wga", check=False)
    sh(f"ip netns exec remote python3 -c '{sender}' 10.99.0.2 7001 5 unlisted wga", check=False)
    sh(f"ip netns exec remote python3 -c '{sender}' 10.99.0.3 7000 5 otherpeer wgo", check=False)
    # From the management side, outside the tunnel: the relay's sockets are bound to wg0.
    sh("python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[s.sendto(b'outside',('127.0.0.1',7000)) for i in range(3)]\"", check=False)
    got = json.loads(rx.communicate(timeout=30)[0])
    relay.terminate()
    out = relay.communicate(timeout=10)[0]
    frames = cap.stop()
    ok7000 = [d for d, a in got["7000"] if d.startswith("ok")]
    result(len(ok7000) == 20 and all(a == "192.0.2.50" for _, a in got["7000"]),
           "relay (WIP): an allowed datagram reaches its one target, from the relay's own address", f"{len(ok7000)} of 20")
    result(rep == "20", "relay (WIP): replies from the target return to the remote machine (direction both)", f"{rep} of 20")
    result(len(got["7002"]) == 5, "relay (WIP): a one-way rule forwards", f"{len(got['7002'])} of 5")
    result(not got["7001"], "relay (WIP): a port with no rule forwards nothing", f"{len(got['7001'])}")
    result(not any(d.startswith("otherpeer") for d, _ in got["7000"]),
           "relay (WIP): an authenticated peer that is not the rule's remote is denied", "denied" if "denied" in out else out[-200:])
    result(not any(d.startswith("outside") for d, _ in got["7000"]), "relay (WIP): nothing from outside the tunnel is relayed")
    bad = []
    for f in frames:
        et = f[12:14]
        if et == b"\x08\x06":
            continue  # ARP: the relay answers for its own address, as any host on the link does
        if et == b"\x08\x00" and f[23] == 17 and f[26:30] == bytes([192, 0, 2, 50]) and f[30:34] == bytes([192, 0, 2, 2]) \
                and int.from_bytes(f[36:38], "big") in (7000, 7002):
            continue
        bad.append(f[:40].hex())
    result(not bad, "relay (WIP): on the link, only ARP and the allowed datagrams were sent", f"{len(frames)} frames, {len(bad)} other: {bad[:3]}")
    # refusals
    write_cfg(RELAY.replace('remote_interface = "wg0"', 'remote_interface = "u0"'))
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "not a WireGuard interface" in p.stderr, "relay refused: remote side is not WireGuard", p.stderr.strip()[-120:])
    write_cfg(RELAY.replace('192.0.2.50/24', '192.0.2.51/24'))
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "does not hold" in p.stderr, "relay refused: its interface does not hold the declared address", p.stderr.strip()[-120:])
    write_cfg(RELAY.replace('target = "192.0.2.2", target_port = 7000', 'target = "198.51.100.9", target_port = 7000'))
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "is not on the link" in p.stderr, "relay refused: a target that is not on the link", p.stderr.strip()[-120:])
    write_cfg(RELAY.replace('target = "192.0.2.2", target_port = 7000', 'target = "192.0.2.255", target_port = 7000'))
    p = gr("validate", "--config", CFG)
    result(p.returncode == 2 and "names one machine" in p.stderr, "relay refused: a broadcast target", p.stderr.strip()[-120:])

    # A reply that cannot be sent (the remote peer has no key on wg0) is counted; the relay keeps running.
    write_cfg(RELAY)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)
    primed = 0
    for _ in range(10):  # until the relay has forwarded one datagram from the remote, so it knows the peer
        sh(f"ip netns exec remote python3 -c '{sender}' 10.99.0.2 7000 1 prime wga", check=False)
        time.sleep(2.5)
        try:
            primed = sum(r["to_link"] for r in json.load(open("/var/lib/goatrope/relay.health"))["rules"])
        except (OSError, ValueError, KeyError):
            primed = 0
        if primed:
            break
    port = next((ln.split()[3].rsplit(":", 1)[1] for ln in sh("ss -Huan").stdout.splitlines()
                 if ln.split()[3].startswith(("192.0.2.50:", "192.0.2.50%"))), None)
    allowed = subprocess.run(["wg", "pubkey"], input=open(f"{WORK}/allowed.key").read(), capture_output=True,
                             text=True).stdout.strip()
    sh(f"wg set wg0 peer {allowed} remove")
    sh("ip netns exec linkhost python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
       f"s.bind(('192.0.2.2',7000));[s.sendto(b'late',('192.0.2.50',{port})) for i in range(3)]\"", check=False)
    time.sleep(3)
    health = json.load(open("/var/lib/goatrope/relay.health"))
    errs = sum(r.get("send_errors", 0) for r in health["rules"])
    result(relay.poll() is None and errs >= 1, "relay (WIP): a reply it cannot send is counted and the relay keeps running",
           f"running={relay.poll() is None}, send_errors={errs}, primed={primed}, port={port}, health={health['rules']}")
    sh(f"wg set wg0 peer {allowed} allowed-ips 10.99.0.2/32")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=1")
    try:
        rc = relay.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay.kill()
        rc = None
    result(rc == 1, "relay (WIP): it stops when IP forwarding is turned on while it runs", f"exit {rc}")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0")


PHASES["relay"] = phase_relay

COMPONENTS = "/opt/gt-components"  # run.sh copies the real binaries here when GOATROPE_TEST_COMPONENTS is set
REMOTE_ID = "122624160b42bf241b6ed1b4b69808ac0870086b53150e0200"  # goat-transformers' README example message
NTP = ("240206e90000060000000a80c0000201ed135500c0000000ed13554040000000ed13554043000000ed13554043800000")


def phase_components() -> None:
    """The real goat-transformers goat-xf in a [[send]] and the real first-bite mind in a [[decode]]."""
    if not os.path.exists(f"{COMPONENTS}/goat-xf"):
        result(None, "components: not run (no real binaries given; set GOATROPE_TEST_COMPONENTS)")
        return
    xf, mind = f"{COMPONENTS}/goat-xf", f"{COMPONENTS}/mind"
    pin = {b: hashlib.sha256(open(b, "rb").read()).hexdigest() for b in (xf, mind)}
    ver = {b: sh(f"{b} --version", check=False).stdout.strip() or "unknown" for b in (mind,)}
    with open(f"{COMPONENTS}/publishers.yml", "w") as f:
        f.write("publishers:\n  - name: records\n    publisher_type: PUB\n    address: \"tcp://127.0.0.1:47123\"\n"
                "    topic: \"subsystem/message_type\"\n")
    with open(f"{COMPONENTS}/subscribers.yml", "w") as f:
        f.write("subscribers:\n  - name: ToFile\n    subscriber_type: local\n    subtype: locallog\n"
                "    zmq_url: 127.0.0.1\n    zmq_port: 47123\n    local_logfile: records.jsonl\n"
                "    topics: [\"*\"]\n")
    sh(f"chmod -R go+rX {COMPONENTS}")
    write_cfg(LISTEN + f"""
[[send]]
name = "remote-id"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
convert = {{ component = "goat-transformers", binary = "{xf}", version = "main", sha256 = "{pin[xf]}", from = "remote-id", to = "cot-xml", packs = "{COMPONENTS}/packs" }}
to = ["udp://127.0.0.1:9105"]

[[decode]]
name = "ntp"
component = "first-bite"
binary = "{mind}"
version = "{ver[mind]}"
sha256 = "{pin[mind]}"
ports = ["tp0"]
filter = "udp port 123"
dictionary = "{COMPONENTS}/dictionaries/ntp"
subscribers = "{COMPONENTS}/subscribers.yml"
publishers = "{COMPONENTS}/publishers.yml"
""")
    rx = subprocess.Popen([sys.executable, "-c", """
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 9105)); s.settimeout(25)
got = []
try:
    while len(got) < 10: got.append(s.recv(65535).decode(errors="replace"))
except socket.timeout: pass
print(json.dumps(got))
"""], stdout=subprocess.PIPE, text=True)
    c0 = Capture("feed", "f0", "components-f0")
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "components: install with the real goat-xf and mind",
           f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-400:]}")
    for _ in range(30):
        if sh("systemctl is-active goatrope-decode@ntp.service", check=False).stdout.strip() == "active" and \
                ":47123" in sh("ss -Htln", check=False).stdout:
            break
        time.sleep(1)
    time.sleep(3)
    code = ("import socket,struct,time\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(('f0',0))\n"
            "def ck(h):\n s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);return (~(s+(s>>16)))&0xffff\n"
            "def frame(ident,sport,dport,pl):\n"
            " u=struct.pack('!HHHH',sport,dport,8+len(pl),0)+pl\n"
            " h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),ident,0,64,17,0,bytes([192,0,2,10]),bytes([192,0,2,20]))\n"
            " h=h[:10]+struct.pack('!H',ck(h))+h[12:]\n"
            " return b'\\x02\\x00\\x00\\x00\\x00\\x20'+b'\\x02\\x00\\x00\\x00\\x00\\x10'+b'\\x08\\x00'+h+u\n"
            f"for i in range(10):\n s.send(frame(5000+i,40000,5000,bytes.fromhex('{REMOTE_ID}'))); time.sleep(0.2)\n"
            f"for i in range(20):\n s.send(frame(6000+i,123,123,bytes.fromhex('{NTP}'))); time.sleep(0.05)\n")
    sh(f"ip netns exec feed python3 -c \"{code}\"")
    got = json.loads(rx.communicate(timeout=60)[0])
    result(len(got) == 10 and all(g.startswith("<event") for g in got),
           "components: goat-xf converted 10 of 10 Remote ID messages to Cursor-on-Target XML and they were sent",
           f"{len(got)} of 10; {got[0][:90] if got else ''}")
    time.sleep(5)
    recs = []
    for path in glob.glob("/var/lib/goatrope-decode-ntp/records.jsonl") + glob.glob("/var/lib/private/goatrope-decode-ntp/records.jsonl"):
        recs = open(path).read().splitlines()
        break
    strata = sum('"stratum"' in r for r in recs)
    jl = sh("journalctl -u goatrope-decode@ntp.service --no-pager -n 15", check=False).stdout
    result(strata == 20, "components: mind decoded 20 of 20 NTP packets against its dictionary and wrote them",
           f"{strata} records with a stratum field; {len(recs)} lines" + ("" if strata == 20 else "; " + jl[-500:]))
    pid = sh("systemctl show -p MainPID --value goatrope-decode@ntp.service", check=False).stdout.strip()
    user = sh(f"ps -o user= -p {pid}", check=False).stdout.split() if pid not in ("", "0") else []
    result(bool(user) and "root" not in user, "components: mind runs as its own dynamic user, not root", " ".join(user))
    check_exit(0, "components: check after install (pins, units)")
    time.sleep(1)
    frames = c0.stop()
    result(not frames, "components: nothing was sent toward the feed while the decoders ran", f"{len(frames)} frames")
    # A binary replaced after install: the running copy is the verified one; a restart refuses the new one.
    shutil.copyfile(mind, f"{WORK}/mind.orig")
    with open(mind, "ab") as f:
        f.write(b"\0")
    sh("systemctl restart goatrope-decode@ntp.service", check=False)
    time.sleep(3)
    a = sh("systemctl is-active goatrope-decode@ntp.service", check=False).stdout.strip()
    result(a != "active", "components: a changed mind binary is refused at start", a)
    shutil.copyfile(f"{WORK}/mind.orig", mind)


PHASES["components"] = phase_components


def nm_states() -> dict[str, str]:
    out = sh("nmcli -t -f DEVICE,STATE device", check=False).stdout
    return dict(ln.rsplit(":", 1) for ln in out.splitlines() if ":" in ln)


def phase_units() -> None:
    """Fixes that need no tap: each case calls the code directly. A crash is that case's failure."""
    sys.path.insert(0, SRC)
    import http.server
    import threading
    from goatrope import config as cm, send as sm, sysutil as su, tap as tm

    def case(name, fn):
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        result(bool(ok), "units: " + name, str(detail)[:300])

    def full_disk():
        os.makedirs("/mnt/small", exist_ok=True)
        sh("mount -t tmpfs -o size=64k tmpfs /mnt/small")
        try:
            su.write_file("/mnt/small/f", "good")
            try:
                su.write_file("/mnt/small/f", "x" * 200000)
                return False, "no error"
            except OSError as e:
                left = os.listdir("/mnt/small")
                return open("/mnt/small/f").read() == "good" and left == ["f"], f"errno {e.errno}, {left}"
        finally:
            sh("umount /mnt/small")
    case("a full disk leaves the old file whole", full_disk)

    def redirect():
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302); self.send_header("Location", "http://127.0.0.1:9206/x"); self.end_headers()

            def do_GET(self):
                hits.append(1); self.send_response(200); self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 9206), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        d = cm.Destination("http://127.0.0.1:9206/in", "http", "127.0.0.1", 9206, "/in", None, None)
        try:
            sm.Sink(d, set()).send(b"x", {"feed": "f"})
            return False, f"followed, {len(hits)} GET"
        except OSError as e:
            return not hits, e
        finally:
            srv.shutdown()
    case("an HTTP redirect is refused", redirect)

    def fragments():
        f = sm.Fragments()
        for i in range(250):
            for j in range(40):
                f.add(("a", "b", i), j * 1480, True, b"x" * 1480)
        held = sum(len(x) for e in f.pending.values() for x in e["parts"].values())
        return held <= 4 << 20, f"{held} bytes held of {250 * 40 * 1480} sent"
    case("fragment reassembly holds at most 4 MiB", fragments)

    def routes():
        sh("ip link add dr0 type dummy && ip addr add 203.0.113.1/24 dev dr0 && ip link set dr0 up")
        sh("ip link add dr1 type dummy && ip addr add 203.0.113.129/25 dev dr1 && ip link set dr1 up")
        try:
            sh("ip route add default dev dr0 table 77")
            a = su.default_route_devs()
            sh("ip route add default table 78 nexthop dev dr0 nexthop dev dr1")
            b = su.default_route_devs()
            return "dr0" in a and "dr1" in b, (a, b)
        finally:
            sh("ip link del dr0; ip link del dr1", check=False)
    case("default routes in other tables and ECMP next hops are seen", routes)

    def backup():
        os.makedirs("/var/lib/goatrope")
        try:
            tm._save_state({"ports": {"a": 1}})
            tm._save_state({"ports": {"a": 2}})
            open(tm.STATE, "w").close()
            return tm._load_state() == {"ports": {"a": 1}}, "previous copy used"
        finally:
            shutil.rmtree("/var/lib/goatrope")
    case("an empty state file falls back to the previous copy", backup)

    def dashes():
        c = cm.parse(INLINE.replace('filter = ""', 'filter = "-c1"'))
        a = tm.recorder_argv(c, "tp0")
        r = subprocess.run(["tcpdump", "-d", "-i", "lo"] + a[a.index("--"):], capture_output=True, text=True)
        return r.returncode != 0 and "syntax error" in r.stderr, r.stderr.strip()[-120:]
    case("a filter that looks like an option reaches tcpdump as a filter", dashes)

    def clsact():
        topo_listen()
        sh("tc qdisc add dev tp0 clsact && tc filter add dev tp0 ingress pref 9 matchall action pass")
        before = sh("tc filter show dev tp0 ingress").stdout
        write_cfg(LISTEN)
        stand_in_watchdog()
        p = gr("install", "--config", CFG)
        dropped = "drop" in sh("tc filter show dev tp0 egress").stdout
        q = gr("uninstall", "--purge")
        after = sh("tc filter show dev tp0 ingress").stdout
        left = sh("tc filter show dev tp0 egress").stdout.strip()
        return p.returncode == q.returncode == 0 and dropped and before == after and not left, (p.returncode, q.returncode, dropped, before == after, left)
    case("uninstall keeps the operator's own tc filters", clsact)

    def previous():
        topo_listen()
        write_cfg(LISTEN)
        gr("install", "--config", CFG)
        write_cfg(LISTEN.replace("files = 4", "files = 5"))
        gr("install", "--config", CFG)
        kept = open("/etc/goatrope/goatrope.toml.prev").read()
        gr("uninstall", "--purge")
        return "files = 4" in kept and not os.path.exists("/etc/goatrope"), "kept, then purged"
    case("a replaced declaration is kept as .prev", previous)


PHASES["units"] = phase_units


def phase_networkmanager() -> None:
    """NetworkManager manages the ports before install (as it does on a desktop image); install must take
    them from it at once, and uninstall must give them back."""
    topo_listen()
    before = snapshot()
    with open(f"{WORK}/before.json", "w") as f:
        json.dump(before, f)
    managed = {}
    for _ in range(60):
        managed = {k: v for k, v in nm_states().items() if k in ("tp0", "tp1")}
        if len(managed) == 2 and all(v != "unmanaged" for v in managed.values()):
            break
        time.sleep(1)
    result(len(managed) == 2 and all(v != "unmanaged" for v in managed.values()),
           "networkmanager: before install, NetworkManager manages tp0 and tp1", str(managed))
    write_cfg(LISTEN)
    stand_in_watchdog()
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "networkmanager: install listen", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}")
    st = nm_states()
    result(st.get("tp0") == "unmanaged" and st.get("tp1") == "unmanaged",
           "networkmanager: right after install, NetworkManager no longer manages the ports", str({k: st.get(k) for k in ("tp0", "tp1")}))
    result(st.get("eth0") == "unmanaged", "networkmanager: the management interface, which another file keeps "
           "from NetworkManager, is still not managed by it (goatrope adds to unmanaged-devices, never replaces it)",
           f"eth0: {st.get('eth0')}")
    c0, c1 = Capture("feed", "f0", "nm-f0"), Capture("feed", "f1", "nm-f1")
    time.sleep(20)  # DHCP and router solicitation retries would show here
    sh("systemctl restart NetworkManager.service")
    time.sleep(10)
    f0, f1 = c0.stop(), c1.stop()
    result(not f0 and not f1, "networkmanager: nothing sent toward the feed over 30 s, a NetworkManager restart included",
           f"{len(f0)} + {len(f1)} frames")
    j = check_exit(0, "networkmanager: check after install", "--json")
    ids = [i["id"] for i in (j or {}).get("items", [])]
    result(sum(i.startswith("networkmanager-unmanaged:") for i in ids) == 2,
           "networkmanager: check reads NetworkManager's view of both ports", ", ".join(i for i in ids if "networkmanager" in i))
    p = gr("uninstall", "--purge")
    for _ in range(20):
        st = nm_states()
        if st.get("tp0") != "unmanaged":
            break
        time.sleep(1)
    result(p.returncode == 0 and st.get("tp0") != "unmanaged",
           "networkmanager: after uninstall, NetworkManager manages the ports again", str({k: st.get(k) for k in ("tp0", "tp1")}))


PHASES["networkmanager"] = phase_networkmanager


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
