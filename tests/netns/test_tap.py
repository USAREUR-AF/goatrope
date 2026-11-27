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
GR = [os.path.join(SRC, "bin", "goatrope")]  # the launcher runs bin/<arch>/goatrope
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
            if REAL_WATCHDOG and dp == "/var/lib":  # in the VM, its other services write here while the tests run
                dn[:] = [d for d in dn if d == "private" or d.startswith("goatrope")]
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


def wait_packet_sockets(port: str, n: int, timeout: float = 300) -> None:
    """Wait until n packet sockets are bound to port. A unit is active before its program has opened
    its socket; under emulation that takes seconds, and frames sent sooner are not seen."""
    index = open(f"/sys/class/net/{port}/ifindex").read().strip()
    end = time.time() + timeout
    while time.time() < end:
        rows = open("/proc/net/packet").read().splitlines()[1:]
        if sum(1 for r in rows if r.split()[4] == index) >= n:
            return
        time.sleep(0.5)


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
    refused("relay wip that is not true or false", ok_cfg + """
[relay]
wip = "yes"
remote_interface = "eth0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [{ direction = "remote-to-link", protocol = "udp", remote = "198.51.100.5", listen_port = 7000, target = "192.0.2.2", target_port = 7000 }]
""", "wip must be true or false")
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
    p = subprocess.run(GR + ["uninstall", "--purge"],
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
    """Decode-and-send on the listen tap: UDP, TCP, HTTP and file destinations (conversion: phase linked-engine)."""
    cfg = LISTEN + f"""
[[send]]
name = "plain"
port = "tp0"
match = {{ protocol = "udp", src = "192.0.2.10", dst_port = 5000 }}
to = ["udp://127.0.0.1:9101", {{ url = "file:///var/lib/goatrope/send/plain.jsonl", format = "jsonl", max_mb = 50 }},
      {{ url = "tcp://127.0.0.1:9102", framing = "len32be" }}, "http://127.0.0.1:9103/in"]

[[send]]
name = "wider"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
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
WAIT = int(sys.argv[1])
got = {"udp": [], "tcp": [], "http": [], "conv": []}
def udp(port, key):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port)); s.settimeout(WAIT)
    try:
        while True: got[key].append(s.recv(65535).hex())
    except socket.timeout: pass
def tcp():
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("127.0.0.1", 9102)); l.listen(1); l.settimeout(WAIT)
    try:
        c, _ = l.accept(); c.settimeout(WAIT); buf = b""
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
import time; end = time.time() + WAIT
def full(): return all(len(got[k]) >= n for k, n in (("udp", 101), ("tcp", 101), ("http", 101), ("conv", 151)))
while time.time() < end and not full(): srv.handle_request()
settle = time.time() + 3  # anything past the expected count still shows
while time.time() < settle: srv.handle_request()
print(json.dumps({k: len(v) for k, v in got.items()} | {"sample_conv": got["conv"][:1], "sample_udp": got["udp"][:1]}), flush=True)
import os; os._exit(0)
""", "900" if REAL_WATCHDOG else "30"], stdout=subprocess.PIPE, text=True)
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
    got = json.loads(rx.communicate(timeout=1200)[0])
    result(got["udp"] == 101, "send: UDP destination got the 100 matching datagrams and 1 reassembled from 2 fragments",
           f"{got['udp']}")
    result(got["tcp"] == 101, "send: TCP destination (len32be) got the same 101", f"{got['tcp']}")
    result(got["http"] == 101, "send: HTTP destination got the same 101", f"{got['http']}")
    lines = open("/var/lib/goatrope/send/plain.jsonl").read().splitlines()
    result(len(lines) == 101, "send: file destination holds 101 JSON lines", f"{len(lines)}")
    result(got["conv"] == 151, "send: a second feed with a wider match got 151 messages", f"{got['conv']}")
    sample = bytes.fromhex(got["sample_conv"][0]).decode() if got["sample_conv"] else ""
    result(sample == "SEND\x00\x00\x00\x00", "send: a feed sends the datagram's payload as it was", repr(sample))
    time.sleep(2)
    b = "/var/lib/goatrope/send/bounded.jsonl"
    sizes = [os.path.getsize(f) if os.path.exists(f) else -1 for f in (b, b + ".1")]
    n = sum(len(open(f).read().splitlines()) for f in (b, b + ".1") if os.path.exists(f))
    result(sizes[1] > 0 and max(sizes) < 1_000_000 + 4_000 and n == 600,
           "send: a file destination with max_mb = 1 is cut at 1 MB, one older file kept, nothing lost",
           f"sizes {sizes}, {n} of 600 lines")
    mode = oct(os.stat("/var/lib/goatrope/send/plain.jsonl").st_mode & 0o777)
    result(mode == "0o640", "send: file destinations are not world-readable", mode)
    check_exit(0, "send: check after install (heartbeats)")


PHASES = {"refusals": phase_refusals, "inline": phase_inline, "reboot-verify": phase_reboot_verify,
          "uninstall": lambda: phase_uninstall(True), "listen": phase_listen, "send": phase_send}

RELAY = """schema = 1
[relay]
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
           "relay: an allowed datagram reaches its one target, from the relay's own address", f"{len(ok7000)} of 20")
    result(rep == "20", "relay: replies from the target return to the remote machine (direction both)", f"{rep} of 20")
    result(len(got["7002"]) == 5, "relay: a one-way rule forwards", f"{len(got['7002'])} of 5")
    result(not got["7001"], "relay: a port with no rule forwards nothing", f"{len(got['7001'])}")
    result(not any(d.startswith("otherpeer") for d, _ in got["7000"]),
           "relay: an authenticated peer that is not the rule's remote is denied", "denied" if "denied" in out else out[-200:])
    result(not any(d.startswith("outside") for d, _ in got["7000"]), "relay: nothing from outside the tunnel is relayed")
    bad = []
    for f in frames:
        et = f[12:14]
        if et == b"\x08\x06":
            continue  # ARP: the relay answers for its own address, as any host on the link does
        if et == b"\x08\x00" and f[23] == 17 and f[26:30] == bytes([192, 0, 2, 50]) and f[30:34] == bytes([192, 0, 2, 2]) \
                and int.from_bytes(f[36:38], "big") in (7000, 7002):
            continue
        bad.append(f[:40].hex())
    result(not bad, "relay: on the link, only ARP and the allowed datagrams were sent", f"{len(frames)} frames, {len(bad)} other: {bad[:3]}")
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
    # one reply socket per rule, in no fixed order: send to each, the rule with no target on this port denies it
    port = [int(ln.split()[3].rsplit(":", 1)[1]) for ln in sh("ss -Huan").stdout.splitlines()
            if ln.split()[3].startswith(("192.0.2.50:", "192.0.2.50%"))]
    allowed = subprocess.run(["wg", "pubkey"], input=open(f"{WORK}/allowed.key").read(), capture_output=True,
                             text=True).stdout.strip()
    sh(f"wg set wg0 peer {allowed} remove")
    sh("ip netns exec linkhost python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
       f"s.bind(('192.0.2.2',7000));[s.sendto(b'late',('192.0.2.50',p)) for p in {port} for i in range(3)]\"", check=False)
    time.sleep(3)
    health = json.load(open("/var/lib/goatrope/relay.health"))
    errs = sum(r.get("send_errors", 0) for r in health["rules"])
    result(relay.poll() is None and errs >= 1, "relay: a reply it cannot send is counted and the relay keeps running",
           f"running={relay.poll() is None}, send_errors={errs}, primed={primed}, port={port}, health={health['rules']}")
    sh(f"wg set wg0 peer {allowed} allowed-ips 10.99.0.2/32")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=1")
    try:
        rc = relay.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay.kill()
        rc = None
    result(rc == 1, "relay: it stops when IP forwarding is turned on while it runs", f"exit {rc}")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0")


PHASES["relay"] = phase_relay


BOUNDARY = """schema = 1
[relay]
transport = "boundary"
remote_interface = "grb0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [
  { direction = "both", protocol = "udp", remote = "10.200.0.1", listen_port = 7000, target = "192.0.2.2", target_port = 7000 },
]
[relay.boundary]
listen_port = 51901
private_key_file = "/root/gt/bnd/boundary.key"
address = "10.200.0.2/30"
peer_public_key = "PEERKEY"
peer_endpoint = "203.0.113.7:51900"
peer_address = "10.200.0.1"
"""


def phase_boundary() -> None:
    """A site outside the deployment: goatrope's own WireGuard interface, one peer, the boundary point."""
    for leftover in ("wg0", "u0", "r0"):  # the relay phase's interfaces, if it ran first in this container
        sh(f"ip link del {leftover}", check=False)
    topo_relay()  # the link side (r0 -> linkhost 192.0.2.2); its wg0 is not used here
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1 net.ipv4.conf.r0.forwarding=0 net.ipv6.conf.all.forwarding=0")
    sh("ip netns del bpoint", check=False)
    sh("ip link del grb0", check=False)
    shutil.rmtree(f"{WORK}/bnd", ignore_errors=True)
    sh("ip netns add bpoint && ip -n bpoint link set lo up")
    sh("ip link add bp0 type veth peer name bp1 && ip link set bp1 netns bpoint")
    sh("ip addr add 203.0.113.1/24 dev bp0 && ip link set bp0 up")
    sh("ip -n bpoint addr add 203.0.113.7/24 dev bp1 && ip -n bpoint link set bp1 up")
    bpriv = sh("wg genkey").stdout.strip()
    bpub = subprocess.run(["wg", "pubkey"], input=bpriv, capture_output=True, text=True).stdout.strip()
    cfg = BOUNDARY.replace("PEERKEY", bpub)
    write_cfg(cfg)

    p = gr("boundary", "check", "--config", CFG)
    result(p.returncode == 3 and "does not exist" in p.stdout, "boundary: check before a key exists differs", p.stdout.strip()[-160:])
    p = gr("boundary", "key", "--config", CFG)
    key = f"{WORK}/bnd/boundary.key"
    mode = oct(os.stat(key).st_mode & 0o777) if os.path.exists(key) else "absent"
    mypub = p.stdout.split("public key ", 1)[1].split()[0] if "public key " in p.stdout else ""
    result(p.returncode == 0 and mode == "0o600" and len(mypub) == 44 and "PRIVATE" not in p.stdout.upper(),
           "boundary: key writes a mode-600 private key and prints only the public key", f"exit {p.returncode}, {mode}")
    p = gr("boundary", "key", "--config", CFG)
    result(p.returncode == 2 and "never replaces" in p.stderr, "boundary: key refuses to replace an existing key", p.stderr.strip()[-120:])

    # The boundary point: one WireGuard peer, us.
    sh("ip -n bpoint link add bpw type wireguard")
    subprocess.run(["ip", "netns", "exec", "bpoint", "wg", "set", "bpw", "listen-port", "51900", "private-key", "/dev/stdin",
                    "peer", mypub, "endpoint", "203.0.113.1:51901", "allowed-ips", "10.200.0.2/32"],
                   input=bpriv + "\n", text=True, check=True)
    sh("ip -n bpoint addr add 10.200.0.1/30 dev bpw && ip -n bpoint link set bpw up")

    rx = subprocess.Popen(["ip", "netns", "exec", "linkhost", sys.executable, "-c", """
import socket, json, select, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.2", 7000))
got = []; end = time.time() + 10
while time.time() < end:
    if select.select([s], [], [], 0.5)[0]:
        d, a = s.recvfrom(65535); got.append([d.decode(), a[0]]); s.sendto(b"reply-" + d, a)
print(json.dumps(got))
"""], stdout=subprocess.PIPE, text=True)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(3)
    made = sh("ip -d link show grb0", check=False).stdout
    result("wireguard" in made, "boundary: the relay makes its boundary interface when it is absent", made.strip()[:120])
    sender = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, 25, b"bpw")
s.bind(("10.200.0.1", 0)); s.settimeout(0.5); n = 0
for i in range(10):
    s.sendto(f"bp{i}".encode(), ("10.200.0.2", 7000))
    try:
        n += s.recv(65535).startswith(b"reply-")
    except socket.timeout: pass
print(n)
"""
    rep = sh(f"ip netns exec bpoint python3 -c '{sender}'", check=False).stdout.strip()
    got = json.loads(rx.communicate(timeout=30)[0])
    result(len(got) == 10 and all(a == "192.0.2.50" for _, a in got) and rep == "10",
           "boundary: datagrams from the boundary point reach the target and replies return",
           f"{len(got)} delivered, {rep} replies")
    p = gr("boundary", "check", "--config", CFG)
    result(p.returncode == 0, "boundary: check says the interface matches the declaration", p.stdout.strip()[-160:])

    # A second peer on the boundary interface: the relay stops.
    other = subprocess.run(["wg", "pubkey"], input=sh("wg genkey").stdout, capture_output=True, text=True).stdout.strip()
    sh(f"wg set grb0 peer {other} allowed-ips 10.200.0.3/32")
    try:
        rc = relay.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay.kill()
        rc = None
    out = relay.communicate(timeout=10)[0]
    result(rc == 1 and "2 peers" in out, "boundary: the relay stops when a second peer is added to its interface", f"exit {rc}: {out.strip()[-160:]}")
    sh(f"wg set grb0 peer {other} remove")

    # Each way the interface can differ from the declaration is a difference, and the relay refuses to start on it.
    for name, bad, undo, want in (
            ("the peer may send from more than one address", f"wg set grb0 peer {bpub} allowed-ips 10.200.0.0/30",
             f"wg set grb0 peer {bpub} allowed-ips 10.200.0.1/32", "allows only"),
            # the boundary point is down meanwhile: a packet from it would move the endpoint back (roaming)
            ("another endpoint", f"ip -n bpoint link set bpw down && wg set grb0 peer {bpub} endpoint 203.0.113.9:51900",
             f"wg set grb0 peer {bpub} endpoint 203.0.113.7:51900 && ip -n bpoint link set bpw up", "endpoint"),
            ("another listen port", "wg set grb0 listen-port 51999", "wg set grb0 listen-port 51901", "listens on"),
            ("a key file others can read", f"chmod 644 {key}", f"chmod 600 {key}", "mode 600")):
        sh(bad)
        p = gr("boundary", "check", "--config", CFG)
        q = gr("relay", "--config", CFG)
        sh(undo)
        result(p.returncode == 3 and want in p.stdout and q.returncode == 2,
               f"boundary: {name} is a difference, and the relay refuses to start", f"check {p.returncode}, relay {q.returncode}: {p.stdout.strip()[-120:]}")

    p = gr("boundary", "check", "--config", CFG)
    result(p.returncode == 0, "boundary: after each repair, check matches again", p.stdout.strip()[-120:])
    p = gr("boundary", "down", "--config", CFG)
    result(p.returncode == 0 and not os.path.exists("/sys/class/net/grb0"), "boundary: down removes the interface", p.stdout.strip())
    p = gr("boundary", "up", "--config", CFG)
    result(p.returncode == 0 and "made" in p.stdout, "boundary: up makes it again from the declaration", p.stdout.strip())
    sh("ip link del grb0", check=False)
    sh("ip link add grb0 type dummy")
    q = gr("relay", "--config", CFG)
    sh("ip link del grb0", check=False)
    result(q.returncode == 2 and "not a WireGuard interface" in q.stderr,
           "boundary: an existing non-WireGuard interface under that name is refused", q.stderr.strip()[-120:])
    for name, text, want in (
            ("the mesh's own port", cfg.replace("listen_port = 51901", "listen_port = 51820"), "mesh's own"),
            ("a rule whose remote is not the boundary point", cfg.replace('remote = "10.200.0.1"', 'remote = "10.200.0.9"'), "not the boundary point"),
            ("an endpoint given as a name", cfg.replace('"203.0.113.7:51900"', '"bp.example:51900"'), "name is not accepted")):
        write_cfg(text)
        p = gr("validate", "--config", CFG)
        result(p.returncode == 2 and want in p.stderr, f"boundary refused at validation: {name}", p.stderr.strip()[-120:])
    sh("ip netns del bpoint", check=False)


PHASES["boundary"] = phase_boundary


def unit_props(unit: str = "goatrope-relay.service") -> dict:
    out = sh(f"systemctl show {unit} -p ActiveState -p SubState -p NRestarts -p ExecMainStatus -p Result", check=False).stdout
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


def wait_unit(want: str, timeout: float = 20) -> dict:
    end = time.monotonic() + timeout
    while True:
        u = unit_props()
        if u.get("ActiveState") == want or time.monotonic() > end:
            return u
        time.sleep(0.5)


def relay_through(n: int, tag: str) -> int:
    """n datagrams from the allowed peer to rule port 7002; how many reached the link host."""
    rx = subprocess.Popen(["ip", "netns", "exec", "linkhost", sys.executable, "-c", """
import socket, select, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.2", 7002))
n = 0; end = time.time() + 6
while time.time() < end:
    if select.select([s], [], [], 0.3)[0]:
        n += s.recv(65535).startswith(sys.argv[1].encode())
print(n)
""", tag], stdout=subprocess.PIPE, text=True)
    time.sleep(0.5)
    code = ("import socket,sys,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,25,b'wga')\n"
            "s.bind(('10.99.0.2',0))\nfor i in range(int(sys.argv[1])):\n s.sendto(f'{sys.argv[2]}{i}'.encode(),('10.99.0.1',7002)); time.sleep(0.02)\n")
    sh(f"ip netns exec remote python3 -c \"{code}\" {n} {tag}", check=False)
    return int(rx.communicate(timeout=30)[0].strip() or 0)


def phase_relay_service() -> None:
    """ADR 0004 module 1: install writes and starts goatrope-relay.service; check reads it."""
    for leftover in ("wg0", "u0", "r0", "grb0"):
        sh(f"ip link del {leftover}", check=False)
    topo_relay()
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1 net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 "
       "net.ipv6.conf.all.forwarding=0")
    write_cfg(RELAY.replace("[relay]\n", "[relay]\nwip = true\n"))
    p = gr("validate", "--config", CFG)
    result(p.returncode == 0, "relay service: wip = true still parses (and does nothing)", p.stderr.strip()[-120:])
    write_cfg(RELAY)
    before = snapshot()
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "relay service: install of a declaration with only [relay]",
           f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-400:]}")
    unit = "/etc/systemd/system/goatrope-relay.service"
    text = open(unit).read() if os.path.exists(unit) else ""
    want = ("ExecStart=/usr/local/sbin/goatrope relay --config /etc/goatrope/goatrope.toml", "Restart=on-failure",
            "RestartPreventExitStatus=2", "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN")
    result(all(w in text for w in want), "relay service: install writes the unit (on-failure; the refusal code is not restarted)",
           f"{sum(w in text for w in want)} of {len(want)} lines present")
    after = snapshot()
    tapish = [k for k in after["files"] if k not in before["files"]
              and ("/systemd/network/" in k or "goatrope-ports" in k or "goatrope-record" in k or k.endswith("90-goatrope.conf")
                   or "system.conf.d" in k)]
    result(not tapish and after["networkd"] == before["networkd"] and after["watchdog"] == before["watchdog"],
           "relay service: install touches no tap port and writes no tap file", f"{tapish}; networkd {after['networkd']}")
    u = wait_unit("active")
    result(u.get("ActiveState") == "active", "relay service: the unit is enabled and active",
           f"{u}, {sh('systemctl is-enabled goatrope-relay.service', check=False).stdout.strip()}")
    check_exit(0, "relay service: active")
    n = relay_through(20, "svc")
    result(n == 20, "relay service: the service forwards an allowed rule", f"{n} of 20")
    time.sleep(2.5)
    p = gr("status", "--config", CFG)
    result("rule" in p.stdout and "sent to the link" in p.stdout and "active" in p.stdout,
           "relay service: status shows the rules and counters", " | ".join(p.stdout.splitlines()[1:6])[:400])

    sh("systemctl stop goatrope-relay.service")
    check_exit(3, "relay service: stopped")
    sh("systemctl start goatrope-relay.service")
    wait_unit("active")
    time.sleep(1)
    check_exit(0, "relay service: started again")
    sh("systemctl kill --signal=SIGSTOP goatrope-relay.service")
    time.sleep(12)
    p = gr("check", "--config", CFG)
    stale = [ln for ln in p.stdout.splitlines() if "DIFF" in ln]
    result(p.returncode == 3 and any("relay-health" in ln for ln in stale) and unit_props().get("ActiveState") == "active",
           "relay service: a hung relay (unit active, relay.health older than 10 s): check exits 3",
           f"exit {p.returncode}: {'; '.join(stale)[:200]}")
    sh("systemctl kill --signal=SIGCONT goatrope-relay.service")
    time.sleep(3)
    check_exit(0, "relay service: after it resumes")

    # IP forwarding turned on while it runs: the relay exits 1 and is restarted once; that start is a refusal
    # (exit 2), which is not restarted.
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=1")
    time.sleep(15)
    u = unit_props()
    result(u.get("ActiveState") == "failed" and u.get("ExecMainStatus") == "2" and u.get("NRestarts") == "1",
           "relay service: a failure is restarted, and the refusal that follows is not", str(u))
    time.sleep(10)
    u2 = unit_props()
    result(u2.get("NRestarts") == "1" and u2.get("ActiveState") == "failed", "relay service: 10 s later it is still stopped, not restarted",
           str(u2))
    check_exit(3, "relay service: refused")
    sh("systemctl reset-failed goatrope-relay.service", check=False)
    sh("systemctl start goatrope-relay.service")
    time.sleep(5)
    u = unit_props()
    result(u.get("ActiveState") == "failed" and u.get("ExecMainStatus") == "2" and u.get("NRestarts") == "0",
           "relay service: a refusal at start (IP forwarding on) is not restarted", str(u))
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0")
    sh("systemctl reset-failed goatrope-relay.service", check=False)
    sh("systemctl start goatrope-relay.service")
    wait_unit("active")
    time.sleep(1)
    check_exit(0, "relay service: forwarding off and started again")

    p = gr("uninstall")
    left = diff(before, snapshot())
    allowed = [x for x in left if x.startswith("file /etc/goatrope")]
    result(p.returncode == 0 and set(left) == set(allowed) and not os.path.exists("/var/lib/goatrope/relay.health"),
           "relay service: uninstall removes the unit and relay.health; only the declaration remains",
           "; ".join(x for x in left if x not in allowed)[:400] or "; ".join(allowed)[:200])
    gr("uninstall", "--purge")
    left = diff(before, snapshot())
    result(not left, "relay service: uninstall --purge leaves nothing", "; ".join(left)[:400])

    # A declaration with both [tap] and [relay]: both are installed and checked.
    topo_listen()
    stand_in_watchdog()
    before = snapshot()
    both = LISTEN + RELAY.replace("schema = 1\n", "")
    write_cfg(both)
    p = gr("install", "--config", CFG)
    wait_unit("active")
    time.sleep(1)
    result(p.returncode == 0 and unit_props().get("ActiveState") == "active"
           and sh("systemctl is-active goatrope-ports.service", check=False).stdout.strip() == "active",
           "relay service: a declaration with [tap] and [relay] installs both", f"exit {p.returncode}: {p.stdout.strip()[-200:]}")
    check_exit(0, "relay service: tap and relay")
    n = relay_through(10, "both")
    result(n == 10, "relay service: with a tap beside it, the relay forwards", f"{n} of 10")
    write_cfg(RELAY)
    p = gr("install", "--config", CFG)
    result(p.returncode == 2 and "uninstall first" in p.stderr,
           "relay service: a relay-only declaration over an installed tap is refused", p.stderr.strip()[-160:])
    write_cfg(both)
    gr("uninstall", "--purge")
    left = diff(before, snapshot())
    result(not left, "relay service: uninstall --purge of tap and relay leaves nothing", "; ".join(left)[:400])


PHASES["relay-service"] = phase_relay_service


RELAY_TCP = """schema = 1
[relay]
remote_interface = "wg0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [
  { direction = "remote-to-link", protocol = "tcp", remote = "10.99.0.2", listen_port = 7100, target = "192.0.2.2", target_port = 7100, max_connections = 3 },
  { direction = "link-to-remote", protocol = "udp", remote = "10.99.0.2", listen_port = 8000, remote_port = 8000, sources = ["192.0.2.2"] },
  { direction = "link-to-remote", protocol = "tcp", remote = "10.99.0.2", listen_port = 8001, remote_port = 8001, sources = ["192.0.2.2"] },
]
"""

# A TCP server that logs each connection's peer, reads until the client closes its sending half,
# answers b"echo:" + what it read, and closes. A UDP server that answers b"reply-" + the datagram.
NET_SERVER = r"""
import socket, sys, threading
kind, host, port, log = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
def note(line):
    with open(log, "a") as f:
        f.write(line + "\n")
if kind == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((host, port))
    while True:
        d, a = s.recvfrom(65535); note(f"udp {a[0]} {d.decode()}"); s.sendto(b"reply-" + d, a)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((host, port)); s.listen(64)
def serve(c, a):
    note(f"accept {a[0]}")
    data = b""
    while True:
        d = c.recv(65536)
        if not d:
            break
        data += d
    c.sendall(b"echo:" + data); c.close(); note(f"done {len(data)}")
while True:
    c, a = s.accept(); threading.Thread(target=serve, args=(c, a), daemon=True).start()
"""

# A TCP client: n connections from src (bound to dev), each sends size bytes, closes its sending half
# and reads to the end. "hold": opens n connections, sends nothing, and reports which the relay closed.
NET_CLIENT = r"""
import json, socket, sys, time
mode, dev, src, dst, port, n, size = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])
def conn():
    c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, 25, dev.encode()); c.bind((src, 0)); c.settimeout(5)
    c.connect((dst, port)); return c
out = {"ok": 0, "closed": 0, "errors": []}
if mode == "echo":
    for i in range(n):
        payload = bytes([65 + i % 26]) * size
        try:
            c = conn(); c.sendall(payload); c.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                d = c.recv(65536)
                if not d:
                    break
                got += d
            if got == b"echo:" + payload:
                out["ok"] += 1
            else:
                out["closed"] += 1
        except OSError as e:
            out["closed"] += 1; out["errors"].append(str(e))
else:
    held = []
    for i in range(n):
        try:
            held.append(conn())
        except OSError as e:
            out["errors"].append(str(e))
        time.sleep(0.2)
    time.sleep(1.5)
    for c in held:
        c.settimeout(0.5)
        try:
            d = c.recv(1)
            out["closed" if not d else "ok"] += 1
        except socket.timeout:
            out["ok"] += 1  # still open: nothing to read, no end
        except OSError:
            out["closed"] += 1
    for c in held:
        c.close()
print(json.dumps(out))
"""

UDP_CLIENT = r"""
import socket, sys
dev, src, dst, port, n, tag = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, 25, dev.encode())
s.bind((src, 0)); s.settimeout(0.3); replies = 0
for i in range(n):
    s.sendto(f"{tag}{i}".encode(), (dst, port))
    try:
        replies += s.recv(65535) == f"reply-{tag}{i}".encode()
    except socket.timeout:
        pass
print(replies)
"""


def lines(path: str) -> list[str]:
    try:
        return open(path).read().splitlines()
    except OSError:
        return []


def relay_rows() -> list[dict]:
    try:
        return json.load(open("/var/lib/goatrope/relay.health"))["rules"]
    except (OSError, ValueError, KeyError):
        return []


def phase_relay_tcp() -> None:
    """ADR 0004 module 2: TCP rules, and traffic a machine on the link starts (link-to-remote)."""
    for leftover in ("wg0", "u0", "r0", "grb0"):
        sh(f"ip link del {leftover}", check=False)
    topo_relay()
    sh("ip -n linkhost addr add 192.0.2.3/24 dev l0")  # a second machine on the link, not in any rule's sources
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1 net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 "
       "net.ipv6.conf.all.forwarding=0")
    for name, text, want in (
            ("tcp with direction both", RELAY_TCP.replace('"remote-to-link", protocol = "tcp"', '"both", protocol = "tcp"'),
             "refused for TCP"),
            ("link-to-remote without sources", RELAY_TCP.replace(', sources = ["192.0.2.2"] },\n  { direction = "link-to-remote", protocol = "tcp"',
                                                                  ' },\n  { direction = "link-to-remote", protocol = "tcp"'),
             "missing required key(s) sources"),
            ("a source that is not on the link", RELAY_TCP.replace('sources = ["192.0.2.2"] },\n  { direction = "link-to-remote", protocol = "tcp"',
                                                                   'sources = ["198.51.100.9"] },\n  { direction = "link-to-remote", protocol = "tcp"'),
             "is not on the link"),
            ("max_connections on a UDP rule", RELAY_TCP.replace("remote_port = 8000,", "remote_port = 8000, max_connections = 4,"),
             "unknown key")):
        write_cfg(text)
        p = gr("validate", "--config", CFG)
        result(p.returncode == 2 and want in p.stderr, f"relay tcp refused at validation: {name}", p.stderr.strip()[-160:])

    srv = f"{WORK}/net-server.py"
    cli = f"{WORK}/net-client.py"
    ucli = f"{WORK}/udp-client.py"
    for path, text in ((srv, NET_SERVER), (cli, NET_CLIENT), (ucli, UDP_CLIENT)):
        with open(path, "w") as f:
            f.write(text)
    logs = {k: f"{WORK}/srv-{k}.log" for k in ("link", "remote-udp", "remote-tcp")}
    for p in logs.values():
        open(p, "w").close()
    servers = [
        subprocess.Popen(["ip", "netns", "exec", "linkhost", sys.executable, srv, "tcp", "192.0.2.2", "7100", logs["link"]]),
        subprocess.Popen(["ip", "netns", "exec", "remote", sys.executable, srv, "udp", "10.99.0.2", "8000", logs["remote-udp"]]),
        subprocess.Popen(["ip", "netns", "exec", "remote", sys.executable, srv, "tcp", "10.99.0.2", "8001", logs["remote-tcp"]]),
    ]
    write_cfg(RELAY_TCP)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)

    def client(ns: str, *args: str) -> dict:
        p = sh(f"ip netns exec {ns} {sys.executable} {cli} {' '.join(args)}", check=False)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": 0, "closed": 0, "errors": [p.stderr.strip()[-200:]]}

    try:
        # remote -> link, both ways, half-close passed on
        r = client("remote", "echo", "wga", "10.99.0.2", "10.99.0.1", "7100", "5", "100000")
        acc = [ln for ln in lines(logs["link"]) if ln.startswith("accept")]
        done = [ln for ln in lines(logs["link"]) if ln == "done 100000"]
        result(r["ok"] == 5 and len(done) == 5 and all(ln == "accept 192.0.2.50" for ln in acc),
               "relay tcp: remote -> link both ways (100000 bytes each way, the client's half-close passed on), from the relay's address",
               f"{r['ok']} of 5 echoed; target saw {len(done)} of 5 whole, from {sorted(set(acc))}; {r['errors'][:2]}")
        before = len(lines(logs["link"]))
        r = client("remote", "echo", "wgo", "10.99.0.3", "10.99.0.1", "7100", "3", "100")
        time.sleep(0.5)
        result(r["ok"] == 0 and len(lines(logs["link"])) == before,
               "relay tcp: a connection from another authenticated peer is closed, and never reaches the target",
               f"{r['closed']} of 3 closed; target saw {len(lines(logs['link'])) - before} lines")
        before = len([ln for ln in lines(logs["link"]) if ln.startswith("accept")])
        r = client("remote", "hold", "wga", "10.99.0.2", "10.99.0.1", "7100", "5", "0")
        time.sleep(1)
        held = len([ln for ln in lines(logs["link"]) if ln.startswith("accept")]) - before
        result(r["ok"] == 3 and r["closed"] == 2 and held == 3, "relay tcp: max_connections = 3 enforced",
               f"5 opened: {r['ok']} held open, {r['closed']} closed; the target saw {held}")
        time.sleep(1)

        # link -> remote, UDP
        rep = sh(f"ip netns exec linkhost {sys.executable} {ucli} l0 192.0.2.2 192.0.2.50 8000 20 lu", check=False).stdout.strip()
        got = [ln for ln in lines(logs["remote-udp"]) if " lu" in ln]
        result(len(got) == 20 and all(ln.startswith("udp 10.99.0.1 ") for ln in got) and rep == "20",
               "relay link-to-remote udp: a link machine's datagrams reach the remote, and the replies come back",
               f"{len(got)} of 20 delivered, {rep} of 20 replies")
        sh(f"ip netns exec linkhost {sys.executable} {ucli} l0 192.0.2.3 192.0.2.50 8000 5 lx", check=False)
        got = [ln for ln in lines(logs["remote-udp"]) if " lx" in ln]
        result(not got, "relay link-to-remote udp: a link address not in sources is denied", f"{len(got)} of 5 delivered")

        # link -> remote, TCP
        r = client("linkhost", "echo", "l0", "192.0.2.2", "192.0.2.50", "8001", "3", "50000")
        acc = [ln for ln in lines(logs["remote-tcp"]) if ln.startswith("accept")]
        result(r["ok"] == 3 and len(acc) == 3 and all(ln == "accept 10.99.0.1" for ln in acc),
               "relay link-to-remote tcp: a link machine's connection reaches the remote through the tunnel, both ways",
               f"{r['ok']} of 3 echoed (50000 bytes each way); remote saw {len(acc)} from {sorted(set(acc))}")
        r = client("linkhost", "echo", "l0", "192.0.2.3", "192.0.2.50", "8001", "3", "100")
        time.sleep(0.5)
        acc2 = [ln for ln in lines(logs["remote-tcp"]) if ln.startswith("accept")]
        result(r["ok"] == 0 and len(acc2) == len(acc), "relay link-to-remote tcp: a link address not in sources is denied",
               f"{r['closed']} of 3 closed; remote saw {len(acc2) - len(acc)}")
        time.sleep(2.5)
        rows = {(x["protocol"], x["listen_port"]): x for x in relay_rows()}
        t, lu, lt = rows.get(("tcp", 7100), {}), rows.get(("udp", 8000), {}), rows.get(("tcp", 8001), {})
        result(t.get("denied") == 3 and t.get("over_limit") == 2 and t.get("bytes_to_link", 0) >= 500000
               and t.get("bytes_to_remote", 0) >= 500000 and lu.get("denied") == 5 and lt.get("denied") == 3
               and t.get("connections") == 0,
               "relay tcp: relay.health counts connections, bytes each way and denials per rule",
               f"7100 {t}; 8000 {lu}; 8001 {lt}")
        p = gr("status", "--config", CFG)
        result("over the limit" in p.stdout and "broken" in p.stdout and "link-to-remote" not in p.stdout and "connections from 192.0.2.2" in p.stdout,
               "relay tcp: status shows the TCP and link-initiated rules in words",
               " | ".join(ln.strip() for ln in p.stdout.splitlines() if "rule" in ln)[:400])

        # A remote that vanishes without a FIN (its WireGuard interface taken down): keepalive and the
        # user timeout free the slot within 120 s (60 s idle, then 6 probes 10 s apart).
        held = subprocess.Popen(["ip", "netns", "exec", "remote", sys.executable, "-c",
                                 "import socket,time\nc=socket.socket();c.setsockopt(socket.SOL_SOCKET,25,b'wga')\n"
                                 "c.bind(('10.99.0.2',0));c.connect(('10.99.0.1',7100));time.sleep(600)\n"])
        end = time.monotonic() + 20
        while time.monotonic() < end and {(x["protocol"], x["listen_port"]): x for x in relay_rows()}.get(("tcp", 7100), {}).get("connections") != 1:
            time.sleep(0.5)
        t0 = time.monotonic()
        sh("ip -n remote link set wga down")
        row, freed = {}, None
        while time.monotonic() < t0 + 200:
            row = {(x["protocol"], x["listen_port"]): x for x in relay_rows()}.get(("tcp", 7100), {})
            if row.get("connections") == 0:
                freed = time.monotonic() - t0
                break
            time.sleep(1)
        held.kill()
        sh("ip -n remote link set wga up")
        sh("ip -n remote route replace 10.99.0.1/32 dev wga metric 1")
        result(freed is not None and freed <= 135 and row.get("broken") == 1,
               "relay tcp: a remote that vanishes without a FIN frees its slot at the 120 s bound (relay.health is rewritten every 2 s)",
               f"freed after {freed if freed is None else round(freed)} s; connections {row.get('connections')}, broken {row.get('broken')}")
        result(relay.poll() is None, "relay tcp: the relay kept running", f"exit {relay.poll()}")
    finally:
        relay.terminate()
        try:
            relay.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            relay.kill()
        for s in servers:
            s.terminate()


PHASES["relay-tcp"] = phase_relay_tcp

COMPONENTS = "/opt/gt-components"  # run.sh copies the real binaries here when GOATROPE_TEST_COMPONENTS is set
REMOTE_ID = "122624160b42bf241b6ed1b4b69808ac0870086b53150e0200"  # goat-transformers' README example message
NTP = ("240206e90000060000000a80c0000201ed135500c0000000ed13554040000000ed13554043000000ed13554043800000")


def phase_components() -> None:
    """The linked goat-transformers engine with the given packs in a [[send]], and the real first-bite mind in a [[decode]]."""
    if not os.path.exists(f"{COMPONENTS}/mind") or not os.path.exists(f"{COMPONENTS}/packs/remote-id/pack.def"):
        result(None, "components: not run (no real mind and packs given; set GOATROPE_TEST_COMPONENTS)")
        return
    mind = f"{COMPONENTS}/mind"
    pin = {mind: hashlib.sha256(open(mind, "rb").read()).hexdigest()}
    ver = {b: sh(f"{b} --version", check=False).stdout.strip() or "unknown" for b in (mind,)}
    with open(f"{COMPONENTS}/publishers.yml", "w") as f:
        f.write("publishers:\n  - name: records\n    publisher_type: PUB\n    address: \"tcp://127.0.0.1:47123\"\n"
                "    topic: \"subsystem/message_type\"\n")
    with open(f"{COMPONENTS}/subscribers.yml", "w") as f:
        f.write("subscribers:\n  - name: ToFile\n    subscriber_type: local\n    subtype: locallog\n"
                "    zmq_url: 127.0.0.1\n    zmq_port: 47123\n    local_logfile: records.jsonl\n"
                "    topics: [\"*\"]\n")
    sh(f"chmod -R go+rX {COMPONENTS}")
    engine_version, packs_sha = packs_digest(f"{COMPONENTS}/packs")
    write_cfg(LISTEN + f"""
[[send]]
name = "remote-id"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
convert = {{ component = "goat-transformers", version = "{engine_version}", from = "remote-id", to = "cot-xml", packs = "{COMPONENTS}/packs", packs_sha256 = "{packs_sha}" }}
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
    result(p.returncode == 0, "components: install with the linked engine and the real mind",
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
           "components: the linked engine converted 10 of 10 Remote ID messages to Cursor-on-Target XML and they were sent",
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
    """Cases that call the code directly run from the Rust unit-test binary (tools/build-bin.sh,
    GOATROPE_BUILD_UNITS=1), here, as root; the rest drive the command line. A crash is that case's failure."""
    import re

    def case(name, fn):
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        result(bool(ok), "units: " + name, str(detail)[:300])

    exe = os.path.join(SRC, "bin", os.uname().machine, "goatrope-units")
    p = subprocess.run([exe, "--include-ignored", "--test-threads=1", "units::"], capture_output=True, text=True)
    seen = 0
    for line in p.stdout.splitlines():
        m = re.match(r"test units::(\w+) \.\.\. (ok|FAILED)$", line)
        if m:
            seen += 1
            failure = p.stdout.split(f"---- units::{m.group(1)} stdout ----", 1)
            detail = failure[1].strip().split("\n\n")[0] if len(failure) > 1 else ""
            result(m.group(2) == "ok", "units: " + m.group(1).replace("_", " "), detail[:300])
    result(p.returncode == 0 and seen == 6, "units: the six direct cases ran", f"exit {p.returncode}, {seen} ran {p.stderr.strip()[-200:]}")

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

    def networkd():
        units = "systemd-networkd.service"

        def links():
            return sh("find /etc/systemd/system -type l -lname '*/systemd-network*' | sort").stdout.split()
        had = sh(f"systemctl is-enabled {units}", check=False).stdout.strip()
        sh(f"systemctl disable {units} && systemctl enable --runtime {units}")  # as netplan leaves it
        before = links()
        try:
            topo_listen()
            write_cfg(LISTEN)
            stand_in_watchdog()
            gr("install", "--config", CFG)
            during = links()
            gr("uninstall", "--purge")
            state = sh(f"systemctl is-enabled {units}", check=False).stdout.strip()
            return len(during) > len(before) and links() == before and state == "enabled-runtime", \
                (before, during, links(), state)
        finally:
            sh(f"systemctl disable --runtime {units}", check=False)
            if had == "enabled":
                sh(f"systemctl enable {units}")
    case("uninstall leaves networkd enabled as it was (under /run only, as netplan does)", networkd)

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


# Stands in for the deploy driver's own release-file role: the file at <root>/<component>/<sha256>/<name>,
# `current` and `previous` beside it, and a ledger line. GOATROPE_TEST_ROLES puts the real one in /opt/gt-roles.
RELEASE_FILE_STUB = """
- ansible.builtin.shell: |
    set -e; h=/opt/goat/releases/goatrope; L=/var/log/gt-ledger
    if [ "{{ release_file_rollback | default(false) | bool }}" = True ]; then n=$(readlink $h/previous)
    else a=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
      n=$h/{{ (release_file_files | default({})).get('amd64', {}).get('sha256', '') }}/{{ (release_file_files | default({})).get('amd64', {}).get('name', '') }}
      mkdir -p $(dirname $n); cp {{ (release_file_files | default({})).get('amd64', {}).get('src', '') }} $n; fi
    c=$(readlink $h/current || true); [ -z "$c" ] || [ "$c" = "$n" ] || ln -sfn $c $h/previous
    ln -sfn $n $h/current; echo "$n" >> $L
"""
GT_HOME = "/opt/goat/releases/goatrope"


def make_release(version: str, d: str = "/opt/gt-dist") -> dict:
    """The release archive's layout (tools/build-release.sh), and the file as a driver passes it."""
    import io
    import tarfile
    os.makedirs(d, exist_ok=True)
    name = f"goatrope-{version}"
    path = f"{d}/{name}.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        for x in ("bin", "deploy", "examples"):
            t.add(f"{SRC}/{x}", f"{name}/{x}", filter=lambda i: None if "__pycache__" in i.name else i)
        data = (version + "\n").encode()
        i = tarfile.TarInfo(f"{name}/VERSION")
        i.size = len(data)
        t.addfile(i, io.BytesIO(data))
    return describe(path)


def describe(path: str) -> dict:
    with open(path, "rb") as f:
        return {"src": path, "name": os.path.basename(path), "sha256": hashlib.sha256(f.read()).hexdigest()}


def play(host_vars: dict, rel: dict | None = None, rollback: bool = False, *extra: str) -> subprocess.CompletedProcess:
    w = f"{WORK}/ansible"
    os.makedirs(f"{w}/inventory/host_vars", exist_ok=True)
    roles = [f"{SRC}/deploy/ansible/roles"]
    if os.path.isdir("/opt/gt-roles"):
        roles.append("/opt/gt-roles")
    else:
        os.makedirs(f"{w}/roles/release-file/tasks", exist_ok=True)
        with open(f"{w}/roles/release-file/tasks/main.yml", "w") as f:
            f.write(RELEASE_FILE_STUB)
        roles.append(f"{w}/roles")
    with open(f"{w}/inventory/hosts", "w") as f:
        f.write("[taps]\ntap-a ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n")
    with open(f"{w}/inventory/host_vars/tap-a.yml", "w") as f:
        json.dump(host_vars, f)
    v: dict = {"target": "taps", "release_file_component": "goatrope", "release_file_ledger": "goatrope"}
    if rel:
        v |= {"release_file_ref": f"example-org/goatrope@goatrope-v1@sha256:{'0' * 64}",
              "release_file_files": {"amd64": rel, "arm64": rel}}  # one archive serves both
    if rollback:
        v["release_file_rollback"] = True
    with open(f"{w}/vars.json", "w") as f:
        json.dump(v, f)
    return subprocess.run(["ansible-playbook", "-i", f"{w}/inventory", f"{SRC}/deploy/ansible/goatrope-deploy.yml",
                           "-e", f"@{w}/vars.json", *extra], capture_output=True, text=True,
                          env=dict(os.environ, ANSIBLE_ROLES_PATH=":".join(roles), ANSIBLE_NOCOLOR="1", LC_ALL="C.UTF-8"))


def recap(p: subprocess.CompletedProcess) -> str:
    return next((" ".join(ln.split()[2:]) for ln in p.stdout.splitlines() if ln.startswith("tap-a ") and "ok=" in ln), "no recap")


def phase_deploy() -> None:
    """The deploy play, from a release file, as a driver runs it (Ansible in this container, against itself)."""
    topo_listen()
    stand_in_watchdog()
    given = [f for f in sorted(os.listdir("/opt/gt-dist")) if f.endswith(".tar.gz")] if os.path.isdir("/opt/gt-dist") else []
    real = describe(f"/opt/gt-dist/{given[0]}") if given else None
    r1 = real or make_release("0.1.0")
    r2 = make_release("0.1.1")
    v1 = r1["name"].removeprefix("goatrope-").removesuffix(".tar.gz")
    print(f"# archive: {'built by tools/build-release.sh' if real else 'built by the test'}; release-file role: "
          f"{'the real one' if os.path.isdir('/opt/gt-roles') else 'a stand-in'}", flush=True)
    tap = {"mode": "listen", "source": "mirror-port", "ports": ["tp0", "tp1"], "management": MGMT}
    rec = {"ports": ["tp0", "tp1"], "filter": "", "file_mb": 5, "files": 4}
    good = {"tap": tap, "goatrope_record": rec}
    before = snapshot()

    def link(n="current"):
        return os.readlink(f"{GT_HOME}/{n}") if os.path.islink(f"{GT_HOME}/{n}") else None

    def ledger():
        t = ""
        for f in ("/var/log/gt-ledger", "/var/lib/goat/goatrope/deploy-history.jsonl"):
            t += open(f).read() if os.path.exists(f) else ""
        return t

    def refused(name, hv, text, rel=None, rollback=False):
        pre = (snapshot(), link(), ledger())
        p = play(hv, rel, rollback)
        post = (snapshot(), link(), ledger())
        d = diff(pre[0], post[0])
        d = [x for x in d if "/var/lib/goatrope/record/" not in x]  # a running recorder's ring
        left = [x for x in os.listdir("/run") if x.startswith("goatrope-deploy")]
        result(p.returncode != 0 and text in p.stdout + p.stderr and not d and pre[1:] == post[1:] and not left,
               f"deploy refused: {name}; the machine, `current` and the ledger are as they were",
               f"exit {p.returncode}; {'' if text in p.stdout + p.stderr else (p.stdout + p.stderr)[-500:]}; {d[:3]} {left}")

    refused("no release installed and none given", good, "release is not installed here")
    refused("no tap declaration", {"goatrope_record": rec}, "there is no default", r1)
    refused("no recording declaration", {"tap": tap}, "there is no default", r1)
    refused("an unknown tap key", {"tap": tap | {"speed": 1}, "goatrope_record": rec}, "there is no default", r1)
    refused("no mode", {"tap": {k: v for k, v in tap.items() if k != "mode"}, "goatrope_record": rec}, "goatrope: refused", r1)
    refused("listen without a source", {"tap": {k: v for k, v in tap.items() if k != "source"}, "goatrope_record": rec}, "goatrope: refused", r1)
    refused("inline with one port", {"tap": {"mode": "inline", "ports": ["tp0"], "management": MGMT}, "goatrope_record": rec}, "goatrope: refused", r1)
    refused("management is a port", {"tap": tap | {"ports": ["tp0", MGMT]}, "goatrope_record": rec}, "goatrope: refused", r1)
    refused("a port that does not exist", {"tap": tap | {"ports": ["tp0", "tp9"]}, "goatrope_record": rec | {"ports": ["tp0"]}}, "no interface tp9", r1)
    refused("TOML in a value", {"tap": tap, "goatrope_record": rec | {"filter": 'x"\nfiles = 9\n#'}}, "goatrope: refused", r1)
    refused("more TOML that declares the tap again", good | {"goatrope_extra_toml": "[tap]\nmode = 'inline'"}, "refused", r1)
    sh("ip addr add 198.51.100.9/24 dev tp0")
    refused("a port with an address", good, "has address(es) 198.51.100.9/24", r1)
    sh("ip addr del 198.51.100.9/24 dev tp0")
    refused("an archive that is not the verified one", good, "nothing changed", r1 | {"sha256": "0" * 64})

    c0, c1 = Capture("feed", "f0", "dep-f0"), Capture("feed", "f1", "dep-f1")
    p = play(good, r1)
    result(p.returncode == 0 and "changed=0" not in recap(p), "deploy: listen, installed from the release file",
           f"{recap(p)} {'' if p.returncode == 0 else (p.stdout + p.stderr)[-900:]}")
    result((link() or "").endswith(f"/{r1['sha256']}/{r1['name']}") and ledger() != "", "deploy: `current` names the archive", str(link()))
    def installed_check(name):
        q = subprocess.run(["goatrope", "check"], capture_output=True, text=True)
        result(q.returncode == 0, name, f"exit {q.returncode} {[x for x in q.stdout.splitlines() if 'DIFF' in x]} {q.stderr[-200:]}")
    installed_check("deploy: goatrope check exits 0")
    f0, f1 = c0.stop(), c1.stop()
    result(not f0 and not f1, "deploy: nothing sent toward the feed while it installed", f"{len(f0)} + {len(f1)} frames")

    def pids():
        return sh("systemctl show -p MainPID --value goatrope-record@tp0 goatrope-record@tp1").stdout.split()
    p0, files0 = pids(), {k: v for k, v in snapshot()["files"].items() if "/record/" not in k and "deploy-history" not in k}
    p = play(good, None)
    result(p.returncode == 0 and "changed=0" in recap(p) and pids() == p0, "deploy: a second run changes nothing and restarts no recorder", recap(p))
    q = play(good, r1)
    files1 = {k: v for k, v in snapshot()["files"].items() if "/record/" not in k and "deploy-history" not in k}
    result(q.returncode == 0 and pids() == p0 and files1 == files0,
           "deploy: the same release again restarts no recorder and changes no file of the tap", recap(q))
    sh("tc qdisc del dev tp0 clsact")
    p = play(good, None)
    result(p.returncode == 0 and "changed=1" in recap(p), "deploy: a removed egress drop is repaired", recap(p))
    installed_check("deploy: check exits 0 after the repair")
    pre = snapshot()
    p = play({"tap": tap, "goatrope_record": rec | {"files": 5}}, None, False, "--check", "-v")
    d = [x for x in diff(pre, snapshot()) if "/record/" not in x]
    result(p.returncode == 0 and "would-change" in p.stdout and not d, "deploy: check mode says it would change, and changes nothing", f"{recap(p)} {d}")
    p = play({"tap": tap, "goatrope_record": rec | {"files": 5}}, None)
    result(p.returncode == 0 and "files = 5" in open("/etc/goatrope/goatrope.toml").read()
           and "files = 4" in open("/etc/goatrope/goatrope.toml.prev").read(), "deploy: a changed declaration is applied, the one before kept", recap(p))
    p = play(good, r2)
    have = sh("goatrope --version").stdout.strip()
    result(p.returncode == 0 and have.endswith("0.1.1"), "deploy: a newer release replaces the software", f"{have}; {recap(p)}")
    sh("ip addr add 198.51.100.9/24 dev tp1")
    refused("rollback while a port is in use", good, "has address(es)", None, True)
    sh("ip addr del 198.51.100.9/24 dev tp1")
    p = play(good, None, True)
    have = sh("goatrope --version").stdout.strip()
    result(p.returncode == 0 and have.endswith(v1) and r1["sha256"] in (link() or ""), "deploy: rollback installs the release before", f"{have}; {recap(p)}")
    installed_check("deploy: check exits 0 after the rollback")
    cur = link() or ""
    with open(cur, "ab") as f:
        f.write(b"x")
    refused("an installed archive changed on the machine", good, "nothing changed")
    sh(f"cp {r1['src']} {cur}")
    p = gr("uninstall", "--purge")
    # the driver's ledger and release files are its own
    d = [x for x in diff(before, snapshot()) if "/var/lib/goat:" not in x and "/var/lib/goat/" not in x]
    result(p.returncode == 0 and not d, "deploy: uninstall --purge leaves nothing of the tap", str(d[:4]))

    topo_inline()
    inline = {"tap": {"mode": "inline", "ports": ["tp0", "tp1"], "management": MGMT}, "goatrope_record": rec | {"ports": ["tp0"]}}
    p = play(inline, None)
    result(p.returncode == 0, "deploy: inline, from the installed file", f"{recap(p)} {'' if p.returncode == 0 else (p.stdout + p.stderr)[-600:]}")
    installed_check("deploy: inline check exits 0")
    pg = subprocess.Popen(["ip", "netns", "exec", "a", "ping", "-i", "0.05", "-c", "400", "-q", "192.0.2.2"], stdout=subprocess.PIPE, text=True)
    time.sleep(1)
    p = play(inline, None)
    out = pg.communicate(timeout=60)[0]
    result(p.returncode == 0 and "changed=0" in recap(p) and " 0% packet loss" in out,
           "deploy: a second inline run loses no ping through the bridge", f"{recap(p)}; {out.splitlines()[-2] if out else ''}")
    sh("ip addr add 198.51.100.9/24 dev goatrope0")
    refused("inline, the bridge has an address", inline, "has address(es)")
    sh("ip addr del 198.51.100.9/24 dev goatrope0")
    p = gr("uninstall", "--purge")
    result(p.returncode == 0 and not os.path.exists("/sys/class/net/goatrope0"), "deploy: inline uninstall")


PHASES["deploy"] = phase_deploy



ERSPAN = """schema = 1
[tap]
mode = "listen"
source = "erspan"
ports = ["grspan0"]
management = "eth0"
[tap.erspan]
underlay = "er0"
local = "203.0.113.10"
remote = "203.0.113.1"
session_id = 100
version = 1
[tap.record]
ports = ["grspan0"]
filter = ""
file_mb = 5
files = 4

[[send]]
name = "span"
port = "grspan0"
match = { protocol = "udp", dst_port = 9300 }
to = ["udp://127.0.0.1:9301"]
"""


def topo_erspan() -> None:
    """A switch in its own namespace mirrors a link to this machine over ERSPAN: one session the
    declaration names (key 100) and one it does not (key 200)."""
    sh("ip netns del sw", check=False)
    sh("ip link del er0", check=False)
    sh("ip netns add sw && ip -n sw link set lo up")
    # Fixed addresses: udev's MACAddressPolicy=persistent rewrites a randomly addressed veth after it
    # is up, and the switch then sends the GRE frames to the old address, where they are dropped.
    sh("ip link add er0 address 02:00:00:00:e7:01 type veth peer name sw1 address 02:00:00:00:e7:02"
       " && ip link set sw1 netns sw")
    sh("ip addr add 203.0.113.10/24 dev er0 && ip link set er0 up")
    sh("ip -n sw addr add 203.0.113.1/24 dev sw1 && ip -n sw link set sw1 up")
    for name, key in (("span100", 100), ("span200", 200)):
        sh(f"ip -n sw link add {name} type erspan seq key {key} local 203.0.113.1 remote 203.0.113.10 erspan_ver 1 erspan 7")
        sh(f"ip -n sw link set {name} up")


def mirror_udp(ifname: str, n: int, tag: bytes, dport: int) -> None:
    """Ethernet frames carrying UDP datagrams, sent into the switch's ERSPAN interface, as a mirror copies them."""
    code = ("import socket,struct\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\n"
            f"s.bind(({ifname!r},0))\n"
            "def ck(h):\n s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);return (~(s+(s>>16)))&0xffff\n"
            f"for i in range({n}):\n"
            f" pl={MAGIC!r}+{tag!r}+i.to_bytes(4,'big')+b'm'*30\n"
            f" u=struct.pack('!HHHH',40000,{dport},8+len(pl),0)+pl\n"
            " h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),i,0,64,17,0,bytes([192,0,2,10]),bytes([192,0,2,20]))\n"
            " h=h[:10]+struct.pack('!H',ck(h))+h[12:]\n"
            " s.send(b'\\x02\\x00\\x00\\x00\\x00\\x20'+b'\\x02\\x00\\x00\\x00\\x00\\x10'+b'\\x08\\x00'+h+u)\n")
    sh(f"ip netns exec sw python3 -c \"{code}\"")


def phase_erspan() -> None:
    topo_erspan()
    before = snapshot()
    stand_in_watchdog()
    p = gr("validate", "--config", write_cfg(ERSPAN.replace("session_id = 100", "session_id = 2000")))
    result(p.returncode == 2 and "session_id must be a whole number from 0 to 1023" in p.stderr, "erspan: a session ID over 1023 is refused", p.stderr.strip()[-120:])
    p = gr("validate", "--config", write_cfg(ERSPAN.replace('local = "203.0.113.10"', 'local = "2001:db8::10"')))
    result(p.returncode == 2 and "IPv6 is not built" in p.stderr, "erspan: an IPv6 underlay is refused", p.stderr.strip()[-120:])
    p = gr("validate", "--config", write_cfg(ERSPAN.replace('source = "erspan"', 'source = "mirror-port"')))
    result(p.returncode == 2 and "applies only with source" in p.stderr, "erspan: [tap.erspan] without source = \"erspan\" is refused", p.stderr.strip()[-120:])
    p = gr("install", "--config", write_cfg(ERSPAN.replace('local = "203.0.113.10"', 'local = "203.0.113.11"')))
    result(p.returncode == 2 and "does not hold 203.0.113.11" in p.stderr and not diff(before, snapshot()),
           "erspan: install refused, changing nothing, when the underlay does not hold the declared address", p.stderr.strip()[-160:])

    write_cfg(ERSPAN)
    up = Capture("sw", "sw1", "erspan-back")  # anything this machine sends toward the switch
    rx = subprocess.Popen([sys.executable, "-c", """
import socket, json, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 9301)); s.settimeout(0.5)
got = set(); end = time.time() + 600  # an emulated arm64 install alone can take a minute
while time.time() < end and len(got) < 50:
    try:
        d = s.recv(65535)
    except socket.timeout:
        continue
    if d.startswith(b"GTROPEOK"):
        got.add(int.from_bytes(d[8:12], "big"))
print(json.dumps(sorted(got)))
"""], stdout=subprocess.PIPE, text=True)
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "erspan: install", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-600:]}")
    kind = sh("ip -d link show grspan0", check=False).stdout
    result("erspan" in kind and "key 100" in kind.replace("ikey 0.0.0.100", "key 100").replace("ikey 100", "key 100"),
           "erspan: the decapsulating interface exists, keyed by the session ID", " ".join(kind.split())[:200])
    check_exit(0, "erspan after install")
    p = gr("status", "--config", CFG)
    result("session 100" in p.stdout and "egress-drop=yes" in p.stdout, "erspan: status names the session and the egress drop",
           next((ln for ln in p.stdout.splitlines() if "erspan" in ln), ""))
    wait_packet_sockets("grspan0", 2)  # the recorder and the send service, before the mirror starts
    mirror_udp("span100", 50, b"OK", 9300)
    mirror_udp("span200", 20, b"NO", 9300)
    got = json.loads(rx.communicate(timeout=660)[0] or "[]")
    result(got == list(range(50)), "erspan: [[send]] got every datagram of the declared session", f"{len(got)} of 50")
    # The switch restarts its session: its sequence numbers start at 0 again.
    sh("ip -n sw link del span100")
    sh("ip -n sw link add span100 type erspan seq key 100 local 203.0.113.1 remote 203.0.113.10 erspan_ver 1 erspan 7")
    sh("ip -n sw link set span100 up")
    mirror_udp("span100", 20, b"RS", 9300)
    time.sleep(3)  # stopping a recorder loses what tcpdump has not yet written (hardware.md, known limits)
    flush_recorders(["grspan0"])
    frames = ring_frames("grspan0")
    start_recorders(["grspan0"])
    result(tagged(frames, b"OK") == set(range(50)), "erspan: every mirrored frame of session 100 recorded, decapsulated",
           f"{len(tagged(frames, b'OK'))} of 50 ({len(frames)} frames in the ring)")
    result(not tagged(frames, b"NO"), "erspan: no frame of another session recorded", f"{len(tagged(frames, b'NO'))} of 20")
    result(tagged(frames, b"RS") == set(range(20)), "erspan: every frame recorded after the sender restarted its session",
           f"{len(tagged(frames, b'RS'))} of 20; sequence flags {' '.join(w for w in sh('ip -d link show grspan0').stdout.split() if w in ('iseq', 'oseq'))}")
    back = [f for f in up.stop() if len(f) > 23 and f[12:14] == b"\x08\x00" and f[23] == 47]
    result(not back, "erspan: nothing sent back toward the switch in GRE", f"{len(back)} GRE frames")
    sh("ip link del grspan0")
    check_exit(3, "erspan: the decapsulating interface removed")
    p = gr("install", "--config", CFG)
    check_exit(0, "erspan: install again restores it")
    p = gr("uninstall", "--purge")
    d = diff(before, snapshot())
    result(p.returncode == 0 and not d and not os.path.exists("/sys/class/net/grspan0"),
           "erspan: uninstall --purge removes the interface and leaves nothing", "; ".join(d)[:400])
    sh("ip netns del sw", check=False)
    sh("ip link del er0", check=False)


PHASES["erspan"] = phase_erspan


# ---------------------------------------------------------------- bench: data-path ceilings (docs/performance.md)

BENCH_SECONDS = float(os.environ.get("GOATROPE_BENCH_SECONDS", "2"))
BENCH_STEPS = int(os.environ.get("GOATROPE_BENCH_STEPS", "6"))
BENCHGEN = os.path.join(SRC, "tests", "netns", "benchgen.py")


def host_line() -> str:
    cpu = next((ln.split(":", 1)[1].strip() for ln in open("/proc/cpuinfo") if ln.startswith("model name")), "unknown")
    load = open("/proc/loadavg").read().split()[0]
    return f"{cpu}, {os.cpu_count()} threads, kernel {os.uname().release}, load {load}"


def bench(name: str, detail: str, values: dict) -> None:
    """A measurement: printed and recorded, never a pass or a failure."""
    line = f"bench - {name}  [{detail}]"
    print(line, flush=True)
    RESULTS.append({"result": "bench", "name": name, "detail": detail, "values": values, "host": host_line()})


def ns_prefix(ns: str) -> list[str]:
    return ["ip", "netns", "exec", ns] if ns else []


def udp_drops(ns: str) -> int:
    """RcvbufErrors of the namespace's UDP: datagrams a socket's full buffer dropped."""
    lines = [ln.split() for ln in sh(" ".join(ns_prefix(ns) + ["cat", "/proc/net/snmp"])).stdout.splitlines() if ln.startswith("Udp:")]
    return int(dict(zip(lines[0][1:], lines[1][1:])).get("RcvbufErrors", 0))


def gen(ns: str, *args) -> dict:
    p = subprocess.run(ns_prefix(ns) + [sys.executable, "-I", BENCHGEN] + [str(a) for a in args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"benchgen {args[0]}: {p.stderr.strip()[-300:]}")
    return json.loads(p.stdout.strip().splitlines()[-1])


class Sink:
    def __init__(self, ns: str, bind: str, port: int, seconds: float, run: int):
        self.p = subprocess.Popen(ns_prefix(ns) + [sys.executable, "-I", BENCHGEN, "udp-sink", bind, str(port), str(seconds), str(run)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = self.p.stdout.readline()
        if "ready" not in ready:
            raise RuntimeError(f"udp-sink did not start: {self.p.stderr.read()[-300:]}")

    def result(self) -> dict:
        out, err = self.p.communicate(timeout=120)
        if self.p.returncode != 0:
            raise RuntimeError(f"udp-sink: {err.strip()[-300:]}")
        return json.loads(out.strip().splitlines()[-1])


RUN = [0]


def next_run() -> int:
    RUN[0] += 1
    return RUN[0]


def ceiling(trial, threshold: float) -> dict:
    """The highest offered rate whose loss is at most `threshold`: one unpaced trial, then a binary search
    between 0 and the unpaced rate. trial(rate) returns a dict with sent, received and offered_per_s."""
    top = trial(0)
    top["loss"] = 1 - top["received"] / max(1, top["sent"])
    if top["loss"] <= threshold:
        return {"rate": top["offered_per_s"], "loss": top["loss"], "unpaced": top, "trials": 1, "generator_bound": True}
    lo, hi, best, trials = 0.0, float(top["offered_per_s"]), None, 1
    for _ in range(BENCH_STEPS):
        mid = (lo + hi) / 2
        t = trial(mid)
        trials += 1
        t["loss"] = 1 - t["received"] / max(1, t["sent"])
        if t["loss"] <= threshold:
            lo, best = mid, t
        else:
            hi = mid
    return {"rate": best["offered_per_s"] if best else 0, "loss": best["loss"] if best else None, "unpaced": top,
            "trials": trials, "generator_bound": False}


def fmt(n) -> str:
    return f"{int(round(n)):,}"


def bench_relay_udp() -> None:
    topo_relay()
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 net.ipv6.conf.all.forwarding=0")
    # Fragments of a datagram the overloaded tunnel half-dropped hold reassembly memory for ipfrag_time (30 s by
    # default), and every later fragmented datagram is then dropped; 2 s keeps one trial from spoiling the next.
    sh("sysctl -qw net.ipv4.ipfrag_time=2")
    sh("ip netns exec remote sysctl -qw net.ipv4.ipfrag_time=2")
    write_cfg(RELAY)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(2)
    D = BENCH_SECONDS

    def trial_path(path: str, size: int):
        def trial(rate: float) -> dict:
            run = next_run()
            if path == "wireguard":  # the generator and WireGuard alone: a socket on the relay machine, no relay
                sink = Sink("", "10.99.0.1", 7100, D, run)
                port = 7100
            else:
                sink = Sink("linkhost", "192.0.2.2", 7002, D, run)
                port = 7002
            d0 = udp_drops("")
            s = gen("remote", "udp-send", "10.99.0.2", "10.99.0.1", port, size, rate, D, run, "wga")
            r = sink.result()
            time.sleep(0.5)
            return s | {"received": r["received"], "p50_us": r["p50_us"], "p99_us": r["p99_us"],
                        "relay_socket_drops": udp_drops("") - d0}
        return trial

    for size in (64, 512, 1400):
        base = ceiling(trial_path("wireguard", size), 0.001)
        rel = ceiling(trial_path("relay", size), 0.001)
        lat_b = trial_path("wireguard", size)(10000)
        lat_r = trial_path("relay", size)(10000)
        add50 = round(lat_r["p50_us"] - lat_b["p50_us"], 1) if lat_r["p50_us"] is not None and lat_b["p50_us"] is not None else None
        add99 = round(lat_r["p99_us"] - lat_b["p99_us"], 1) if lat_r["p99_us"] is not None and lat_b["p99_us"] is not None else None
        un = rel["unpaced"]
        frag = ", two fragments in the tunnel (WireGuard MTU 1,420)" if size + 28 > 1420 else ""
        bench(f"relay UDP {size}-byte payload{frag}: {fmt(rel['rate'])} datagrams/s with loss under 0.1 %",
              f"unpaced: {fmt(un['offered_per_s'])} offered, {fmt(un['received'] / max(un['seconds'], 1e-9))} delivered/s, "
              f"{fmt(un['relay_socket_drops'])} dropped at the relay's socket; WireGuard alone (no relay) "
              f"{fmt(base['rate'])}/s{' (generator-bound)' if base['generator_bound'] else ''}; "
              f"latency at 10,000/s: relay path p50 {lat_r['p50_us']} us p99 {lat_r['p99_us']} us, WireGuard alone "
              f"p50 {lat_b['p50_us']} us p99 {lat_b['p99_us']} us, added p50 {add50} us p99 {add99} us; "
              f"{rel['trials']} trials of {D:g} s; {host_line()}",
              {"path": "relay-udp", "size": size, "rate": rel["rate"], "loss": rel["loss"], "unpaced": un,
               "wireguard_alone_rate": base["rate"], "wireguard_alone_generator_bound": base["generator_bound"],
               "latency_relay": [lat_r["p50_us"], lat_r["p99_us"]], "latency_wireguard": [lat_b["p50_us"], lat_b["p99_us"]],
               "added_p50_us": add50, "added_p99_us": add99, "trial_seconds": D})
    bench_relay_tc(trial_path)
    relay.terminate()
    relay.wait(timeout=10)


def bench_mirror() -> None:
    """tc mirred from a port to an ERSPAN type II interface over WireGuard, as ADR 0004 module 5 sets it up; the
    collector is an ERSPAN interface at the far end of the tunnel, and its receive counter is the count."""
    topo_listen()
    sh("ip link del grbm1", check=False)
    sh("ip link add grbm1 mtu 9000 type erspan seq key 1 local 10.99.0.1 remote 10.99.0.2 erspan_ver 1 erspan 1 nopmtudisc ignore-df")
    sh("sysctl -qw net.ipv6.conf.grbm1.disable_ipv6=1 && ip link set grbm1 arp off && ip link set grbm1 up")
    sh("ip -n remote link add grbc1 mtu 9000 type erspan seq key 1 local 10.99.0.2 remote 10.99.0.1 erspan_ver 1 erspan 1")
    sh("ip netns exec remote sysctl -qw net.ipv6.conf.grbc1.disable_ipv6=1")
    sh("ip -n remote link set grbc1 arp off && ip -n remote link set grbc1 up")
    sh("ip link set tp0 up && sysctl -qw net.ipv6.conf.tp0.disable_ipv6=1")
    sh("tc qdisc add dev tp0 clsact")
    sh("tc filter add dev tp0 ingress pref 1001 handle 1 matchall action mirred egress mirror dev grbm1")
    D = BENCH_SECONDS

    def rx() -> int:
        return int(sh("ip netns exec remote cat /sys/class/net/grbc1/statistics/rx_packets").stdout)

    def trial_size(size: int):
        def trial(rate: float) -> dict:
            before = rx()
            s = gen("feed", "raw-send", "f0", size, rate, D, next_run(), 5000)
            time.sleep(1.5)
            return s | {"received": rx() - before}
        return trial

    for size in (64, 512, 1514):
        c = ceiling(trial_size(size), 0.0)
        un = c["unpaced"]
        frag = ", outer packet in two fragments" if size + 46 > 1420 else ""
        bench(f"remote mirror {size}-byte frames{frag}: {fmt(c['rate'])} frames/s with 0 lost at the collector",
              f"unpaced: {fmt(un['offered_per_s'])} offered, {fmt(un['received'])} of {fmt(un['sent'])} arrived; "
              f"{c['trials']} trials of {D:g} s{'; generator-bound' if c['generator_bound'] else ''}; {host_line()}",
              {"path": "mirror", "size": size, "rate": c["rate"], "unpaced": un, "generator_bound": c["generator_bound"],
               "trial_seconds": D})
    sh("tc qdisc del dev tp0 clsact", check=False)
    sh("ip link del grbm1", check=False)


class SinkArgs(Sink):
    def __init__(self, ns: str, bind: str, port: int, seconds: float, run: int, idle: float, deadline: float):
        self.p = subprocess.Popen(ns_prefix(ns) + [sys.executable, "-I", BENCHGEN, "udp-sink", bind, str(port), str(seconds),
                                                   str(run), str(idle), str(deadline)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "ready" not in self.p.stdout.readline():
            raise RuntimeError(f"udp-sink did not start: {self.p.stderr.read()[-300:]}")


def converted_rate(r: dict) -> float:
    """Messages per second between the first and the last that arrived."""
    return (r["received"] - 1) / r["span_s"] if r["received"] > 1 and r["span_s"] > 0 else 0.0


def bench_converter(label: str, option: str, conv: str, which: str) -> None:
    """One [[send]] with this convert line on a listen tap: frames into the tap port, converted messages counted at UDP."""
    topo_listen()
    write_cfg(LISTEN + f"""
[[send]]
name = "bench"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
{conv}
to = ["udp://127.0.0.1:9201"]
""")
    stand_in_watchdog()
    p = gr("install", "--config", CFG)
    if p.returncode != 0:
        bench(f"decode-and-send, {label}: not measured", f"install exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}", {})
        return
    for _ in range(30):
        if sh("systemctl is-active goatrope-send@bench.service", check=False).stdout.strip() == "active":
            break
        time.sleep(1)
    time.sleep(2)
    D = max(BENCH_SECONDS * 4, 10.0)

    def trial(rate: float) -> dict:
        sh("systemctl restart goatrope-send@bench.service")  # an empty socket buffer for each trial
        time.sleep(1.5)
        sink = SinkArgs("", "127.0.0.1", 9201, D, 0, 6, D + 8)
        s = gen("feed", "raw-send", "f0", 0, rate, D, next_run(), 5000, REMOTE_ID)
        r = sink.result()
        return s | {"received": r["received"], "span_s": r["span_s"]}

    over = trial(0)
    conv_rate = converted_rate(over)
    try:
        hb = json.load(open("/var/lib/goatrope/send/bench.health"))
    except (OSError, ValueError):
        hb = {}
    cv, ld = hb.get("convert", {}), hb.get("load", {})
    check = trial(conv_rate * 0.9) if conv_rate >= 5 else None
    gr("uninstall", "--config", CFG)
    at90 = (f"at 90 % of that rate, {fmt(check['received'])} of {fmt(check['sent'])} arrived" if check
            else "too slow for a second trial at 90 %")
    bench(f"decode-and-send, {label}: {conv_rate:,.1f} messages/s converted and sent",
          f"converter: {which}; {fmt(over['offered_per_s'])}/s offered for {D:g} s, {fmt(over['received'])} converted "
          f"in {over['span_s']:g} s; {at90}; {host_line()}",
          {"path": "send-convert", "option": option, "converter": which, "rate": round(conv_rate, 2), "unpaced": over,
           "at_90_percent": check, "trial_seconds": D})
    if cv:
        bench(f"decode-and-send, {label}: one conversion p50 {cv.get('p50_us')} us, p99 {cv.get('p99_us')} us, max {cv.get('max_us')} us",
              f"{fmt(cv.get('count', 0))} conversions in the last trial, timed in the send process (p50, p99 over the last 16,384); "
              f"packs loaded once at start: {ld.get('files')} files in {ld.get('seconds')} s, resident {ld.get('rss_kib')} KiB, "
              f"peak {ld.get('peak_rss_kib')} KiB; {host_line()}",
              {"path": "send-convert-latency", "option": option, "convert": cv, "load": ld})


def bench_send_convert() -> None:
    """The converter: the engine linked into goatrope; goat-xf-pipe beside it when GOATROPE_TEST_COMPONENTS gives it."""
    epacks = engine_packs()
    if epacks:
        sh(f"chmod -R go+rX {os.path.dirname(epacks)}")
        version, digest = packs_digest(epacks)
        bench_converter("the engine linked into goatrope", "linked",
                        f'convert = {{ component = "goat-transformers", version = "{version}", from = "remote-id", to = "cot-xml", '
                        f'packs = "{epacks}", packs_sha256 = "{digest}" }}', f"goat-transformers {version}, linked, packs {epacks}")
    else:
        bench("decode-and-send, the engine linked into goatrope: not measured", "no packs (see engine_packs)", {})
    pipe = f"{COMPONENTS}/goat-xf-pipe"
    if epacks and os.path.exists(pipe):
        bench_pipe(pipe, epacks, max(BENCH_SECONDS * 4, 10.0))


def bench_pipe(pipe: str, packs: str, D: float) -> None:
    """goat-xf-pipe, one long-lived process, converting what arrives on UDP: the engine's rate with no per-message start."""
    proc = subprocess.Popen([pipe, "--packs", packs, "--packs-only", "--from-format", "remote-id", "--in", "udp://127.0.0.1:9210",
                             "--out", "udp://127.0.0.1:9211", "--to-format", "cot-xml", "--status-every", "3600"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    loaded = time.monotonic()
    for _ in range(600):  # until it has loaded its packs and bound the port
        if ":9210" in sh("ss -Huan", check=False).stdout:
            break
        time.sleep(0.1)
    load_s = time.monotonic() - loaded

    def trial(rate: float) -> dict:
        run = next_run()
        sink = SinkArgs("", "127.0.0.1", 9211, D / 4, 0, 1, D / 4 + 8)
        s = gen("", "udp-send", "127.0.0.1", "127.0.0.1", 9210, 0, rate, D / 4, run, "", REMOTE_ID)
        r = sink.result()
        return s | {"received": r["received"], "span_s": r["span_s"]}

    c = ceiling(trial, 0.001)
    proc.terminate()
    proc.wait(timeout=10)
    bench(f"goat-xf-pipe, one long-lived process: {fmt(c['rate'])} messages/s converted with loss under 0.1 %",
          f"remote-id to cot-xml over UDP on the loopback, outside goatrope; start-up and pack load {load_s:.1f} s; "
          f"unpaced {fmt(c['unpaced']['offered_per_s'])} offered, {fmt(c['unpaced']['received'])} of {fmt(c['unpaced']['sent'])} converted; "
          f"{c['trials']} trials of {D / 4:g} s; {host_line()}",
          {"path": "send-convert", "option": "goat-xf-pipe", "rate": c["rate"], "unpaced": c["unpaced"], "load_s": round(load_s, 2),
           "trial_seconds": D / 4})


def phase_bench() -> None:
    """Data-path ceilings: relay UDP over real WireGuard, the remote mirror, decode-and-send with a converter."""
    print(f"# bench host: {host_line()}; {BENCH_SECONDS:g} s trials, {BENCH_STEPS} search steps", flush=True)
    bench_relay_udp()
    bench_mirror()
    bench_send_convert()


PHASES["bench"] = phase_bench


# ---------------------------------------------------------------- address proxy (ADR 0004 module 4)

PROXY_IP = "192.0.2.60"
PROXY_RULES = f"""
  {{ direction = "link-to-remote", protocol = "udp", remote = "10.99.0.2", listen_port = 7100, remote_port = 7100, sources = ["192.0.2.2"], link_address = "{PROXY_IP}" }},
  {{ direction = "remote-to-link", protocol = "tcp", remote = "10.99.0.2", listen_port = 7200, target = "192.0.2.2", target_port = 7200, link_address = "{PROXY_IP}" }},
  {{ direction = "link-to-remote", protocol = "tcp", remote = "10.99.0.2", listen_port = 7300, remote_port = 7300, sources = ["192.0.2.2"], link_address = "{PROXY_IP}" }},
]"""
PROXY = RELAY.replace("target_port = 7000 }", f'target_port = 7000, link_address = "{PROXY_IP}" }}') \
    .replace("target_port = 7002 }", f'target_port = 7002, link_address = "{PROXY_IP}" }}') \
    .replace("\n]", PROXY_RULES, 1) + f"""
[[relay.proxy]]
address = "{PROXY_IP}"
remote = "10.99.0.2"
"""

# A remote machine sends n datagrams to the relay's port through its tunnel and counts the replies.
PROXY_SENDER = """
import socket, sys
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

# The link host: every datagram it receives on 7000 and 7002, with its source, one JSON line each;
# it answers on 7000.
PROXY_RX = """
import socket, json, select, sys
out = open(sys.argv[1], "a")
socks = {}
for p in (7000, 7002):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.2", p)); socks[s] = p
while True:
    for s in select.select(list(socks), [], [], 1)[0]:
        d, a = s.recvfrom(65535)
        out.write(json.dumps([socks[s], d.decode(errors="replace"), a[0]]) + "\\n"); out.flush()
        if socks[s] == 7000: s.sendto(b"reply-" + d, a)
"""


# Clients and servers for the TCP and link-to-remote rules, run in a namespace:
#   serve-remote: on 10.99.0.2 (the remote), echo UDP 7100 and TCP 7300
#   serve-link: on 192.0.2.2 (the target), echo TCP 7200 and log each peer address
#   udp <dst> <port> <n> <tag>: n datagrams, count echoed replies from dst:port
#   tcp <dst> <port> <n> <tag> [bind dev]: n connections, count echoes
#   hold <dst> <port> <out>: one connection, held open; writes the seconds until it was closed
PROXY_TOOL = """
import json, select, socket, sys, threading, time
mode = sys.argv[1]
def echo_tcp(addr, port, log=None):
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind((addr, port)); l.listen(64)
    def one(c, a):
        if log:
            with open(log, "a") as f: f.write(json.dumps([port, "tcp", a[0]]) + "\\n")
        try:
            while True:
                d = c.recv(65535)
                if not d: break
                c.sendall(d)
        except OSError: pass
        c.close()
    while True:
        c, a = l.accept(); threading.Thread(target=one, args=(c, a), daemon=True).start()
if mode == "serve-remote":
    threading.Thread(target=echo_tcp, args=("10.99.0.2", 7300), daemon=True).start()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("10.99.0.2", 7100))
    while True:
        d, a = u.recvfrom(65535); u.sendto(d, a)
elif mode == "serve-link":
    echo_tcp("192.0.2.2", 7200, sys.argv[2])
elif mode == "udp":
    dst, port, n, tag = sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.2", 0)); s.settimeout(0.5)
    got = 0
    for i in range(n):
        s.sendto(f"{tag}{i}".encode(), (dst, port))
        try:
            d, a = s.recvfrom(65535)
            got += d == f"{tag}{i}".encode() and a == (dst, port)
        except socket.timeout: pass
    print(got)
elif mode == "tcp":
    dst, port, n, tag = sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    got = 0
    for i in range(n):
        try:
            s = socket.socket()
            if len(sys.argv) > 7:
                s.setsockopt(socket.SOL_SOCKET, 25, sys.argv[7].encode()); s.bind((sys.argv[6], 0))
            s.settimeout(3); s.connect((dst, port)); m = f"{tag}{i}".encode(); s.sendall(m)
            got += s.recv(65535) == m
            s.close()
        except OSError: pass
    print(got)
elif mode == "hold":
    s = socket.socket(); s.settimeout(5); s.connect((sys.argv[2], int(sys.argv[3]))); s.sendall(b"hold"); s.recv(100)
    s.settimeout(250); t0 = time.time()
    try:
        s.recv(100)
    except OSError: pass
    open(sys.argv[4], "w").write(str(time.time() - t0))
"""


def proxy_tool(ns: str, *args: str, bg: bool = False):
    path = f"{WORK}/proxy_tool.py"
    if not os.path.exists(path):
        open(path, "w").write(PROXY_TOOL)
    argv = ["ip", "netns", "exec", ns, sys.executable, "-I", path, *args]
    if bg:
        return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    return int((p.stdout.strip() or "0").splitlines()[-1])


def proxy_held() -> bool:
    return f"inet {PROXY_IP}/32" in sh("ip -o -4 addr show dev r0", check=False).stdout


FWD_SAMPLES: list[bool] = []


def forwarding_off() -> bool:
    """IPv4 forwards per receiving interface; IPv6 on the global setting (what the relay's preflight reads)."""
    vals = [sh(f"sysctl -n {k}", check=False).stdout.strip() for k in
            ("net.ipv4.conf.r0.forwarding", "net.ipv4.conf.wg0.forwarding", "net.ipv6.conf.all.forwarding")]
    ok = all(v == "0" for v in vals)
    FWD_SAMPLES.append(ok)
    return ok


def wait_for(cond, timeout: float, step: float = 0.5) -> float | None:
    """Seconds until cond() held, sampling forwarding at each step; None on timeout."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        forwarding_off()
        if cond():
            return time.monotonic() - t0
        time.sleep(step)
    return None


def link_arps(frames: list[bytes], mac: bytes) -> dict:
    """ARP frames r0 sent on the link: probes (sender 0.0.0.0) and announcements (sender = target) for the proxy address."""
    ip = socket.inet_aton(PROXY_IP)
    n = {"probes": 0, "announcements": 0, "replies": 0}
    for f in frames:
        if f[12:14] != b"\x08\x06" or f[6:12] != mac:
            continue
        a = f[14:42]
        op, spa, tpa = a[6:8], a[14:18], a[24:28]
        if op == b"\x00\x01" and spa == b"\0\0\0\0" and tpa == ip:
            n["probes"] += 1
        elif op == b"\x00\x01" and spa == ip and tpa == ip:
            n["announcements"] += 1
        elif op == b"\x00\x02" and spa == ip:
            n["replies"] += 1
    return n


ARPING_LAST: list[str] = [""]


def arping(n: int) -> tuple[int, set[str]]:
    """n ARP requests for the proxy address from the link host: how many answered, and from which MACs."""
    p = sh(f"ip netns exec linkhost arping -I l0 -c {n} -w {n + 3} {PROXY_IP}", check=False)
    ARPING_LAST[0] = f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-200:]}"
    got = 0
    for ln in p.stdout.splitlines():
        if ln.startswith("Received"):
            got = int(ln.split()[1])
    found = {w.strip("[]").lower() for ln in p.stdout.splitlines() if "reply from" in ln for w in ln.split() if w.startswith("[")}
    return got, found


def proxy_health() -> dict:
    try:
        h = json.load(open("/var/lib/goatrope/relay.health"))
    except (OSError, ValueError):
        return {}
    row = next((x for x in h.get("proxies", []) if x["address"] == PROXY_IP), {})
    row["rules"] = {r["listen_port"]: r for r in h.get("rules", [])}
    return row


def phase_proxy() -> None:
    """ADR 0004 module 4: a remote machine appears on the link under a proxy address of its own."""
    for leftover in ("wg0", "u0", "r0", "grb0"):
        sh(f"ip link del {leftover}", check=False)
    topo_relay()
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1 net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 "
       "net.ipv6.conf.all.forwarding=0")
    tap_pub = subprocess.run(["wg", "pubkey"], input=open(f"{WORK}/tap.key").read(), capture_output=True, text=True).stdout.strip()
    allowed_pub = subprocess.run(["wg", "pubkey"], input=open(f"{WORK}/allowed.key").read(), capture_output=True,
                                 text=True).stdout.strip()
    # the remote keeps its tunnel up, as a mesh peer with a persistent keepalive does
    sh(f"ip netns exec remote wg set wga peer {tap_pub} persistent-keepalive 5")
    r0_mac = open("/sys/class/net/r0/address").read().strip()
    mac = bytes.fromhex(r0_mac.replace(":", ""))

    # refusals in the declaration
    bad = {
        "an IPv6 proxy address": (PROXY.replace(f'address = "{PROXY_IP}"', 'address = "2001:db8::60"'), "a proxy address is IPv4"),
        "a proxy no rule uses": (RELAY + f'[[relay.proxy]]\naddress = "{PROXY_IP}"\nremote = "10.99.0.2"\n', "no rule uses it"),
        "a proxy for a remote no rule names": (PROXY.replace('remote = "10.99.0.2"\n', 'remote = "10.99.0.3"\n'), "is the remote of no rule"),
        "a proxy address off the link": (PROXY.replace(PROXY_IP, "203.0.113.60"), "is not on the link"),
    }
    for what, (text, msg) in bad.items():
        write_cfg(text)
        p = gr("validate", "--config", CFG)
        result(p.returncode == 2 and msg in p.stderr, f"proxy refused: {what}", p.stderr.strip()[-140:])
    write_cfg(PROXY)
    sh(f"ip addr add {PROXY_IP}/24 dev r0")
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "remove it" in p.stderr, "proxy refused: the operator put the address on the link interface",
           p.stderr.strip()[-160:])
    sh(f"ip addr del {PROXY_IP}/24 dev r0")

    rx_log = f"{WORK}/proxy-rx.jsonl"
    open(rx_log, "w").close()
    rx = subprocess.Popen(["ip", "netns", "exec", "linkhost", sys.executable, "-c", PROXY_RX, rx_log])
    if os.path.exists(f"{WORK}/proxy_tool.py"):
        os.remove(f"{WORK}/proxy_tool.py")
    servers = [proxy_tool("remote", "serve-remote", bg=True), proxy_tool("linkhost", "serve-link", rx_log, bg=True)]
    time.sleep(1)

    def received(tag: str) -> list:
        return [x for x in (json.loads(ln) for ln in open(rx_log)) if x[1].startswith(tag)]

    def send(port: int, n: int, tag: str) -> int:
        out = sh(f"ip netns exec remote python3 -c '{PROXY_SENDER}' 10.99.0.2 {port} {n} {tag} wga", check=False).stdout.strip()
        time.sleep(0.5)
        return int(out or 0)

    # 1. another machine on the link holds the address: the relay probes, finds it, and does not take it
    sh(f"ip -n linkhost addr add {PROXY_IP}/24 dev l0")
    cap = Capture("linkhost", "l0", "proxy-conflict")
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    absent = 0
    for _ in range(28):  # 14 s: a first probe round, a conflict, the 10 s wait, a second round
        forwarding_off()
        absent += not proxy_held()
        time.sleep(0.5)
    send(7000, 5, "elsewhere")
    tcp_away = proxy_tool("remote", "tcp", "10.99.0.1", "7200", "3", "away", "10.99.0.2", "wga")
    time.sleep(2.5)
    h = proxy_health()
    frames = cap.stop()
    arps = link_arps(frames, mac)
    result(absent == 28 and h.get("held") is False and h.get("conflicts", 0) >= 1 and "another machine" in h.get("why", ""),
           "proxy: not taken while another machine on the link holds the address",
           f"absent {absent} of 28 samples, conflicts {h.get('conflicts')}, why: {h.get('why', '')[:90]}")
    # the holder answers the first probe of each round, which ends that round (RFC 5227 §2.1.1)
    result(arps["probes"] >= 2 and arps["announcements"] == 0,
           "proxy: a probe from 0.0.0.0 in each of two rounds 10 s apart, each answered by the holder, and no announcement",
           f"{arps['probes']} probes, {arps['announcements']} announcements, conflicts {h.get('conflicts')}")
    errs = h.get("rules", {}).get(7000, {}).get("send_errors", 0)
    result(not received("elsewhere") and errs == 5, "proxy: while the address is not held, datagrams for its rule are send errors",
           f"{len(received('elsewhere'))} reached the link, send_errors {errs} of 5")
    terr = h.get("rules", {}).get(7200, {}).get("send_errors", 0)
    result(tcp_away == 0 and terr == 3 and not received("away"),
           "proxy: while the address is not held, a TCP connection for its rule is not made toward the link (send errors)",
           f"{tcp_away} of 3 echoed, send_errors {terr} of 3")

    # 2. the other machine lets it go: probed, taken, announced
    cap = Capture("linkhost", "l0", "proxy-take")
    sh(f"ip -n linkhost addr del {PROXY_IP}/24 dev l0 && ip -n linkhost neigh flush dev l0")
    took = wait_for(proxy_held, 30)
    time.sleep(4.5)  # the second announcement comes 2 s after the first
    arps = link_arps(cap.stop(), mac)
    result(took is not None and "noprefixroute" in sh("ip -o -4 addr show dev r0", check=False).stdout,
           "proxy: taken once no other machine holds it, as a /32 with noprefixroute",
           f"after {took if took is None else round(took, 1)} s: {sh('ip -o -4 addr show dev r0', check=False).stdout.strip()[-120:]}")
    result(arps["probes"] >= 3 and arps["announcements"] == 2,
           "proxy: probed (3) before it was taken, and announced (2) after",
           f"{arps['probes']} probes, {arps['announcements']} announcements")
    routes = [ln for ln in sh("ip -4 route show table all", check=False).stdout.splitlines()
              if not ln.startswith(("local ", "broadcast "))]
    bad_routes = [ln for ln in routes if ln.startswith(PROXY_IP) or PROXY_IP + " " in ln or ("10.99." in ln and "dev r0" in ln)]
    result(not bad_routes, "proxy: no route for the proxy address and none to the remote through the link (local table aside)",
           "; ".join(bad_routes) or f"{len(routes)} routes")
    cap = Capture("linkhost", "l0", "proxy-arping")
    got, macs_seen = arping(10)
    wire = link_arps(cap.stop(), mac)["replies"]
    result(got == 10 and macs_seen == {r0_mac} and wire >= 10, "proxy: answers ARP from the link while the peer handshakes",
           f"{got} of 10, from {sorted(macs_seen)} (r0 is {r0_mac}); {wire} replies from r0 on the wire"
           + ("" if got == 10 else f"; arping {ARPING_LAST[0]}; neigh {sh('ip -n linkhost neigh', check=False).stdout.strip()[:120]}"))

    # 3. traffic: the target sees the remote at the proxy address, and its replies to that address reach the remote
    rep = send(7000, 20, "via")
    time.sleep(1)
    via = received("via")
    result(len(via) == 20 and all(src == PROXY_IP for _, _, src in via),
           "proxy: a remote's datagrams reach the link from the proxy address", f"{len(via)} of 20 from {sorted({x[2] for x in via})}")
    result(rep == 20, "proxy: the target's replies to the proxy address reach the remote", f"{rep} of 20")
    send(7002, 5, "oneway")
    ow = received("oneway")
    result(len(ow) == 5 and all(src == PROXY_IP for _, _, src in ow), "proxy: a one-way rule also sends from the proxy address",
           f"{len(ow)} of 5")
    n = proxy_tool("linkhost", "udp", PROXY_IP, "7100", "20", "l2r")
    result(n == 20, "proxy: datagrams a link machine sends to <proxy address>:7100 reach the remote, and its replies come from the proxy address",
           f"{n} of 20")
    n = proxy_tool("remote", "tcp", "10.99.0.1", "7200", "10", "tcpin", "10.99.0.2", "wga")
    peers = [x for x in (json.loads(ln) for ln in open(rx_log)) if x[0] == 7200 and x[1] == "tcp"]
    result(n == 10 and len(peers) >= 10 and all(p[2] == PROXY_IP for p in peers),
           "proxy: a TCP rule from the remote connects to the target from the proxy address",
           f"{n} of 10 echoed; target saw {sorted({p[2] for p in peers})}")
    n = proxy_tool("linkhost", "tcp", PROXY_IP, "7300", "10", "tcpout")
    result(n == 10, "proxy: a link machine's TCP connection to <proxy address>:7300 reaches the remote", f"{n} of 10 echoed")
    # another machine claims the address while it is held (an ARP announcement from its MAC): the relay
    # gives it up at once (RFC 5227 §2.4 (a)), closes the TCP connection on it, and probes again 10 s later
    hold_out = f"{WORK}/proxy-hold.txt"
    if os.path.exists(hold_out):
        os.remove(hold_out)
    holder = proxy_tool("linkhost", "hold", PROXY_IP, "7300", hold_out, bg=True)
    time.sleep(1.5)
    c0 = proxy_health().get("conflicts", 0)
    l0_mac = bytes.fromhex(sh("ip -n linkhost -o link show l0").stdout.split("link/ether ")[1].split()[0].replace(":", ""))
    claim = (b"\xff" * 6 + l0_mac + b"\x08\x06" + bytes([0, 1, 8, 0, 6, 4, 0, 1]) + l0_mac + socket.inet_aton(PROXY_IP)
             + b"\0" * 6 + socket.inet_aton(PROXY_IP))
    sh(f"ip netns exec linkhost python3 -c \"import socket;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);"
       f"s.bind(('l0',0));s.send(bytes.fromhex('{claim.hex()}'))\"")
    gave_up = wait_for(lambda: not proxy_held(), 5, 0.1)
    try:
        holder.wait(timeout=5)
        closed = True
    except subprocess.TimeoutExpired:
        holder.kill()
        closed = False
    time.sleep(2.5)
    h = proxy_health()
    result(gave_up is not None and closed and h.get("conflicts", 0) == c0 + 1 and "holds" in h.get("why", ""),
           "proxy: another machine claiming the address while it is held: given up at once, its open TCP connection closed",
           f"removed after {gave_up if gave_up is None else round(gave_up, 1)} s, connection closed {closed}, conflicts {c0} -> "
           f"{h.get('conflicts')}")
    back = wait_for(proxy_held, 25)
    result(back is not None, "proxy: no machine answers the next probe round, so it is taken back",
           f"after {back if back is None else round(back, 1)} s")
    sh(f"ip -n linkhost route add 10.99.0.0/24 via {PROXY_IP}")
    ping = sh("ip netns exec linkhost ping -c 5 -i 0.3 -W 1 10.99.0.2", check=False).stdout
    rcvd = next((ln.split(",")[1].split()[0] for ln in ping.splitlines() if "packets transmitted" in ln), "?")
    result(rcvd == "0", "proxy: the kernel does not route to the remote through the proxy address", f"{rcvd} of 5 pings answered")
    sh(f"ip -n linkhost route del 10.99.0.0/24 via {PROXY_IP}")

    # 4. the peer stops handshaking: the address is removed within 180 s of its latest handshake (+ one 2 s tick)
    def last_hs() -> int:
        for ln in sh("wg show wg0 latest-handshakes", check=False).stdout.splitlines():
            k, t = ln.split()
            if k == allowed_pub:
                return int(t)
        return 0
    hold_out = f"{WORK}/proxy-hold.txt"
    if os.path.exists(hold_out):
        os.remove(hold_out)
    holder = proxy_tool("linkhost", "hold", PROXY_IP, "7300", hold_out, bg=True)
    time.sleep(1.5)
    sh("ip -n remote link set wga down")
    t_stop = time.time()
    hs = last_hs()
    held_for = wait_for(lambda: not proxy_held(), 200)
    t_rm = time.time()
    after_hs = t_rm - hs
    result(held_for is not None and after_hs <= 180 + 2 + 1.5 and after_hs >= 178,
           "proxy: removed within 180 s of the peer's latest handshake (+ one 2 s tick), and held until then",
           f"handshake {t_stop - hs:.0f} s before the stop; removed {held_for if held_for is None else round(held_for)} s after the stop, "
           f"{after_hs:.1f} s after the handshake")
    time.sleep(2.5)
    h = proxy_health()
    try:
        holder.wait(timeout=10)
        closed_after = float(open(hold_out).read())
    except (subprocess.TimeoutExpired, OSError, ValueError):
        holder.kill()
        closed_after = None
    result(closed_after is not None and closed_after <= (held_for or 0) + 3,
           "proxy: an open TCP connection on the proxy address is closed no later than the address is given up (3 s margin)",
           f"closed {closed_after if closed_after is None else round(closed_after)} s after it was opened; address removed "
           f"{held_for if held_for is None else round(held_for)} s after the stop")
    got, _ = arping(3)
    result(got == 0 and h.get("held") is False and "latest handshake" in h.get("why", "") and h.get("removed", 0) >= 1,
           "proxy: once removed, no ARP answer, and the health file says why", f"{got} of 3 answered; why: {h.get('why', '')[:100]}")

    # 5. the peer comes back: probed again, re-added, and the rule's socket binds again
    cap = Capture("linkhost", "l0", "proxy-back")
    sh("ip -n remote link set wga up && ip -n remote route replace 10.99.0.1/32 dev wga metric 1")
    send(7002, 3, "wake")
    back = wait_for(proxy_held, 40)
    time.sleep(4.5)
    arps = link_arps(cap.stop(), mac)
    via2 = send(7000, 20, "again")
    time.sleep(1)
    again = received("again")
    result(back is not None and arps["probes"] >= 3 and arps["announcements"] == 2,
           "proxy: when the handshake is fresh again it probes again, then takes the address back",
           f"after {back if back is None else round(back, 1)} s; {arps['probes']} probes, {arps['announcements']} announcements")
    result(len(again) == 20 and via2 == 20 and all(src == PROXY_IP for _, _, src in again),
           "proxy: after it is taken back, traffic flows from it again",
           f"{len(again)} of 20 to the link, {via2} of 20 replies")
    n1 = proxy_tool("linkhost", "udp", PROXY_IP, "7100", "10", "back")
    n2 = proxy_tool("linkhost", "tcp", PROXY_IP, "7300", "5", "backtcp")
    result(n1 == 10 and n2 == 5, "proxy: after it is taken back, the link-to-remote UDP and TCP rules on it work again",
           f"UDP {n1} of 10, TCP {n2} of 5")

    # 6. a relay that was killed leaves the address; the next run removes it and probes before taking it again
    relay.kill()
    relay.wait(timeout=10)
    left = proxy_held()
    os.remove("/var/lib/goatrope/relay.health")  # the killed run's counters; the new run writes its own
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    retaken = wait_for(lambda: proxy_held() and proxy_health().get("added", 0) >= 1 and proxy_health().get("probes", 0) >= 3, 30, 0.2)
    result(left and retaken is not None, "proxy: an address a killed relay left is removed at the next start and taken again after a probe",
           f"left after kill: {left}; held again after {retaken if retaken is None else round(retaken, 1)} s")
    relay.terminate()
    try:
        rc = relay.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay.kill()
        rc = None
    out = relay.stdout.read()
    result(rc == 0 and not proxy_held() and "earlier run" in out, "proxy: SIGTERM: the relay removes the address and exits 0",
           f"exit {rc}, held {proxy_held()}")

    # 7. as a service: systemd stop removes it; check and status report it
    for f in ("/var/lib/goatrope/relay.health", "/var/lib/goatrope/relay.health.new"):
        if os.path.exists(f):
            os.remove(f)  # left by the foreground runs above
    before = snapshot()
    p = gr("install", "--config", CFG)
    unit = open("/etc/systemd/system/goatrope-relay.service").read() if os.path.exists("/etc/systemd/system/goatrope-relay.service") else ""
    u = wait_unit("active")
    svc = wait_for(proxy_held, 20)
    time.sleep(2.5)
    result(p.returncode == 0 and u.get("ActiveState") == "active" and svc is not None and "AF_PACKET" in unit,
           "proxy: the service (AF_PACKET allowed in its unit) takes the address",
           f"install {p.returncode}, {u.get('ActiveState')}, held after {svc}")
    j = check_exit(0, "proxy service: held", "--json") or {}
    row = next((i for i in j.get("items", []) if i.get("id") == f"relay-proxy-{PROXY_IP}"), {})
    result(row.get("ok") is True and "held" in str(row.get("have")), "proxy: check reports the address held and on r0", str(row)[:200])
    st = gr("status", "--config", CFG).stdout
    result(f"proxy  {PROXY_IP}" in st and "held (handshake" in st, "proxy: status shows it",
           " | ".join(ln for ln in st.splitlines() if "proxy" in ln)[:200])
    n = send(7000, 10, "svc")
    result(n == 10, "proxy: the service relays through the proxy address", f"{n} of 10 replies")
    sh("systemctl stop goatrope-relay.service")
    gone = wait_for(lambda: not proxy_held(), 5, 0.2)
    result(gone is not None, "proxy: systemctl stop removes the address", f"after {gone} s")
    gr("uninstall", "--purge")
    left = diff(before, snapshot())
    result(not left and not proxy_held(), "proxy: uninstall --purge leaves nothing", "; ".join(left)[:300])
    rx.kill()
    for srv in servers:
        srv.kill()
    forwarding_off()
    result(bool(FWD_SAMPLES) and all(FWD_SAMPLES), "proxy: IP forwarding stayed off throughout (r0 and wg0 IPv4, IPv6 all)",
           f"{sum(FWD_SAMPLES)} of {len(FWD_SAMPLES)} samples off")


PHASES["proxy"] = phase_proxy

TC_OBJ = os.path.join(SRC, "tests", "netns", "build", "relay_tc.o")  # run.sh compiles relay_tc.c when clang is there


def bench_relay_tc(trial_path) -> None:
    """The prototype of ADR 0006: the same rule (port 7002) rewritten and redirected by a tc program on wg0."""
    if not os.path.exists(TC_OBJ):
        bench("relay UDP in a tc program: not measured", "no clang on the machine that ran run.sh, so relay_tc.o was not built", {})
        return
    ifindex = int(open("/sys/class/net/r0/ifindex").read())
    obj = open(TC_OBJ, "rb").read()
    placeholder = (0x7E1F1D00).to_bytes(4, "little")
    if obj.count(placeholder) != 1:
        bench("relay UDP in a tc program: not measured", "relay_tc.o does not hold the interface placeholder once", {})
        return
    path = f"{WORK}/relay_tc.o"
    with open(path, "wb") as f:
        f.write(obj.replace(placeholder, ifindex.to_bytes(4, "little")))
    sh("tc qdisc add dev wg0 clsact")
    p = sh(f"tc filter add dev wg0 ingress pref 1 bpf direct-action obj {path} sec tc", check=False)
    if p.returncode != 0:
        bench("relay UDP in a tc program: not measured", f"tc refused the program: {(p.stdout + p.stderr).strip()[-300:]}", {})
        sh("tc qdisc del dev wg0 clsact", check=False)
        return
    D = BENCH_SECONDS
    for size in (64, 512):
        c = ceiling(trial_path("relay", size), 0.001)
        lat_b = trial_path("wireguard", size)(10000)
        lat_t = trial_path("relay", size)(10000)
        add50 = round(lat_t["p50_us"] - lat_b["p50_us"], 1) if lat_t["p50_us"] is not None and lat_b["p50_us"] is not None else None
        add99 = round(lat_t["p99_us"] - lat_b["p99_us"], 1) if lat_t["p99_us"] is not None and lat_b["p99_us"] is not None else None
        un = c["unpaced"]
        bench(f"relay UDP {size}-byte payload in a tc program (prototype): {fmt(c['rate'])} datagrams/s with loss under 0.1 %",
              f"unpaced: {fmt(un['offered_per_s'])} offered, {fmt(un['received'] / max(un['seconds'], 1e-9))} delivered/s; "
              f"latency at 10,000/s: p50 {lat_t['p50_us']} us p99 {lat_t['p99_us']} us, WireGuard alone p50 {lat_b['p50_us']} us "
              f"p99 {lat_b['p99_us']} us, added p50 {add50} us p99 {add99} us; {c['trials']} trials of {D:g} s; {host_line()}",
              {"path": "relay-udp-tc", "size": size, "rate": c["rate"], "loss": c["loss"], "unpaced": un,
               "latency": [lat_t["p50_us"], lat_t["p99_us"]], "latency_wireguard": [lat_b["p50_us"], lat_b["p99_us"]],
               "added_p50_us": add50, "added_p99_us": add99, "trial_seconds": D})
    sh("tc qdisc del dev wg0 clsact", check=False)


# ---------------------------------------------------------------- the linked engine (docs/adr/0006-data-path.md)

ENGINE_PACKS = "/opt/gt-engine/packs"  # run.sh copies the pinned goat-transformers commit's packs and model here


def engine_packs() -> str | None:
    for p in (f"{COMPONENTS}/packs", ENGINE_PACKS):
        if os.path.exists(f"{p}/remote-id/pack.def") and os.path.exists(f"{p}/cot-xml/pack.def"):
            return p
    return None


def packs_digest(packs: str) -> tuple[str, str]:
    p = gr("packs-digest", packs, "remote-id", "cot-xml")
    vals = dict(ln.split(" = ", 1) for ln in p.stdout.splitlines() if " = " in ln)
    return vals["version"].strip('"'), vals["packs_sha256"].strip('"')


def phase_linked_engine() -> None:
    """A [[send]] converted by the engine linked into goatrope: packs pinned by digest, loaded once."""
    packs = engine_packs()
    if not packs:
        result(None, "linked-engine: not run (no packs: run.sh copies them from the pinned goat-transformers checkout)")
        return
    sh(f"chmod -R go+rX {os.path.dirname(packs)}")
    version, digest = packs_digest(packs)
    conv = (f'convert = {{ component = "goat-transformers", version = "{version}", from = "remote-id", to = "cot-xml", '
            f'packs = "{packs}", packs_sha256 = "{digest}" }}')
    topo_listen()
    cfg = LISTEN + f"""
[[send]]
name = "linked"
port = "tp0"
match = {{ protocol = "udp", dst_port = 5000 }}
{conv}
to = ["udp://127.0.0.1:9220"]
"""
    write_cfg(cfg.replace(f'version = "{version}"', 'version = "0.0.1"'))
    p = gr("validate", "--config", CFG)
    result(p.returncode == 2 and "linked into this goatrope" in p.stderr, "linked-engine: a version other than the linked engine's is refused",
           p.stderr.strip()[-160:])
    write_cfg(cfg.replace(f'packs_sha256 = "{digest}"', f'binary = "/usr/local/bin/goat-xf", sha256 = "{digest}"'))
    p = gr("validate", "--config", CFG)
    result(p.returncode == 2 and "not a goat-xf binary" in p.stderr, "linked-engine: a convert naming a goat-xf binary is refused",
           p.stderr.strip()[-200:])
    write_cfg(cfg)
    stand_in_watchdog()
    rx = subprocess.Popen([sys.executable, "-c", """
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 9220)); s.settimeout(20)
got = []
try:
    while len(got) < 50: got.append(s.recv(65535).decode(errors="replace"))
except socket.timeout: pass
print(json.dumps(got))
"""], stdout=subprocess.PIPE, text=True)
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "linked-engine: install with a linked-engine convert", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}")
    for _ in range(30):
        if "loaded" in sh("journalctl -u goatrope-send@linked.service --no-pager", check=False).stdout:
            break
        time.sleep(0.5)
    started = sh("journalctl -u goatrope-send@linked.service --no-pager", check=False).stdout
    line = next((ln for ln in started.splitlines() if "loaded" in ln), "")
    result("loaded" in line, "linked-engine: the send process loaded the packs once at start", line.split(": ", 1)[-1][-160:])
    gen("feed", "raw-send", "f0", 0, 200, 0.25, 1, 5000, REMOTE_ID)
    got = json.loads(rx.communicate(timeout=60)[0])
    result(len(got) == 50 and all(g.startswith("<event") for g in got),
           "linked-engine: 50 of 50 Remote ID messages converted to Cursor-on-Target XML and sent", f"{len(got)} of 50; {got[0][:80] if got else ''}")
    # one conversion's time, apart from throughput: 10,000 messages at 2,000 a second, timed by the send process
    gen("feed", "raw-send", "f0", 0, 2000, 5, 2, 5000, REMOTE_ID)
    time.sleep(5)
    hb = json.load(open("/var/lib/goatrope/send/linked.health"))
    cv, ld = hb.get("convert", {}), hb.get("load", {})
    detail = (f"{cv.get('count')} conversions; p50 {cv.get('p50_us')} us, p99 {cv.get('p99_us')} us, max {cv.get('max_us')} us "
              f"(p50 and p99 over the last 16,384)")
    if os.uname().machine == "x86_64":
        result(cv.get("count", 0) >= 10050 and cv.get("p99_us", 1e9) <= 1000,
               "linked-engine: a Remote ID to Cursor-on-Target conversion takes 1 ms or less at p99, over 10,000 messages", detail)
    else:
        result(None, "linked-engine: conversion time, over 10,000 messages (the 1 ms assertion is made on amd64)", detail)
    result(None, "linked-engine: the one-time load of the named packs at start",
           f"{ld.get('files')} files in {ld.get('seconds')} s; resident {ld.get('rss_kib')} KiB after it, peak {ld.get('peak_rss_kib')} KiB")
    check_exit(0, "linked-engine: check after install (packs digest, heartbeat)")
    pack = f"{packs}/cot-xml/pack.def"
    orig = open(pack, "rb").read()
    with open(pack, "ab") as f:
        f.write(b"\n# changed\n")
    check_exit(3, "linked-engine: a pack that no longer matches packs_sha256")
    sh("systemctl restart goatrope-send@linked.service", check=False)
    time.sleep(3)
    jl = sh("journalctl -u goatrope-send@linked.service --no-pager -n 5", check=False).stdout
    result("not the declared packs_sha256" in jl, "linked-engine: a changed pack is refused at start", jl.strip().splitlines()[-1][-160:] if jl.strip() else "")
    with open(pack, "wb") as f:
        f.write(orig)
    gr("uninstall", "--config", CFG)


PHASES["linked-engine"] = phase_linked_engine


# ---------------------------------------------------------------- fragments (docs/adr/0006-data-path.md)

def phase_fragments() -> None:
    """A datagram larger than the tunnel MTU crosses it as fragments. An overload of them fills reassembly memory and
    loses fragmented traffic until it times out (ipfrag_time); unfragmented traffic keeps flowing, and the relay
    reports the failures in relay.health. The same for the remote mirror's full-size frames."""
    for dev in ("r0", "u0", "wg0", "tp0", "tp1", "grbm1"):
        sh(f"ip link del {dev}", check=False)
    topo_relay()
    sh("sysctl -qw net.ipv6.conf.r0.disable_ipv6=1")
    sh("sysctl -qw net.ipv4.conf.r0.forwarding=0 net.ipv4.conf.wg0.forwarding=0 net.ipv6.conf.all.forwarding=0")
    frag_time = int(open("/proc/sys/net/ipv4/ipfrag_time").read())
    write_cfg(RELAY)
    relay = subprocess.Popen(GR + ["relay", "--config", CFG], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(2)

    def through(size: int, n: int, rate: float) -> int:
        run = next_run()
        sink = SinkArgs("linkhost", "192.0.2.2", 7002, n / rate, run, 1, n / rate + 5)
        gen("remote", "udp-send", "10.99.0.2", "10.99.0.1", 7002, size, rate, n / rate, run, "wga")
        return sink.result()["received"]

    ok1400 = through(1400, 100, 200)
    result(ok1400 == 100, "fragments: a 1,400-byte datagram (two fragments in the 1,420-byte tunnel) is relayed", f"{ok1400} of 100")
    over = gen("remote", "udp-send", "10.99.0.2", "10.99.0.1", 7002, 1400, 0, 2, next_run(), "wga")
    time.sleep(1)  # the tunnel's queues drain; reassembly memory stays full for ipfrag_time
    small = through(64, 200, 1000)
    stalled = through(1400, 100, 200)
    result(small == 200, "fragments: right after an overload of fragmented datagrams, unfragmented ones are all relayed",
           f"{small} of 200; overload {fmt(over['sent'])} datagrams in 2 s")
    result(None, "fragments: fragmented datagrams sent right after the overload (reassembly memory full)", f"{stalled} of 100 relayed")
    time.sleep(frag_time + 3)
    health = json.load(open(HEALTH_FILE))
    ra = health.get("reassembly", {})
    result(ra.get("failed", 0) + ra.get("timed_out", 0) > 0, "fragments: relay.health counts the reassembly failures since the relay started",
           json.dumps(ra))
    after = through(1400, 100, 200)
    result(after == 100, f"fragments: {frag_time + 3} s later (ipfrag_time {frag_time} s), fragmented datagrams are relayed again", f"{after} of 100")
    relay.terminate()
    relay.wait(timeout=10)

    # the remote mirror, built as ADR 0004 module 5 builds it, over the same tunnel
    topo_listen()
    sh("ip link add grbm1 mtu 9000 type erspan seq key 1 local 10.99.0.1 remote 10.99.0.2 erspan_ver 1 erspan 1 nopmtudisc ignore-df")
    sh("sysctl -qw net.ipv6.conf.grbm1.disable_ipv6=1 && ip link set grbm1 arp off && ip link set grbm1 up")
    sh("ip -n remote link del grbc1", check=False)
    sh("ip -n remote link add grbc1 mtu 9000 type erspan seq key 1 local 10.99.0.2 remote 10.99.0.1 erspan_ver 1 erspan 1")
    sh("ip netns exec remote sysctl -qw net.ipv6.conf.grbc1.disable_ipv6=1")
    sh("ip -n remote link set grbc1 arp off && ip -n remote link set grbc1 up")
    sh("ip link set tp0 up && sysctl -qw net.ipv6.conf.tp0.disable_ipv6=1")
    sh("tc qdisc add dev tp0 clsact")
    sh("tc filter add dev tp0 ingress pref 1001 handle 1 matchall action mirred egress mirror dev grbm1")

    def mirrored(size: int, n: int, rate: float) -> int:
        before = int(sh("ip netns exec remote cat /sys/class/net/grbc1/statistics/rx_packets").stdout)
        gen("feed", "raw-send", "f0", size, rate, n / rate, next_run(), 5000)
        time.sleep(1)
        return int(sh("ip netns exec remote cat /sys/class/net/grbc1/statistics/rx_packets").stdout) - before

    full = mirrored(1514, 100, 200)
    result(full == 100, "fragments: a 1,514-byte frame is mirrored whole (the outer packet in two fragments)", f"{full} of 100")
    gen("feed", "raw-send", "f0", 1514, 0, 2, next_run(), 5000)
    time.sleep(1)  # the tunnel's queues drain; reassembly memory stays full for ipfrag_time
    small = mirrored(64, 200, 1000)
    stalled = mirrored(1514, 100, 200)
    result(small == 200, "fragments: right after an overload of full-size frames, small frames are all mirrored", f"{small} of 200")
    result(None, "fragments: full-size frames mirrored right after the overload (the collector's reassembly memory full)",
           f"{stalled} of 100 arrived")
    rft = int(sh("ip netns exec remote cat /proc/sys/net/ipv4/ipfrag_time").stdout)
    time.sleep(rft + 3)
    again = mirrored(1514, 100, 200)
    result(again == 100, f"fragments: {rft + 3} s later, full-size frames are mirrored again", f"{again} of 100")
    sh("tc qdisc del dev tp0 clsact", check=False)
    sh("ip link del grbm1", check=False)


HEALTH_FILE = "/var/lib/goatrope/relay.health"
PHASES["fragments"] = phase_fragments


# ---------------------------------------------------------------- layer-2 lane (ADR 0004 module 6)

MAC_A, MAC_B = "02:00:00:00:a0:01", "02:00:00:00:b0:01"
L2_A = """schema = 1
[relay]
remote_interface = "wgl0"
link_interface = "l2d0"
link_address = "198.51.100.129/25"
allow = [{ direction = "remote-to-link", protocol = "udp", remote = "203.0.113.2", listen_port = 7100, target = "198.51.100.130", target_port = 7100 }]
[[relay.l2]]
name = "lane0"
port = "lp0"
peer = "203.0.113.2"
local = "203.0.113.1"
key = 4242
accept_layer2 = true
ethertypes = ["0x0806", "0x0800", "0x88b5"]
macs = ["02:00:00:00:b0:01"]
"""
L2_B = (L2_A.replace('"wgl0"', '"wgl1"').replace('"l2d0"', '"l2d1"').replace('remote = "203.0.113.2"', 'remote = "203.0.113.1"')
        .replace('peer = "203.0.113.2"', 'peer = "203.0.113.9"').replace('local = "203.0.113.1"', 'local = "203.0.113.2"')
        .replace('peer = "203.0.113.9"', 'peer = "203.0.113.1"').replace('"lp0"', '"lp1"').replace(MAC_B, MAC_A))
CFG_B = f"{WORK}/goatrope-b.toml"


def topo_l2() -> None:
    """Two lane ends joined by WireGuard over an underlay veth: this machine (end A, the installed relay)
    and namespace endB (a relay in the foreground). Each end's port leads to its own link host.

      hostA [ha0 192.0.2.1] == lp0 ]-l2b-lane0-[ l2g-lane0 ~ wgl0 203.0.113.1 == underlay ==
          == wgl1 203.0.113.2 (ns endB) ~ l2g-lane0 ]-l2b-lane0-[ lp1 == [hb0 192.0.2.2] hostB
    """
    for ns in ("hostA", "hostB", "endB"):
        sh(f"ip netns del {ns}", check=False)
    for leftover in ("wg0", "u0", "r0", "grb0", "bp0", "er0", "l2u0", "wgl0", "lp0", "l2d0", "l2g-lane0", "l2b-lane0"):
        sh(f"ip link del {leftover}", check=False)
    for ns in ("hostA", "hostB", "endB"):
        sh(f"ip netns add {ns} && ip -n {ns} link set lo up")
    for ns in ("hostA", "hostB"):  # the link hosts send no IPv6, so the counters below count only what the test sends
        sh(f"ip netns exec {ns} sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
    sh("ip link add l2u0 address 02:00:00:00:e1:01 type veth peer name l2u1 address 02:00:00:00:e1:02 && ip link set l2u1 netns endB")
    sh("ip addr add 198.51.100.1/30 dev l2u0 && ip link set l2u0 up")
    sh("ip -n endB addr add 198.51.100.2/30 dev l2u1 && ip -n endB link set l2u1 up")
    keys = {}
    for k in ("l2a", "l2b"):
        priv = sh("wg genkey").stdout.strip()
        keys[k] = (priv, subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip())
    sh("ip link add wgl0 type wireguard")
    subprocess.run(["wg", "set", "wgl0", "listen-port", "51830", "private-key", "/dev/stdin", "peer", keys["l2b"][1],
                    "endpoint", "198.51.100.2:51831", "allowed-ips", "203.0.113.2/32", "persistent-keepalive", "5"],
                   input=keys["l2a"][0] + "\n", text=True, check=True)
    # NetBird's default WireGuard MTU: a GRETAP made on it starts below IPv6's minimum MTU
    sh("ip addr add 203.0.113.1/24 dev wgl0 && ip link set wgl0 mtu 1280 up")
    sh("ip -n endB link add wgl1 type wireguard")
    subprocess.run(["ip", "netns", "exec", "endB", "wg", "set", "wgl1", "listen-port", "51831", "private-key", "/dev/stdin",
                    "peer", keys["l2a"][1], "endpoint", "198.51.100.1:51830", "allowed-ips", "203.0.113.1/32",
                    "persistent-keepalive", "5"], input=keys["l2b"][0] + "\n", text=True, check=True)
    sh("ip -n endB addr add 203.0.113.2/24 dev wgl1 && ip -n endB link set wgl1 mtu 1280 up")
    for pre, port, peer, ns, mac, addr in (("", "lp0", "ha0", "hostA", MAC_A, "192.0.2.1"),
                                           ("ip netns exec endB ", "lp1", "hb0", "hostB", MAC_B, "192.0.2.2")):
        end = "endB" if pre else None
        sh(f"ip link add {port} address 02:00:00:00:{'a' if port == 'lp0' else 'b'}0:fe type veth peer name {peer} address {mac}")
        sh(f"ip link set {peer} netns {ns}")
        if end:
            sh(f"ip link set {port} netns {end}")
        sh(f"ip -n {ns} addr add {addr}/24 dev {peer} && ip -n {ns} link set {peer} up")
        sh(f"{pre}ip link set {port} up")  # IPv6 stays on for the port here: the first start must refuse
        dummy = "l2d0" if not end else "l2d1"
        sh(f"{pre}ip link add {dummy} type dummy && {pre}ip addr add 198.51.100.129/25 dev {dummy}")
        sh(f"{pre}sysctl -qw net.ipv6.conf.{dummy}.disable_ipv6=1 net.ipv4.conf.all.forwarding=0 net.ipv6.conf.all.forwarding=0")
        sh(f"{pre}ip link set {dummy} up")


def l2_inject(ns: str, ifname: str, n: int, tag: bytes, src: str, ethertype: int = 0x88b5) -> None:
    s = bytes.fromhex(src.replace(":", ""))
    code = (f"import socket,time\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind(({ifname!r},0))\n"
            f"for i in range({n}):\n s.send(b'\\xff'*6+{s!r}+{ethertype.to_bytes(2, 'big')!r}+"
            f"{MAGIC!r}+{tag!r}+i.to_bytes(4,'big')+b'z'*40)\n time.sleep(0.002)\n")
    sh(f"ip netns exec {ns} python3 -c \"{code}\"")


def l2_counter(dev: str, ns: str | None = None, drop: bool = True) -> int:
    """Packets counted by the lane's drop (or its pass) filters on dev's ingress."""
    pre = f"ip netns exec {ns} " if ns else ""
    p = sh(f"{pre}tc -s -j filter show dev {dev} ingress", check=False)
    try:
        rows = json.loads(p.stdout or "[]")
    except ValueError:
        return -1
    want = "matchall" if drop else "flower"
    return sum(f["options"]["actions"][0]["stats"]["packets"] for f in rows if f.get("kind") == want and "options" in f)


def l2_up(dev: str, ns: str | None = None) -> bool:
    pre = f"ip -n {ns} " if ns else "ip "
    p = sh(f"{pre}-j link show dev {dev}", check=False)
    return p.returncode == 0 and "UP" in json.loads(p.stdout)[0].get("flags", [])


def l2_wait(cond, timeout: float, step: float = 0.5) -> float | None:
    """Seconds until cond() held, or None."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if cond():
            return time.monotonic() - t0
        time.sleep(step)
    return None


def l2_ping(src_ns: str, dst: str, n: int, size: int = 56) -> int:
    p = sh(f"ip netns exec {src_ns} ping -n -q -M do -s {size} -c {n} -i 0.2 -W 3 {dst}", check=False)
    for ln in p.stdout.splitlines():
        if "received" in ln:
            return int(ln.split(",")[1].split()[0])
    return 0


def phase_l2() -> None:
    """ADR 0004 module 6: an opt-in bridge of one port to one peer, filtered by EtherType and source MAC."""
    topo_l2()
    write_cfg(L2_B, CFG_B)
    # refused at validation
    for name, text, want in (
            ("without accept_layer2", L2_A.replace("accept_layer2 = true\n", ""), "missing required key(s) accept_layer2"),
            ("with accept_layer2 = false", L2_A.replace("accept_layer2 = true", "accept_layer2 = false"), "accept_layer2 = true is required"),
            ("without ethertypes", L2_A.replace('ethertypes = ["0x0806", "0x0800", "0x88b5"]\n', ""), "missing required key(s) ethertypes"),
            ("with an empty macs list", L2_A.replace('macs = ["02:00:00:00:b0:01"]', "macs = []"), "macs must list"),
            ("with a group source MAC", L2_A.replace('macs = ["02:00:00:00:b0:01"]', 'macs = ["01:00:5e:00:00:01"]'), "group"),
            ("with a VLAN tag as an EtherType", L2_A.replace('"0x88b5"]', '"0x8100"]'), "VLAN tag"),
            ("with the relay's link interface as its port", L2_A.replace('port = "lp0"', 'port = "l2d0"'), "relay's link interface")):
        p = gr("validate", "--config", write_cfg(text))
        result(p.returncode == 2 and want in p.stderr, f"l2: refused {name}", p.stderr.strip()[-160:])
    p = gr("validate", "--config", write_cfg(L2_A.replace("accept_layer2 = true\n", "accept_layer2 = false\n")))
    result("ADR 0002" in p.stderr and "ARP" in p.stderr, "l2: the refusal names the risks the lane keeps (ADR 0002)", p.stderr.strip()[-200:])
    write_cfg(L2_A)
    p = gr("relay", "--config", CFG)
    result(p.returncode == 2 and "IPv6 is on for lp0" in p.stderr, "l2: relay refused: IPv6 on the lane port", p.stderr.strip()[-120:])
    sh("sysctl -qw net.ipv6.conf.lp0.disable_ipv6=1")
    sh("ip netns exec endB sysctl -qw net.ipv6.conf.lp1.disable_ipv6=1")
    # br_netfilter: a VM loads it here for the refusal and unloads it after; a container cannot load modules
    loaded = not os.path.exists("/proc/sys/net/bridge") and sh("modprobe br_netfilter", check=False).returncode == 0
    nf = [k for k in ("iptables", "ip6tables", "arptables") if os.path.exists(f"/proc/sys/net/bridge/bridge-nf-call-{k}")]
    if nf and any(open(f"/proc/sys/net/bridge/bridge-nf-call-{k}").read().strip() == "1" for k in nf):
        p = gr("relay", "--config", CFG)
        result(p.returncode == 2 and "bridge-nf-call" in p.stderr, "l2: relay refused: bridged frames would pass through iptables",
               p.stderr.strip()[-120:])
    else:
        result(None, "l2: bridge-nf-call refusal not shown", "br_netfilter is not loaded on this kernel")
    for pre in ("", "ip netns exec endB "):
        for k in nf:
            sh(f"{pre}sysctl -qw net.bridge.bridge-nf-call-{k}=0", check=False)
    if loaded:
        sh("modprobe -r br_netfilter", check=False)
    result(not sh("ip link show l2b-lane0", check=False).returncode == 0, "l2: a refused start made no lane interface")
    # A failure while the lane is being made (another GRETAP already has its local, remote and key, so
    # the kernel refuses ours after the bridge exists): the refusal removes what was made.
    sh("ip link add dup0 type gretap local 203.0.113.1 remote 203.0.113.2 key 4242 dev wgl0")
    p = gr("relay", "--config", CFG)
    left = [i for i in ("l2b-lane0", "l2g-lane0") if os.path.exists(f"/sys/class/net/{i}")]
    qd = sh("tc qdisc show dev lp0").stdout
    sh("ip link del dup0")
    result(p.returncode == 2 and not left and "clsact" not in qd,
           "l2: a start that fails while making the lane removes what it made", f"exit {p.returncode}, left {left}: {p.stderr.strip()[-120:]}")

    # a foreground relay of an earlier phase leaves relay.health; uninstall removes it, so start without it
    if os.path.exists("/var/lib/goatrope/relay.health") and not os.path.exists("/var/lib/goatrope/state.json"):
        os.remove("/var/lib/goatrope/relay.health")
    before = snapshot()
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "l2: install of a relay with a lane", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}")
    unit = open("/etc/systemd/system/goatrope-relay.service").read() if os.path.exists("/etc/systemd/system/goatrope-relay.service") else ""
    result("ExecStopPost=/usr/local/sbin/goatrope l2 down" in unit, "l2: the unit closes the lane however the relay stops (ExecStopPost)")
    b_log = open(f"{WORK}/relay-b.log", "w")
    relay_b = subprocess.Popen(["ip", "netns", "exec", "endB"] + GR + ["relay", "--config", CFG_B], stdout=b_log, stderr=subprocess.STDOUT)
    waited = l2_wait(lambda: l2_up("l2g-lane0") and l2_up("l2g-lane0", "endB"), 60)
    result(waited is not None, "l2: both lane ends come up once the WireGuard peers handshake",
           f"after {waited:.1f} s" if waited is not None else open(f"{WORK}/relay-b.log").read()[-300:])
    check_exit(0, "l2: lane up")
    gre = json.loads(sh("ip -d -j link show l2g-lane0").stdout)[0]
    br = json.loads(sh("ip -d -j link show l2b-lane0").stdout)[0]
    result(br["linkinfo"]["info_data"]["stp_state"] == 0 and not sh("ip -br addr show dev l2b-lane0").stdout.split()[2:]
           and gre["mtu"] == 1500 and gre["linkinfo"]["info_data"]["pmtudisc"] is False,
           "l2: bridge with STP off and no address; GRETAP MTU 1500, outer fragmentation allowed",
           f"stp {br['linkinfo']['info_data']['stp_state']}, gretap mtu {gre['mtu']}, pmtudisc {gre['linkinfo']['info_data']['pmtudisc']}")

    cap_b = Capture("hostB", "hb0", "l2-b")
    cap_a = Capture("hostA", "ha0", "l2-a")
    sh("ip -n hostA neigh flush dev ha0 && ip -n hostB neigh flush dev hb0", check=False)
    n = l2_ping("hostA", "192.0.2.2", 10)
    neigh_a = sh("ip -n hostA neigh show 192.0.2.2 dev ha0").stdout
    neigh_b = sh("ip -n hostB neigh show 192.0.2.1 dev hb0").stdout
    result(n == 10 and MAC_B in neigh_a and MAC_A in neigh_b,
           "l2: ARP crosses both ways (each host resolved the other's MAC) and IPv4 crosses", f"{n} of 10 pings; {neigh_a.strip()} | {neigh_b.strip()}")
    n = l2_ping("hostB", "192.0.2.1", 10)
    result(n == 10, "l2: IPv4 crosses the other way", f"{n} of 10")
    pass_a, pass_b = l2_counter("l2g-lane0", drop=False), l2_counter("l2g-lane0", "endB", drop=False)
    l2_inject("hostA", "ha0", 50, b"E1", MAC_A)
    l2_inject("hostB", "hb0", 50, b"E2", MAC_B)
    time.sleep(0.5)
    pass_a, pass_b = l2_counter("l2g-lane0", drop=False) - pass_a, l2_counter("l2g-lane0", "endB", drop=False) - pass_b
    drops_a, drops_b = l2_counter("lp0"), l2_counter("lp1", "endB")
    l2_inject("hostA", "ha0", 30, b"U1", MAC_A, 0x88b6)
    l2_inject("hostB", "hb0", 30, b"U2", MAC_B, 0x88b6)
    gdrops_a, gdrops_b = l2_counter("l2g-lane0"), l2_counter("l2g-lane0", "endB")
    l2_inject("hostA", "ha0", 30, b"M1", "02:00:00:00:a0:66")
    l2_inject("hostB", "hb0", 30, b"M2", "02:00:00:00:b0:66")
    # an ARP request whose Ethernet source is declared but whose sender hardware address is not
    spoof = bytes.fromhex("02000000a066")
    arp = (b"\xff" * 6 + bytes.fromhex(MAC_A.replace(":", "")) + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01"
           + spoof + bytes([192, 0, 2, 77]) + b"\x00" * 6 + bytes([192, 0, 2, 2]))
    sh(f"ip netns exec hostA python3 -c \"import socket;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('ha0',0));"
       f"[s.send({arp!r}) for i in range(10)]\"")
    time.sleep(1)
    fb, fa = cap_b.stop(), cap_a.stop()
    result(tagged(fb, b"E1") == set(range(50)) and tagged(fa, b"E2") == set(range(50)),
           "l2: a declared EtherType (0x88b5) crosses both ways",
           f"{len(tagged(fb, b'E1'))} of 50 A to B, {len(tagged(fa, b'E2'))} of 50 B to A; "
           f"passed from the tunnel {pass_b} at B, {pass_a} at A")
    da, db = l2_counter("lp0") - drops_a, l2_counter("lp1", "endB") - drops_b
    result(not tagged(fb, b"U1") and not tagged(fa, b"U2") and da >= 30 and db >= 30,
           "l2: an undeclared EtherType (0x88b6) is dropped at the port, and counted",
           f"{len(tagged(fb, b'U1'))} of 30 and {len(tagged(fa, b'U2'))} of 30 crossed; drops counted {da} at A, {db} at B")
    ga, gb = l2_counter("l2g-lane0") - gdrops_a, l2_counter("l2g-lane0", "endB") - gdrops_b
    spoofed = [f for f in fb if f[12:14] == b"\x08\x06" and f[22:28] == spoof]
    result(not tagged(fb, b"M1") and not tagged(fa, b"M2") and not spoofed and ga >= 30 and gb >= 40,
           "l2: an undeclared source MAC (and an ARP sender address that is not the frame's source) is dropped from the tunnel, and counted",
           f"{len(tagged(fb, b'M1'))} of 30 and {len(tagged(fa, b'M2'))} of 30 crossed, {len(spoofed)} of 10 spoofed ARP; drops counted {ga} at A, {gb} at B")
    other = [f[:16].hex() for f in fb if not (f[6:12] == bytes.fromhex(MAC_A.replace(":", "")) and f[12:14] in (b"\x08\x06", b"\x08\x00", b"\x88\xb5"))]
    result(not other, "l2: on link B, every frame from the lane was a declared EtherType from a declared MAC",
           f"{len(fb)} frames, {len(other)} other: {other[:3]}")
    wg_mtu = json.loads(sh("ip -j link show wgl0").stdout)[0]["mtu"]
    n = l2_ping("hostA", "192.0.2.2", 10, 1472)
    result(n == 10 and wg_mtu == 1280, "l2: a 1,472-byte ping (a 1,514-byte frame, DF set) crosses a WireGuard MTU of 1,280",
           f"{n} of 10, WireGuard MTU {wg_mtu}")
    fwd = {i: (open(f"/proc/sys/net/ipv4/conf/{i}/forwarding").read().strip()) for i in ("lp0", "l2b-lane0", "l2g-lane0", "wgl0")}
    fwd["ipv6"] = open("/proc/sys/net/ipv6/conf/all/forwarding").read().strip()
    result(set(fwd.values()) == {"0"}, "l2: IP forwarding stays off (the lane bridges, it does not route)", str(fwd))
    p = gr("status", "--config", CFG)
    lane = [ln.strip() for ln in p.stdout.splitlines() if "lane" in ln or "frames passed" in ln]
    result(any("lane0 up" in ln for ln in lane) and any("dropped" in ln for ln in lane), "l2: status shows the lane and its counters",
           " | ".join(lane)[:300])

    # check 3 when part of the lane is removed; the relay stops on it, and its restart builds the lane again
    for what, cmd, item_id in (("a filter", "tc filter del dev l2g-lane0 ingress pref 60000", "l2:lane0:filters:l2g-lane0"),
                               ("the GRETAP interface", "ip link del l2g-lane0", "l2:lane0:gretap"),
                               ("the bridge", "ip link del l2b-lane0", "l2:lane0:bridge")):
        restarts = int(unit_props().get("NRestarts", "0"))
        sh(cmd)
        p = gr("check", "--config", CFG)
        diffs = [ln for ln in p.stdout.splitlines() if "DIFF" in ln]
        result(p.returncode == 3 and any(item_id in ln for ln in diffs), f"l2: {what} removed: check exits 3",
               f"exit {p.returncode}: {'; '.join(diffs)[:200]}")
        back = l2_wait(lambda: int(unit_props().get("NRestarts", "0")) > restarts and gr("check", "--config", CFG).returncode == 0
                       and l2_up("l2g-lane0"), 60, 1)
        n = l2_ping("hostA", "192.0.2.2", 5)
        result(back is not None and n == 5, f"l2: {what} removed: the relay stops, is restarted and builds the lane again; check 0",
               f"after {back:.0f} s, {n} of 5 pings" if back is not None else f"NRestarts {unit_props().get('NRestarts')}")

    # the lane follows the tunnel: down within 180 s + one tick of the last handshake, up when it is fresh again
    def last_hs() -> int:
        out = sh("wg show wgl0 latest-handshakes").stdout.split()
        return int(out[1]) if len(out) > 1 else 0
    sh("ip -n endB link set wgl1 down")
    t_stop, hs = time.time(), last_hs()
    waited = l2_wait(lambda: not l2_up("l2g-lane0"), 200, 0.25)
    t_down = time.time()
    after_hs = t_down - hs
    result(waited is not None and 180 <= after_hs <= 184,
           "l2: the lane goes down within 180 s + one tick (2 s) of the peer's last handshake",
           f"down {after_hs:.1f} s after the last handshake, {t_down - t_stop:.1f} s after the peer stopped")
    n = l2_ping("hostA", "192.0.2.2", 3)
    result(n == 0, "l2: nothing crosses while the lane is down", f"{n} of 3")
    sh("ip -n endB link set wgl1 up")
    waited = l2_wait(lambda: l2_up("l2g-lane0") and l2_up("l2g-lane0", "endB"), 60, 0.25)
    n = l2_ping("hostA", "192.0.2.2", 5)
    result(waited is not None and n == 5, "l2: the lane comes back up when the handshake is fresh again",
           f"after {waited:.1f} s, {n} of 5 pings" if waited is not None else "still down")

    relay_b.terminate()
    try:
        rc = relay_b.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay_b.kill()
        rc = None
    result(rc == 0 and not l2_up("l2g-lane0", "endB"), "l2: a relay stopped with SIGTERM closes its lane first", f"exit {rc}")
    sh("systemctl stop goatrope-relay.service")
    result(not l2_up("l2g-lane0"), "l2: a stopped relay unit leaves its lane closed")
    p = gr("uninstall", "--purge")
    left = diff(before, snapshot())
    gone = [i for i in ("l2b-lane0", "l2g-lane0") if os.path.exists(f"/sys/class/net/{i}")]
    qd = sh("tc qdisc show dev lp0").stdout
    master = os.path.exists("/sys/class/net/lp0/master")
    result(p.returncode == 0 and not left and not gone and "clsact" not in qd and not master,
           "l2: uninstall --purge removes the bridge, the GRETAP interface and the filters, and leaves nothing",
           "; ".join(left + gone)[:300] + f" qdisc: {qd.strip()[:80]}, port in a bridge: {master}")
    for ns in ("hostA", "hostB", "endB"):
        sh(f"ip netns del {ns}", check=False)
    for leftover in ("l2u0", "wgl0", "lp0", "l2d0"):
        sh(f"ip link del {leftover}", check=False)


PHASES["l2"] = phase_l2


# ---------------------------------------------------------------- remote mirror (ADR 0004 module 5)
# Two containers joined by WireGuard over their Docker network: this one is the tap machine and
# sends the mirror; the other (run.sh starts it) is a goatrope listen tap with source = "erspan"
# whose underlay is its WireGuard interface. run.sh writes each one's peer (key, address) to PEER.

PEER = f"{WORK}/peer"
WG_MTU = 1280  # a mesh MTU below 1,500, as NetBird's
MIRROR_SESSION = 7

COLLECTOR = f"""schema = 1
[tap]
mode = "listen"
source = "erspan"
ports = ["grspan0"]
management = "eth0"
[tap.erspan]
underlay = "wg0"
local = "203.0.113.2"
remote = "203.0.113.1"
session_id = {MIRROR_SESSION}
version = 1
[tap.record]
ports = ["grspan0"]
filter = ""
file_mb = 5
files = 4
"""

MIRROR_TABLE = f"""
[[tap.mirror]]
ports = ["tp0"]
underlay = "wg0"
local = "203.0.113.1"
remote = "203.0.113.2"
session_id = {MIRROR_SESSION}
filter = "not udp port 9999"
"""

# What the tap machine sends, and so what the collector must (or must not) receive.
MIRROR_SENT = {"SM": 50, "BG": 50, "IA": 30, "IB": 30}      # mirrored: every one arrives
MIRROR_HELD = {"FX": 20, "T1": 20}                            # filtered, or on a port not mirrored


def wg_key() -> str:
    priv = sh("wg genkey").stdout.strip()
    fd = os.open(f"{WORK}/wg.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, priv.encode() + b"\n")
    os.close(fd)
    return subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()


def wg_up(mine: str, theirs: str) -> None:
    key, endpoint = open(PEER).read().split()
    sh("ip link del wg0", check=False)
    sh("ip link add wg0 type wireguard")
    sh(f"cat {WORK}/wg.key | wg set wg0 listen-port 51820 private-key /dev/stdin "
       f"peer {key} endpoint {endpoint}:51820 allowed-ips {theirs}/32 persistent-keepalive 5")
    sh(f"ip addr add {mine}/24 dev wg0 && ip link set wg0 mtu {WG_MTU} up")


def inject_udp(ns: str, ifname: str, n: int, tag: bytes, dport: int, size: int, df: bool) -> None:
    """Ethernet frames of size bytes (14 + an IPv4 packet) carrying UDP to dport, sent from ns."""
    code = ("import socket,struct\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\n"
            f"s.bind(({ifname!r},0))\n"
            "def ck(h):\n s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);return (~(s+(s>>16)))&0xffff\n"
            f"for i in range({n}):\n"
            f" pl={MAGIC!r}+{tag!r}+i.to_bytes(4,'big')\n"
            f" pl+=b'm'*({size}-14-20-8-len(pl))\n"
            f" u=struct.pack('!HHHH',40000,{dport},8+len(pl),0)+pl\n"
            f" h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),i,{0x4000 if df else 0},64,17,0,bytes([192,0,2,10]),bytes([192,0,2,20]))\n"
            " h=h[:10]+struct.pack('!H',ck(h))+h[12:]\n"
            " s.send(b'\\x02\\x00\\x00\\x00\\x00\\x20'+b'\\x02\\x00\\x00\\x00\\x00\\x10'+b'\\x08\\x00'+h+u)\n")
    sh(f"ip netns exec {ns} python3 -c \"{code}\"")


def tc_filters(port: str) -> str:
    return "".join(sh(f"tc filter show dev {port} {hook}", check=False).stdout for hook in ("ingress", "egress"))


def frag_creates() -> int:
    rows = [ln.split() for ln in open("/proc/net/snmp") if ln.startswith("Ip:")]
    return int(rows[1][rows[0].index("FragCreates")])


def phase_mirror_collector() -> None:
    """The collector: a goatrope listen tap, source = "erspan", whose underlay is WireGuard."""
    wg_up("203.0.113.2", "203.0.113.1")
    write_cfg(COLLECTOR)
    stand_in_watchdog()
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "mirror collector: install (listen, source erspan, underlay WireGuard wg0)",
           f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-400:]}")
    check_exit(0, "mirror collector after install")
    wait_packet_sockets("grspan0", 1)


def phase_mirror() -> None:
    """The tap machine: [[tap.mirror]] on a listen tap, then on an inline tap."""
    wg_up("203.0.113.1", "203.0.113.2")
    ping = sh("ping -c 3 -W 2 203.0.113.2", check=False)
    result(ping.returncode == 0, "mirror: the collector answers over WireGuard", f"wg0 mtu {WG_MTU}")
    topo_listen()
    stand_in_watchdog()
    listen = LISTEN + MIRROR_TABLE
    # Refusals: the declaration, then install on the machine, which must change nothing.
    for bad, want, name in (
        (listen.replace('underlay = "wg0"', 'underlay = "tp1"'), "is a tap interface", "an underlay that is a tap port"),
        (listen.replace('ports = ["tp0"]\nunderlay', 'ports = ["tp9"]\nunderlay'), "is not one of [tap].ports", "a port that is not a tap port"),
        (listen.replace("session_id = 7", "session_id = 1024"), "from 0 to 1023", "a session ID over 1023"),
        (listen.replace('underlay = "wg0"\n', ''), "missing required key(s) underlay", "no underlay (there is no default)"),
        (listen + MIRROR_TABLE.replace('remote = "203.0.113.2"', 'remote = "203.0.113.3"'), "same session_id", "two mirrors with one session ID"),
        (INLINE + MIRROR_TABLE.replace('["tp0"]', '["tp0", "tp1"]'), "exactly 1", "two ports of an inline tap (one bridge port sees both directions)"),
    ):
        p = gr("validate", "--config", write_cfg(bad))
        result(p.returncode == 2 and want in p.stderr, f"mirror: refused: {name}", p.stderr.strip()[-160:])
    before = snapshot()
    filters_before = tc_filters("tp0")
    for bad, want, name in (
        (listen.replace('underlay = "wg0"', 'underlay = "wg9"'), "underlay wg9 does not exist", "the underlay does not exist"),
        (listen.replace('local = "203.0.113.1"', 'local = "203.0.113.9"'), "does not hold 203.0.113.9", "the underlay does not hold local"),
        (listen.replace('remote = "203.0.113.2"', 'remote = "192.0.2.99"'), "not the underlay wg0", "the route to the collector is not by the underlay"),
        (listen.replace('filter = "not udp port 9999"', 'filter = "udp port nine"'), "cannot compile the filter", "a filter tcpdump cannot compile"),
    ):
        p = gr("install", "--config", write_cfg(bad))
        d = diff(before, snapshot())
        result(p.returncode == 2 and want in p.stderr and not d and not os.path.exists("/sys/class/net/goatrope-m7"),
               f"mirror: install refused, changing nothing: {name}", (p.stderr.strip()[-140:] + " " + "; ".join(d))[:300])

    write_cfg(listen)
    c0, c1 = Capture("feed", "f0", "mirror-f0"), Capture("feed", "f1", "mirror-f1")
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "mirror: install (listen tap, mirror of tp0)", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-400:]}")
    link = " ".join(sh("ip -d link show goatrope-m7", check=False).stdout.split())
    result("erspan" in link and "nopmtudisc" in link and "okey 0.0.0.7" in link and "erspan_ver 1" in link,
           "mirror: an ERSPAN type II interface, key 7, outer fragmentation allowed", link[:220])
    check_exit(0, "mirror after install")
    p = gr("status", "--config", CFG)
    line = next((ln for ln in p.stdout.splitlines() if "mirror goatrope-m7" in ln), "")
    result("session 7" in line and "203.0.113.2" in line and "wg0" in line, "mirror: status lists the mirror", line.strip())
    frags = frag_creates()
    inject_udp("feed", "f0", MIRROR_SENT["SM"], b"SM", 5000, 80, False)
    inject_udp("feed", "f0", MIRROR_SENT["BG"], b"BG", 5001, 1514, True)  # a 1,500-byte packet, DF set
    inject_udp("feed", "f0", MIRROR_HELD["FX"], b"FX", 9999, 80, False)    # the filter excludes it
    inject_udp("feed", "f1", MIRROR_HELD["T1"], b"T1", 5000, 80, False)    # tp1 is not mirrored
    time.sleep(2)
    frags = frag_creates() - frags
    sent = int(open("/sys/class/net/goatrope-m7/statistics/tx_packets").read())
    result(sent == MIRROR_SENT["SM"] + MIRROR_SENT["BG"], "mirror: the interface sent exactly the copies the filter passes",
           f"{sent} packets sent, {MIRROR_SENT['SM'] + MIRROR_SENT['BG']} expected; {frags} IPv4 fragments made for wg0 (mtu {WG_MTU})")
    result(frags >= MIRROR_SENT["BG"], "mirror: 1,500-byte frames were sent fragmented, not dropped or truncated",
           f"{frags} fragments for {MIRROR_SENT['BG']} full-size frames")
    sh("systemctl restart goatrope-ports.service"); ports_settled()
    f0, f1 = c0.stop(), c1.stop()
    result(not f0 and not f1, "mirror: no frame sent on the tapped link (install, mirror, restart of goatrope-ports)",
           f"{len(f0)} + {len(f1)} frames reached the feed side")
    sh("tc filter del dev tp0 ingress pref 1007")
    check_exit(3, "mirror: the tc filter removed")
    sh("systemctl restart goatrope-ports.service"); ports_settled()
    check_exit(0, "mirror: after goatrope-ports restores the filter")
    sh("ip link del goatrope-m7")
    check_exit(3, "mirror: the interface removed")
    gr("install", "--config", CFG)
    check_exit(0, "mirror: install again restores it")
    p = gr("uninstall", "--purge")
    d = diff(before, snapshot())
    result(p.returncode == 0 and not d and tc_filters("tp0") == filters_before and not os.path.exists("/sys/class/net/goatrope-m7"),
           "mirror: uninstall removes the interface and the filters and restores the ports",
           ("; ".join(d) + f" filters now {tc_filters('tp0')!r}")[:400])

    # Inline: one bridge port mirrors both directions of the link.
    topo_inline()
    for ns, peer in (("a", "a0"), ("b", "b0")):
        sh(f"ip netns exec {ns} sysctl -qw net.ipv6.conf.{peer}.disable_ipv6=1")  # the hosts send only what the test sends
    sh("tc qdisc add dev tp1 clsact && tc filter add dev tp1 ingress pref 9 matchall action pass")  # the operator's own
    before = snapshot()
    filters_before = tc_filters("tp0") + tc_filters("tp1")
    write_cfg(INLINE + MIRROR_TABLE.replace('filter = "not udp port 9999"\n', ""))
    p = gr("install", "--config", CFG)
    result(p.returncode == 0, "mirror: install (inline tap, mirror of tp0, every frame)", f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}")
    check_exit(0, "mirror inline after install")
    cb, ca = Capture("b", "b0", "mirror-b0"), Capture("a", "a0", "mirror-a0")
    raw_inject("a", "a0", MIRROR_SENT["IA"], b"IA")
    raw_inject("b", "b0", MIRROR_SENT["IB"], b"IB")
    fb, fa = cb.stop(), ca.stop()
    result(tagged(fb, b"IA") == set(range(MIRROR_SENT["IA"])) and len(fb) == MIRROR_SENT["IA"]
           and tagged(fa, b"IB") == set(range(MIRROR_SENT["IB"])) and len(fa) == MIRROR_SENT["IB"],
           "mirror inline: the link carries both directions, and nothing else",
           f"b0 got {len(fb)} frames ({len(tagged(fb, b'IA'))} of {MIRROR_SENT['IA']} from a); a0 got {len(fa)} ({len(tagged(fa, b'IB'))} of {MIRROR_SENT['IB']} from b)")
    p = gr("uninstall", "--purge")
    d = diff(before, snapshot())
    after = tc_filters("tp0") + tc_filters("tp1")
    result(p.returncode == 0 and not d and after == filters_before,
           "mirror inline: uninstall restores the ports and keeps the operator's own tc filter", ("; ".join(d) + f" {after!r}")[:400])


def phase_mirror_arrived() -> None:
    """Back on the collector: what reached it over WireGuard, counted from its recording."""
    time.sleep(3)  # stopping a recorder loses what tcpdump has not yet written
    flush_recorders(["grspan0"])
    frames = ring_frames("grspan0")
    for tag, n in MIRROR_SENT.items():
        got = tagged(frames, tag.encode())
        later = " (sent after the mirror interface was made again)" if tag in ("IA", "IB") else ""
        result(got == set(range(n)), f"mirror collector: every mirrored frame arrived ({tag}){later}", f"{len(got)} of {n}")
    big = [f for f in frames if MAGIC + b"BG" in f]
    result(len(big) == MIRROR_SENT["BG"] and all(len(f) == 1514 for f in big),
           "mirror collector: 1,500-byte frames arrived whole across a WireGuard MTU of 1,280",
           f"{len(big)} frames, lengths {sorted(set(len(f) for f in big))}")
    for tag, n in MIRROR_HELD.items():
        got = tagged(frames, tag.encode())
        result(not got, f"mirror collector: frames that are not mirrored did not arrive ({tag})", f"{len(got)} of {n}")
    other = [f for f in frames if MAGIC not in f]
    result(not other, "mirror collector: only the mirrored frames arrived (the mirror interface sends nothing of its own)",
           f"{len(other)} other frames: {[f[12:14].hex() for f in other[:5]]}")
    p = gr("uninstall", "--purge")
    result(p.returncode == 0, "mirror collector: uninstall", p.stdout.strip()[-200:])


PHASES["mirror-collector"] = phase_mirror_collector
PHASES["mirror"] = phase_mirror
PHASES["mirror-arrived"] = phase_mirror_arrived


if __name__ == "__main__":
    os.makedirs(WORK, exist_ok=True)
    for name in sys.argv[1:]:
        if name == "topo-inline":
            topo_inline()
            continue
        if name == "wg-key":  # run.sh reads the public key for the other container's peer
            print(wg_key())
            sys.exit(0)
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
