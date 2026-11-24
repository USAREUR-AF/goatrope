# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""The declared configuration: one TOML file, validated before anything changes.

There are no defaults for what the operator must decide: the tap mode, the
ports, the management interface, the recording filter, and every address and
port number a decode-and-send or relay section names. A missing value is a
refusal, never a guess.
"""
from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_PATH = "/etc/goatrope/goatrope.toml"
IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
RECORD_DIR = "/var/lib/goatrope/record"
# goatrope's own directories under /var/lib/goatrope; a recording directory may not be one of them.
RESERVED_DIRS = ("send", "components", "state.json", "relay.health")
SOURCES = ("copper-tap", "mirror-port", "bypass-relay")


class ConfigError(Exception):
    """The declaration is incomplete or contradicts itself. Exit code 2."""


@dataclass
class Record:
    ports: list[str]
    filter: str
    file_mb: int
    files: int
    directory: str


@dataclass
class Tap:
    mode: str
    ports: list[str]
    management: str
    source: str | None
    speed_mbps: int | None
    record: Record


@dataclass
class Match:
    protocol: str
    src: str | None
    dst: str | None
    src_port: int | None
    dst_port: int | None


@dataclass
class Convert:
    binary: str
    sha256: str
    version: str
    from_format: str
    to_format: str
    packs: str


@dataclass
class Destination:
    url: str
    scheme: str
    host: str | None
    port: int | None
    path: str | None
    framing: str | None
    format: str | None
    max_mb: int | None = None


@dataclass
class Send:
    name: str
    port: str
    match: Match
    convert: Convert | None
    to: list[Destination]


@dataclass
class Decode:
    name: str
    component: str
    binary: str
    sha256: str
    version: str
    ports: list[str]
    filter: str
    dictionary: str
    subscribers: str
    publishers: str


@dataclass
class RelayRule:
    direction: str
    remote: str
    listen_port: int
    target: str
    target_port: int
    protocol: str


@dataclass
class Relay:
    wip_acknowledged: bool
    remote_interface: str
    link_interface: str
    link_address: str
    rules: list[RelayRule]


@dataclass
class WormRule:
    """out: from a machine on this link, at a claimed address, into the tunnel. in: out of the tunnel,
    as a claimed address, to a machine on this link."""
    protocol: str
    port: int
    tunnel_port: int
    replies: bool
    from_: str = ""
    at: str = ""
    as_: str = ""
    to: str = ""


@dataclass
class WormPeer:
    name: str
    interface: str
    address: str
    heartbeat_port: int
    claims: list[str]
    out: list[WormRule]
    in_: list[WormRule]


@dataclass
class Wormhole:
    link_interface: str
    link_address: str
    peers: list[WormPeer]


@dataclass
class Config:
    path: str
    tap: Tap | None
    sends: list[Send] = field(default_factory=list)
    decodes: list[Decode] = field(default_factory=list)
    relay: Relay | None = None
    wormhole: Wormhole | None = None

    def tap_ports(self) -> list[str]:
        return list(self.tap.ports) if self.tap else []


def _keys(table: dict, where: str, allowed: set[str], required: set[str]) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
    missing = sorted(k for k in required if k not in table)
    if missing:
        raise ConfigError(f"{where}: missing required key(s) {', '.join(missing)}; there is no default")


def _str(table: dict, key: str, where: str) -> str:
    v = table[key]
    if not isinstance(v, str) or (key != "filter" and not v):
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    _plain(v, f"{where}.{key}")
    return v


def _plain(v: str, where: str) -> None:
    """Values reach unit files, environment files and command lines: no control characters, no quotes."""
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ConfigError(f"{where} contains a control character (a newline, tab or similar)")
    if any(c in v for c in "'\"\\"):
        raise ConfigError(f"{where} contains a quote or a backslash")


def _int(table: dict, key: str, where: str, lo: int, hi: int) -> int:
    v = table[key]
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ConfigError(f"{where}.{key} must be a whole number from {lo} to {hi}")
    return v


def _ifname(v, where: str) -> str:
    if not isinstance(v, str) or not IFNAME.match(v):
        raise ConfigError(f"{where}: {v!r} is not an interface name")
    return v


def _addr(v, where: str) -> str:
    try:
        return str(ipaddress.ip_address(v))
    except (ValueError, TypeError):
        raise ConfigError(f"{where}: {v!r} is not an IP address") from None


def _port_list(v, where: str, lo: int, hi: int) -> list[str]:
    if not isinstance(v, list) or not lo <= len(v) <= hi:
        n = f"exactly {lo}" if lo == hi else f"{lo} to {hi}"
        raise ConfigError(f"{where} must list {n} interface(s)")
    names = [_ifname(p, where) for p in v]
    if len(set(names)) != len(names):
        raise ConfigError(f"{where}: an interface is listed twice")
    return names


def _sha(table: dict, where: str) -> str:
    v = _str(table, "sha256", where)
    if not re.fullmatch(r"[0-9a-f]{64}", v):
        raise ConfigError(f"{where}.sha256 must be 64 lowercase hex digits")
    return v


def _tap(t: dict) -> Tap:
    w = "[tap]"
    if not isinstance(t, dict):
        raise ConfigError(f"{w} must be a table")
    _keys(t, w, {"mode", "ports", "management", "source", "speed_mbps", "record"},
          {"mode", "ports", "management", "record"})
    mode = t["mode"]
    if mode not in ("inline", "listen"):
        raise ConfigError(f"{w}.mode must be \"inline\" or \"listen\", not {mode!r}")
    if mode == "inline":
        ports = _port_list(t["ports"], f"{w}.ports (inline bridges two ports)", 2, 2)
        if "source" in t:
            raise ConfigError(f"{w}.source is for listen mode; an inline tap is the device on the link")
        source = None
    else:
        ports = _port_list(t["ports"], f"{w}.ports (listen takes one port, or two for a passive tap's two outputs)", 1, 2)
        if "source" not in t:
            raise ConfigError(f"{w}.source is required in listen mode: one of {', '.join(SOURCES)}")
        source = t["source"]
        if source not in SOURCES:
            raise ConfigError(f"{w}.source must be one of {', '.join(SOURCES)}, not {source!r}")
    mgmt = _ifname(t["management"], f"{w}.management")
    if mgmt in ports:
        raise ConfigError(f"{w}.management ({mgmt}) is also a tap port; manage the machine over another interface")
    speed = None
    if "speed_mbps" in t:
        speed = t["speed_mbps"]
        if speed not in (10, 100, 1000, 2500, 5000, 10000):
            raise ConfigError(f"{w}.speed_mbps must be 10, 100, 1000, 2500, 5000 or 10000")
    if source == "copper-tap" and speed is None:
        raise ConfigError(f"{w}.speed_mbps is required with source = \"copper-tap\": "
                          "a passive copper tap's outputs do not negotiate (100 is usual)")
    r = t["record"]
    rw = f"{w.rstrip(']')}.record]"
    if not isinstance(r, dict):
        raise ConfigError(f"{rw} must be a table")
    _keys(r, rw, {"ports", "filter", "file_mb", "files", "directory"}, {"ports", "filter", "file_mb", "files"})
    rports = _port_list(r["ports"], f"{rw}.ports", 1, 1 if mode == "inline" else 2)
    for p in rports:
        if p not in ports:
            raise ConfigError(f"{rw}.ports: {p} is not one of [tap].ports")
    rfilter = _str(r, "filter", rw)
    directory = r.get("directory", RECORD_DIR)
    m = re.fullmatch(r"/var/lib/goatrope/([a-z0-9][a-z0-9-]{0,31})", directory) if isinstance(directory, str) else None
    if not m or m.group(1) in RESERVED_DIRS:
        raise ConfigError(f"{rw}.directory must be /var/lib/goatrope/<name> (lowercase letters, digits, hyphens; "
                          f"not {', '.join(RESERVED_DIRS)}): goatrope gives it to tcpdump and --purge deletes it")
    return Tap(mode, ports, mgmt, source, speed,
               Record(rports, rfilter, _int(r, "file_mb", rw, 1, 4096), _int(r, "files", rw, 2, 10000), directory))


def _destination(u, where: str, tap_ports: list[str]) -> Destination:
    if isinstance(u, str):
        u = {"url": u}
    if not isinstance(u, dict):
        raise ConfigError(f"{where} must be a URL string or a table with url")
    _keys(u, where, {"url", "framing", "format", "max_mb"}, {"url"})
    url = _str(u, "url", where)
    s = urlsplit(url)
    if s.scheme != "file" and "max_mb" in u:
        raise ConfigError(f"{where}: max_mb is for file destinations")
    if s.scheme in ("udp", "tcp"):
        if not s.hostname or s.port is None:
            raise ConfigError(f"{where}: {url} needs an address and a port, e.g. {s.scheme}://192.0.2.1:5000")
        _addr(s.hostname, where)
        framing = u.get("framing")
        if s.scheme == "tcp" and framing not in ("len32be", "raw"):
            raise ConfigError(f"{where}: a tcp destination needs framing = \"len32be\" or \"raw\"")
        if s.scheme == "udp" and framing is not None:
            raise ConfigError(f"{where}: framing is for tcp destinations")
        if "format" in u:
            raise ConfigError(f"{where}: format is for file destinations")
        return Destination(url, s.scheme, s.hostname, s.port, None, framing, None)
    if s.scheme in ("http", "https"):
        if not s.hostname:
            raise ConfigError(f"{where}: {url} has no host")
        if "framing" in u or "format" in u:
            raise ConfigError(f"{where}: an HTTP destination posts each message; no framing or format")
        return Destination(url, s.scheme, s.hostname, s.port, s.path or "/", None, None)
    if s.scheme == "file":
        if not s.path.startswith("/var/lib/goatrope/") or ".." in s.path:
            raise ConfigError(f"{where}: a file destination must be under /var/lib/goatrope/")
        fmt = u.get("format")
        if fmt not in ("jsonl", "raw"):
            raise ConfigError(f"{where}: a file destination needs format = \"jsonl\" or \"raw\"")
        if "framing" in u:
            raise ConfigError(f"{where}: framing is for tcp destinations")
        if "max_mb" not in u:
            raise ConfigError(f"{where}: a file destination needs max_mb (the file is cut there and one older "
                              "file is kept, so it holds at most twice max_mb)")
        return Destination(url, "file", None, None, s.path, None, fmt, _int(u, "max_mb", where, 1, 100000))
    if s.scheme == "zenoh":
        raise ConfigError(f"{where}: goatrope sends no Zenoh itself; use a [[decode]] component's own sink")
    raise ConfigError(f"{where}: {url} is not udp://, tcp://, http(s):// or file://")


def _send(s: dict, i: int, tap: Tap | None) -> Send:
    w = f"[[send]] #{i + 1}"
    if not isinstance(s, dict):
        raise ConfigError(f"{w} must be a table")
    _keys(s, w, {"name", "port", "match", "convert", "to"}, {"name", "port", "match", "to"})
    name = _str(s, "name", w)
    if not NAME.match(name):
        raise ConfigError(f"{w}.name is lowercase letters, digits and hyphens")
    w = f"[[send]] {name}"
    if tap is None:
        raise ConfigError(f"{w}: decode-and-send reads a tap's copy; declare [tap] first")
    port = _ifname(s["port"], f"{w}.port")
    if port not in tap.ports:
        raise ConfigError(f"{w}.port: {port} is not one of [tap].ports")
    m = s["match"]
    if not isinstance(m, dict):
        raise ConfigError(f"{w}.match must be a table")
    _keys(m, f"{w}.match", {"protocol", "src", "dst", "src_port", "dst_port"}, {"protocol"})
    if m["protocol"] != "udp":
        raise ConfigError(f"{w}.match.protocol: only \"udp\" is built (TCP stream reassembly is not)")
    if not any(k in m for k in ("src", "dst", "src_port", "dst_port")):
        raise ConfigError(f"{w}.match names nothing but the protocol; declare at least one address or port")
    match = Match("udp",
                  _addr(m["src"], f"{w}.match.src") if "src" in m else None,
                  _addr(m["dst"], f"{w}.match.dst") if "dst" in m else None,
                  _int(m, "src_port", f"{w}.match", 1, 65535) if "src_port" in m else None,
                  _int(m, "dst_port", f"{w}.match", 1, 65535) if "dst_port" in m else None)
    conv = None
    if "convert" in s:
        c = s["convert"]
        cw = f"{w}.convert"
        if not isinstance(c, dict):
            raise ConfigError(f"{cw} must be a table")
        req = {"component", "binary", "sha256", "version", "from", "to", "packs"}
        _keys(c, cw, req, req)
        if c["component"] != "goat-transformers":
            raise ConfigError(f"{cw}.component: only \"goat-transformers\" converts")
        conv = Convert(_str(c, "binary", cw), _sha(c, cw), _str(c, "version", cw), _str(c, "from", cw),
                       _str(c, "to", cw), _str(c, "packs", cw))
    to = s["to"]
    if not isinstance(to, list) or not to:
        raise ConfigError(f"{w}.to must list at least one destination")
    return Send(name, port, match, conv, [_destination(d, f"{w}.to[{j}]", tap.ports) for j, d in enumerate(to)])


def _decode(d: dict, i: int, tap: Tap | None) -> Decode:
    w = f"[[decode]] #{i + 1}"
    if not isinstance(d, dict):
        raise ConfigError(f"{w} must be a table")
    # publishers: first-bite's record socket is an address and port, so it is declared, not defaulted
    req = {"name", "component", "binary", "sha256", "version", "ports", "filter", "dictionary", "subscribers",
           "publishers"}
    _keys(d, w, req, req)
    name = _str(d, "name", w)
    if not NAME.match(name):
        raise ConfigError(f"{w}.name is lowercase letters, digits and hyphens")
    w = f"[[decode]] {name}"
    if d["component"] != "first-bite":
        raise ConfigError(f"{w}.component: only \"first-bite\" decodes")
    if tap is None:
        raise ConfigError(f"{w}: a decoder reads a tap's copy; declare [tap] first")
    ports = _port_list(d["ports"], f"{w}.ports", 1, 2)
    for p in ports:
        if p not in tap.ports:
            raise ConfigError(f"{w}.ports: {p} is not one of [tap].ports")
    return Decode(name, "first-bite", _str(d, "binary", w), _sha(d, w), _str(d, "version", w), ports,
                  _str(d, "filter", w), _str(d, "dictionary", w), _str(d, "subscribers", w),
                  _str(d, "publishers", w))


def _relay(r: dict, tap: Tap | None) -> Relay:
    w = "[relay]"
    if not isinstance(r, dict):
        raise ConfigError(f"{w} must be a table")
    _keys(r, w, {"wip", "remote_interface", "link_interface", "link_address", "allow"},
          {"wip", "remote_interface", "link_interface", "link_address", "allow"})
    if r["wip"] is not True:
        raise ConfigError(f"{w}.wip must be true: the relay is work in progress and transmits on the link")
    remote_if = _ifname(r["remote_interface"], f"{w}.remote_interface")
    link_if = _ifname(r["link_interface"], f"{w}.link_interface")
    if remote_if == link_if:
        raise ConfigError(f"{w}: remote_interface and link_interface must differ")
    if tap is not None:
        for name in (remote_if, link_if):
            if name in tap.ports:
                kind = "listen port: a listen port never transmits" if tap.mode == "listen" else \
                    "tap port: a relay transmits from its own interface, never through the tap's bridge"
                raise ConfigError(f"{w}: {name} is a {kind}")
        if tap.management in (link_if,):
            raise ConfigError(f"{w}.link_interface is the management interface")
    try:
        link_addr = str(ipaddress.ip_interface(r["link_address"]))
    except (ValueError, TypeError):
        raise ConfigError(f"{w}.link_address must be an address with a prefix, e.g. 192.0.2.50/24") from None
    rules = []
    allow = r["allow"]
    if not isinstance(allow, list) or not allow:
        raise ConfigError(f"{w}.allow must list at least one rule; everything else is denied")
    for j, a in enumerate(allow):
        aw = f"{w}.allow[{j}]"
        if not isinstance(a, dict):
            raise ConfigError(f"{aw} must be a table")
        req = {"direction", "protocol", "remote", "listen_port", "target", "target_port"}
        _keys(a, aw, req, req)
        if a["direction"] not in ("remote-to-link", "both"):
            raise ConfigError(f"{aw}.direction must be \"remote-to-link\" or \"both\" (replies from the target only)")
        if a["protocol"] != "udp":
            raise ConfigError(f"{aw}.protocol: only \"udp\" is built")
        target = _addr(a["target"], f"{aw}.target")
        iface = ipaddress.ip_interface(link_addr)
        net, t = iface.network, ipaddress.ip_address(target)
        if t not in net:
            raise ConfigError(f"{aw}.target {target} is not on the link ({net})")
        if t == iface.ip or (net.num_addresses > 2 and t in (net.network_address, net.broadcast_address)) \
                or t.is_multicast:
            raise ConfigError(f"{aw}.target {target} is the relay's own, the network, a broadcast or a multicast "
                              "address; a rule names one machine")
        rules.append(RelayRule(a["direction"], _addr(a["remote"], f"{aw}.remote"),
                               _int(a, "listen_port", aw, 1, 65535), target,
                               _int(a, "target_port", aw, 1, 65535), "udp"))
    seen = set()
    for rule in rules:
        if rule.listen_port in seen:
            raise ConfigError(f"{w}.allow: listen_port {rule.listen_port} is used twice")
        seen.add(rule.listen_port)
    return Relay(True, remote_if, link_if, link_addr, rules)


def _wormhole(d: dict, tap: Tap | None) -> Wormhole:
    w = "[wormhole]"
    if not isinstance(d, dict):
        raise ConfigError(f"{w} must be a table")
    req = {"wip", "link_interface", "link_address", "peer"}
    _keys(d, w, req, req)
    if d["wip"] is not True:
        raise ConfigError(f"{w}.wip must be true: the wormhole is work in progress and transmits on the link")
    link_if = _ifname(d["link_interface"], f"{w}.link_interface")
    try:
        link = ipaddress.IPv4Interface(d["link_address"])
        if "/" not in d["link_address"] or link.network.num_addresses < 4:
            raise ValueError
    except (ValueError, TypeError):
        raise ConfigError(f"{w}.link_address must be an IPv4 address with a prefix, e.g. 192.0.2.50/24") from None
    net = link.network

    def on_link(v, where: str) -> str:
        a = ipaddress.ip_address(_addr(v, where))
        if a not in net or a in (net.network_address, net.broadcast_address) or a.is_multicast:
            raise ConfigError(f"{where} {a} is not one machine's address on the link ({net})")
        if a == link.ip:
            raise ConfigError(f"{where} {a} is this machine's own link address")
        return str(a)

    peers, claimed, tun_ifs, names = [], set(), set(), set()
    if not isinstance(d["peer"], list) or not d["peer"]:
        raise ConfigError(f"{w} needs at least one [[wormhole.peer]]")
    for j, p in enumerate(d["peer"]):
        pw = f"{w}.peer[{j}]"
        if not isinstance(p, dict):
            raise ConfigError(f"{pw} must be a table")
        preq = {"name", "interface", "address", "heartbeat_port", "claim"}
        _keys(p, pw, preq | {"out", "in"}, preq)
        name = _str(p, "name", pw)
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", name) or name in names:
            raise ConfigError(f"{pw}.name must be lowercase letters, digits and dashes, and used once")
        names.add(name)
        ifn = _ifname(p["interface"], f"{pw}.interface")
        if ifn in tun_ifs or ifn == link_if:
            raise ConfigError(f"{pw}.interface {ifn} is used twice: each pair has a WireGuard interface of its own")
        tun_ifs.add(ifn)
        address = ipaddress.ip_address(_addr(p["address"], f"{pw}.address"))
        if address.version != 4 or address in net:
            raise ConfigError(f"{pw}.address must be the far end's IPv4 tunnel address, not one on the link ({net})")
        if not isinstance(p["claim"], list) or not p["claim"]:
            raise ConfigError(f"{pw}.claim must list at least one address of this link")
        claims = [on_link(c, f"{pw}.claim") for c in p["claim"]]
        for c in claims:
            if c in claimed:
                raise ConfigError(f"{pw}.claim {c} is claimed twice")
            claimed.add(c)
        hb = _int(p, "heartbeat_port", pw, 1, 65535)
        rules: dict[str, list[WormRule]] = {"out": [], "in": []}
        for side, req in (("out", {"protocol", "from", "at", "port", "tunnel_port"}),
                          ("in", {"protocol", "tunnel_port", "as", "to", "port"})):
            if not isinstance(p.get(side, []), list):
                raise ConfigError(f"{pw}.{side} must be a list of rules")
            for k, r in enumerate(p.get(side, [])):
                rw = f"{pw}.{side}[{k}]"
                if not isinstance(r, dict):
                    raise ConfigError(f"{rw} must be a table")
                _keys(r, rw, req | {"replies"}, req | ({"replies"} if r.get("protocol") == "udp" else set()))
                if r["protocol"] not in ("udp", "tcp"):
                    raise ConfigError(f"{rw}.protocol must be \"udp\" or \"tcp\"")
                if r["protocol"] == "tcp" and "replies" in r:
                    raise ConfigError(f"{rw}.replies is for udp; a TCP connection carries both ways")
                if r["protocol"] == "udp" and not isinstance(r["replies"], bool):
                    raise ConfigError(f"{rw}.replies must be true or false")
                rule = WormRule(r["protocol"], _int(r, "port", rw, 1, 65535), _int(r, "tunnel_port", rw, 1, 65535),
                                r.get("replies", True))
                claim, host = ("at", "from") if side == "out" else ("as", "to")
                c = _addr(r[claim], f"{rw}.{claim}")
                if c not in claims:
                    raise ConfigError(f"{rw}.{claim} {c} is not one of this peer's claims")
                setattr(rule, "at" if side == "out" else "as_", c)
                setattr(rule, "from_" if side == "out" else "to", on_link(r[host], f"{rw}.{host}"))
                rules[side].append(rule)
        if not rules["out"] and not rules["in"]:
            raise ConfigError(f"{pw} has no rule; everything else is denied")
        ports = [(r.protocol, r.tunnel_port) for r in rules["in"]]
        if len(set(ports)) != len(ports) or ("udp", hb) in ports:
            raise ConfigError(f"{pw}.in: a tunnel_port is used twice (the heartbeat's included)")
        ats = [(r.protocol, r.at, r.port) for r in rules["out"]]
        if len(set(ats)) != len(ats):
            raise ConfigError(f"{pw}.out: two rules listen at the same address, protocol and port")
        peers.append(WormPeer(name, ifn, str(address), hb, claims, rules["out"], rules["in"]))
    for p in peers:
        for r in p.out + p.in_:
            h = r.from_ or r.to
            if h in claimed:
                raise ConfigError(f"{w}: {h} is a claim; a rule's own machine is a real one on this link")
    if tap is not None:
        for n in [link_if] + sorted(tun_ifs):
            if n in tap.ports or n == "goatrope0":
                raise ConfigError(f"{w}: {n} is a tap port: the wormhole transmits, from its own interface, never through a tap")
        if tap.management == link_if:
            raise ConfigError(f"{w}.link_interface is the management interface")
    return Wormhole(link_if, str(link), peers)


def parse(text: str, path: str = DEFAULT_PATH) -> Config:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: not valid TOML: {e}") from None
    _keys(doc, path, {"schema", "tap", "send", "decode", "relay", "wormhole"}, {"schema"})
    if doc["schema"] != 1:
        raise ConfigError(f"{path}: schema must be 1")
    if not any(k in doc for k in ("tap", "relay", "wormhole")):
        raise ConfigError(f"{path}: declares no role; declare [tap], [relay] or [wormhole]")
    if "relay" in doc and "wormhole" in doc:
        raise ConfigError(f"{path}: [relay] and [wormhole] are not run on one machine yet")
    tap = _tap(doc["tap"]) if "tap" in doc else None
    sends = [_send(s, i, tap) for i, s in enumerate(doc.get("send", []))]
    decodes = [_decode(d, i, tap) for i, d in enumerate(doc.get("decode", []))]
    names = [s.name for s in sends] + [d.name for d in decodes]
    if len(set(names)) != len(names):
        raise ConfigError(f"{path}: a [[send]] or [[decode]] name is used twice")
    relay = _relay(doc["relay"], tap) if "relay" in doc else None
    worm = _wormhole(doc["wormhole"], tap) if "wormhole" in doc else None
    return Config(path, tap, sends, decodes, relay, worm)


def load(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from None
    return parse(text, path)
