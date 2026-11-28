// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The declared configuration: one TOML file, validated before anything changes.
//!
//! There are no defaults for what the operator must decide: the tap mode, the
//! ports, the management interface, the recording filter, and every address and
//! port number a decode-and-send or relay section names. A missing value is a
//! refusal, never a guess.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use toml::{Table, Value};

pub const DEFAULT_PATH: &str = "/etc/goatrope/goatrope.toml";
pub const RECORD_DIR: &str = "/var/lib/goatrope/record";
/// goatrope's own directories under /var/lib/goatrope; a recording directory may not be one of them.
pub const RESERVED_DIRS: [&str; 4] = ["send", "components", "state.json", "relay.health"];
pub const SOURCES: [&str; 4] = ["copper-tap", "mirror-port", "bypass-relay", "erspan"];
pub const NETBIRD_PORT: i64 = 51820;

/// The declaration is incomplete or contradicts itself. Exit code 2.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

type R<T> = Result<T, ConfigError>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(ConfigError(msg.into()))
}

#[derive(Debug, Clone)]
pub struct Record {
    pub ports: Vec<String>,
    pub filter: String,
    pub file_mb: i64,
    pub files: i64,
    pub directory: String,
}

#[derive(Debug, Clone)]
pub struct Tap {
    pub mode: String,
    pub ports: Vec<String>,
    pub management: String,
    pub source: Option<String>,
    pub speed_mbps: Option<i64>,
    pub record: Record,
    pub erspan: Option<Erspan>,
}

/// An ERSPAN mirror: the switch sends copies in GRE to `local`; goatrope's `erspan` interface
/// (the one tap port) decapsulates the session it names.
#[derive(Debug, Clone)]
pub struct Erspan {
    /// the interface the mirror arrives on; it holds `local`
    pub underlay: String,
    pub local: String,
    /// the address the switch sends the mirror from
    pub remote: String,
    /// the GRE key: the switch's mirror session number (declared as session_id); the kernel delivers a
    /// mirror only to the interface whose key is it
    pub gre_key: i64,
    /// 1: ERSPAN type II; 2: type III
    pub version: i64,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub protocol: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl fmt::Display for Match {
    /// As Python's dataclass repr prints it, which `run-send` logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn o<T: fmt::Display>(v: &Option<T>, quote: bool) -> String {
            match v {
                None => "None".into(),
                Some(x) if quote => format!("'{x}'"),
                Some(x) => x.to_string(),
            }
        }
        write!(
            f,
            "Match(protocol='{}', src={}, dst={}, src_port={}, dst_port={})",
            self.protocol,
            o(&self.src, true),
            o(&self.dst, true),
            o(&self.src_port, false),
            o(&self.dst_port, false)
        )
    }
}

#[derive(Debug, Clone)]
pub struct Convert {
    /// The packs digest (`packs_sha256`): what the linked engine loads (docs/adr/0006-data-path.md).
    pub sha256: String,
    pub from_format: String,
    pub to_format: String,
    pub packs: String,
}

#[derive(Debug, Clone)]
pub struct Destination {
    pub url: String,
    pub scheme: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub framing: Option<String>,
    pub format: Option<String>,
    pub max_mb: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Send {
    pub name: String,
    pub port: String,
    pub matcher: Match,
    pub convert: Option<Convert>,
    pub to: Vec<Destination>,
    /// the capture ring, MiB (docs/adr/0006-data-path.md)
    pub capture_mb: usize,
}

/// A `[[send]]`'s capture ring when it names none: at 2,000 frames a second of 1,500 bytes it holds about 5 s.
pub const DEFAULT_CAPTURE_MB: i64 = 16;

#[derive(Debug, Clone)]
pub struct Decode {
    pub name: String,
    #[allow(dead_code)] // the one decoder component today; kept as declared
    pub component: String,
    pub binary: String,
    pub sha256: String,
    pub version: String,
    pub ports: Vec<String>,
    pub filter: String,
    pub dictionary: String,
    pub subscribers: String,
    pub publishers: String,
}

pub const DEFAULT_MAX_CONNECTIONS: i64 = 64;
/// A UDP rule's socket receive buffer, in KiB, when the rule names none (docs/adr/0006-data-path.md).
pub const DEFAULT_RECEIVE_BUFFER_KB: i64 = 8192;

/// One allow rule. "remote-to-link" and "both": the relay listens on the remote interface at
/// listen_port and sends to target:target_port on the link. "link-to-remote": it listens on its
/// link address at listen_port, accepts only `sources`, and sends to remote:remote_port; target is
/// empty and target_port 0.
#[derive(Debug, Clone)]
pub struct RelayRule {
    pub direction: String,
    pub remote: String,
    pub listen_port: u16,
    pub target: String,
    pub target_port: u16,
    /// "udp" or "tcp"
    pub protocol: String,
    /// link-to-remote: the port on the remote
    pub remote_port: u16,
    /// link-to-remote: the link addresses accepted
    pub sources: Vec<String>,
    /// tcp: connections open at once on this rule
    pub max_connections: usize,
    /// udp: the receive buffer of each of the rule's sockets, KiB
    pub receive_buffer_kb: usize,
    /// a [[relay.proxy]] address the rule's link-side sockets bind to, instead of the relay's own (ADR 0004 §4)
    pub link_address: Option<String>,
}

/// A local address on the link that stands for one remote machine (ADR 0004 §4).
#[derive(Debug, Clone)]
pub struct Proxy {
    /// IPv4, without a prefix; added as a /32 while the remote's tunnel is up
    pub address: String,
    pub remote: String,
}

impl RelayRule {
    pub fn link_initiated(&self) -> bool {
        self.direction == "link-to-remote"
    }
}

/// A WireGuard interface of the relay's own with exactly one peer, the boundary point (ADR 0002, Transport).
#[derive(Debug, Clone)]
pub struct Boundary {
    pub listen_port: u16,
    pub private_key_file: String,
    /// this end's tunnel address, with prefix
    pub address: String,
    pub peer_public_key: String,
    /// canonical "ip:port" or "[ip6]:port", as `wg show` prints it
    pub peer_endpoint: String,
    /// the boundary point's tunnel address; the only source the interface accepts
    pub peer_address: String,
    pub preshared_key_file: String,
    pub keepalive_s: u16,
}

#[derive(Debug, Clone)]
pub struct Relay {
    pub remote_interface: String,
    pub link_interface: String,
    pub link_address: String,
    pub rules: Vec<RelayRule>,
    /// "mesh": an existing WireGuard interface; "boundary": goatrope's own, one peer
    pub transport: String,
    pub boundary: Option<Boundary>,
    pub proxies: Vec<Proxy>,
    /// opt-in layer-2 lanes (ADR 0004 §6); empty unless declared
    pub l2: Vec<L2>,
}

/// A layer-2 lane (ADR 0004 §6): one dedicated port bridged with a GRETAP interface to one peer.
#[derive(Debug, Clone)]
pub struct L2 {
    pub name: String,
    pub port: String,
    /// the far end's tunnel address on remote_interface
    pub peer: String,
    /// this end's tunnel address, held by remote_interface
    pub local: String,
    pub key: u32,
    pub ethertypes: Vec<u16>,
    /// source MAC addresses accepted from across the tunnel, lowercase
    pub macs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub path: String,
    pub tap: Option<Tap>,
    pub sends: Vec<Send>,
    pub decodes: Vec<Decode>,
    pub relay: Option<Relay>,
}

impl Config {
    pub fn tap_ports(&self) -> Vec<String> {
        self.tap.as_ref().map(|t| t.ports.clone()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------- Python-compatible rendering of values

/// A value as Python's repr() shows it, for messages that quote what was declared.
pub fn pyrepr(v: &Value) -> String {
    match v {
        Value::String(s) => pystr(s),
        Value::Integer(i) => i.to_string(),
        Value::Float(x) => {
            if x.fract() == 0.0 && x.is_finite() {
                format!("{x:.1}")
            } else {
                x.to_string()
            }
        }
        Value::Boolean(b) => if *b { "True" } else { "False" }.into(),
        Value::Datetime(d) => d.to_string(),
        Value::Array(a) => format!("[{}]", a.iter().map(pyrepr).collect::<Vec<_>>().join(", ")),
        Value::Table(t) => format!("{{{}}}", t.iter().map(|(k, v)| format!("{}: {}", pystr(k), pyrepr(v))).collect::<Vec<_>>().join(", ")),
    }
}

pub fn pystr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c)
            }
            c if (c as u32) < 32 || c as u32 == 127 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

// ---------------------------------------------------------------- field readers

fn keys(table: &Table, where_: &str, allowed: &[&str], required: &[&str]) -> R<()> {
    let mut unknown: Vec<&str> = table.keys().map(|k| k.as_str()).filter(|k| !allowed.contains(k)).collect();
    unknown.sort();
    if !unknown.is_empty() {
        return err(format!("{where_}: unknown key(s) {}", unknown.join(", ")));
    }
    let mut missing: Vec<&str> = required.iter().copied().filter(|k| !table.contains_key(*k)).collect();
    missing.sort();
    if !missing.is_empty() {
        return err(format!("{where_}: missing required key(s) {}; there is no default", missing.join(", ")));
    }
    Ok(())
}

fn plain(v: &str, where_: &str) -> R<()> {
    if v.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return err(format!("{where_} contains a control character (a newline, tab or similar)"));
    }
    if v.chars().any(|c| c == '\'' || c == '"' || c == '\\') {
        return err(format!("{where_} contains a quote or a backslash"));
    }
    Ok(())
}

fn string(table: &Table, key: &str, where_: &str) -> R<String> {
    match table.get(key) {
        Some(Value::String(s)) if key == "filter" || !s.is_empty() => {
            plain(s, &format!("{where_}.{key}"))?;
            Ok(s.clone())
        }
        _ => err(format!("{where_}.{key} must be a non-empty string")),
    }
}

fn int(table: &Table, key: &str, where_: &str, lo: i64, hi: i64) -> R<i64> {
    match table.get(key) {
        Some(Value::Integer(v)) if lo <= *v && *v <= hi => Ok(*v),
        _ => err(format!("{where_}.{key} must be a whole number from {lo} to {hi}")),
    }
}

pub fn is_ifname(s: &str) -> bool {
    // ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 15
        && b[0].is_ascii_alphanumeric()
        && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'))
}

fn is_name(s: &str) -> bool {
    // ^[a-z0-9][a-z0-9-]{0,31}$
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn ifname(v: &Value, where_: &str) -> R<String> {
    match v {
        Value::String(s) if is_ifname(s) => Ok(s.clone()),
        _ => err(format!("{where_}: {} is not an interface name", pyrepr(v))),
    }
}

/// Python's ipaddress.ip_address: an IPv4 or IPv6 literal (an IPv6 zone is accepted and kept).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok()
}

fn addr(v: &Value, where_: &str) -> R<String> {
    match v {
        Value::String(s) => match parse_ip(s) {
            Some(ip) => Ok(ip.to_string()),
            None => err(format!("{where_}: {} is not an IP address", pyrepr(v))),
        },
        _ => err(format!("{where_}: {} is not an IP address", pyrepr(v))),
    }
}

/// An address with a prefix, as ipaddress.ip_interface accepts it ("192.0.2.50/24"; no prefix means a host).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Iface {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Iface {
    pub fn parse(s: &str) -> Option<Iface> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip = parse_ip(a)?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) && p.len() <= 3 => p.parse::<u8>().ok()?,
            Some(_) => return None,
        };
        if prefix > max {
            return None;
        }
        Some(Iface { ip, prefix })
    }

    fn bits(ip: IpAddr) -> u128 {
        match ip {
            IpAddr::V4(a) => u32::from(a) as u128,
            IpAddr::V6(a) => u128::from(a),
        }
    }

    fn width(&self) -> u32 {
        if self.ip.is_ipv4() {
            32
        } else {
            128
        }
    }

    fn mask(&self) -> u128 {
        let w = self.width();
        let host = w - self.prefix as u32;
        let all = if w == 128 { u128::MAX } else { (1u128 << w) - 1 };
        if host == 0 {
            all
        } else if host >= 128 {
            0
        } else {
            all & !((1u128 << host) - 1)
        }
    }

    pub fn contains(&self, other: IpAddr) -> bool {
        self.ip.is_ipv4() == other.is_ipv4() && (Self::bits(self.ip) & self.mask()) == (Self::bits(other) & self.mask())
    }

    pub fn num_addresses(&self) -> u128 {
        let host = self.width() - self.prefix as u32;
        if host >= 128 {
            u128::MAX
        } else {
            1u128 << host
        }
    }

    fn ip_of(&self, b: u128) -> IpAddr {
        if self.ip.is_ipv4() {
            IpAddr::V4((b as u32).into())
        } else {
            IpAddr::V6(b.into())
        }
    }

    pub fn network_address(&self) -> IpAddr {
        self.ip_of(Self::bits(self.ip) & self.mask())
    }

    pub fn broadcast_address(&self) -> IpAddr {
        let all = if self.width() == 128 { u128::MAX } else { (1u128 << self.width()) - 1 };
        self.ip_of((Self::bits(self.ip) & self.mask()) | (all & !self.mask()))
    }

    /// The network, as Python prints ip_interface(...).network ("192.0.2.0/24").
    pub fn network(&self) -> String {
        format!("{}/{}", self.network_address(), self.prefix)
    }
}

impl fmt::Display for Iface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

fn port_list(v: &Value, where_: &str, lo: usize, hi: usize) -> R<Vec<String>> {
    let a = match v {
        Value::Array(a) if lo <= a.len() && a.len() <= hi => a,
        _ => {
            let n = if lo == hi { format!("exactly {lo}") } else { format!("{lo} to {hi}") };
            return err(format!("{where_} must list {n} interface(s)"));
        }
    };
    let names = a.iter().map(|p| ifname(p, where_)).collect::<R<Vec<_>>>()?;
    let set: BTreeSet<&String> = names.iter().collect();
    if set.len() != names.len() {
        return err(format!("{where_}: an interface is listed twice"));
    }
    Ok(names)
}

fn sha(table: &Table, where_: &str) -> R<String> {
    hex64(table, "sha256", where_)
}

fn hex64(table: &Table, key: &str, where_: &str) -> R<String> {
    let v = string(table, key, where_)?;
    if v.len() != 64 || !v.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return err(format!("{where_}.{key} must be 64 lowercase hex digits"));
    }
    Ok(v)
}

fn as_table<'a>(v: &'a Value, where_: &str) -> R<&'a Table> {
    match v {
        Value::Table(t) => Ok(t),
        _ => err(format!("{where_} must be a table")),
    }
}

// ---------------------------------------------------------------- sections

fn tap(v: &Value) -> R<Tap> {
    let w = "[tap]";
    let t = as_table(v, w)?;
    keys(t, w, &["mode", "ports", "management", "source", "speed_mbps", "record", "erspan"], &["mode", "ports", "management", "record"])?;
    let mode = match &t["mode"] {
        Value::String(s) if s == "inline" || s == "listen" => s.clone(),
        other => return err(format!("{w}.mode must be \"inline\" or \"listen\", not {}", pyrepr(other))),
    };
    let (ports, source) = if mode == "inline" {
        let ports = port_list(&t["ports"], &format!("{w}.ports (inline bridges two ports)"), 2, 2)?;
        if t.contains_key("source") {
            return err(format!("{w}.source is for listen mode; an inline tap is the device on the link"));
        }
        (ports, None)
    } else {
        let ports = port_list(&t["ports"], &format!("{w}.ports (listen takes one port, or two for a passive tap's two outputs)"), 1, 2)?;
        let Some(src) = t.get("source") else {
            return err(format!("{w}.source is required in listen mode: one of {}", SOURCES.join(", ")));
        };
        match src {
            Value::String(s) if SOURCES.contains(&s.as_str()) => (ports, Some(s.clone())),
            other => return err(format!("{w}.source must be one of {}, not {}", SOURCES.join(", "), pyrepr(other))),
        }
    };
    let mut erspan = None;
    if source.as_deref() == Some("erspan") {
        if ports.len() != 1 {
            return err(format!(
                "{w}.ports: with source = \"erspan\" list exactly 1 interface, the one goatrope makes to decapsulate the mirror"
            ));
        }
        if t.contains_key("speed_mbps") {
            return err(format!("{w}.speed_mbps does not apply to source = \"erspan\": the mirror arrives over IP"));
        }
        let Some(e) = t.get("erspan") else {
            return err(format!("{w}: source = \"erspan\" needs a [tap.erspan] table: underlay, local, remote, session_id, version"));
        };
        erspan = Some(erspan_table(e, &ports[0])?);
    } else if t.contains_key("erspan") {
        return err(format!("{w}: [tap.erspan] applies only with source = \"erspan\""));
    }
    let mgmt = ifname(&t["management"], &format!("{w}.management"))?;
    if ports.contains(&mgmt) {
        return err(format!("{w}.management ({mgmt}) is also a tap port; manage the machine over another interface"));
    }
    let mut speed = None;
    if let Some(s) = t.get("speed_mbps") {
        match s {
            Value::Integer(n) if [10, 100, 1000, 2500, 5000, 10000].contains(n) => speed = Some(*n),
            _ => return err(format!("{w}.speed_mbps must be 10, 100, 1000, 2500, 5000 or 10000")),
        }
    }
    if source.as_deref() == Some("copper-tap") && speed.is_none() {
        return err(format!(
            "{w}.speed_mbps is required with source = \"copper-tap\": a passive copper tap's outputs do not negotiate (100 is usual)"
        ));
    }
    let rw = "[tap.record]";
    let r = as_table(&t["record"], rw)?;
    keys(r, rw, &["ports", "filter", "file_mb", "files", "directory"], &["ports", "filter", "file_mb", "files"])?;
    let rports = port_list(&r["ports"], &format!("{rw}.ports"), 1, if mode == "inline" { 1 } else { 2 })?;
    for p in &rports {
        if !ports.contains(p) {
            return err(format!("{rw}.ports: {p} is not one of [tap].ports"));
        }
    }
    let rfilter = string(r, "filter", rw)?;
    let directory = match r.get("directory") {
        None => Some(RECORD_DIR.to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => None,
    };
    let ok_dir =
        directory.as_deref().and_then(|d| d.strip_prefix("/var/lib/goatrope/")).filter(|n| is_name(n) && !RESERVED_DIRS.contains(n));
    if ok_dir.is_none() {
        return err(format!(
            "{rw}.directory must be /var/lib/goatrope/<name> (lowercase letters, digits, hyphens; not {}): goatrope gives it to tcpdump and --purge deletes it",
            RESERVED_DIRS.join(", ")
        ));
    }
    Ok(Tap {
        mode,
        ports,
        management: mgmt,
        source,
        speed_mbps: speed,
        record: Record {
            ports: rports,
            filter: rfilter,
            file_mb: int(r, "file_mb", rw, 1, 4096)?,
            files: int(r, "files", rw, 2, 10000)?,
            directory: directory.unwrap(),
        },
        erspan,
    })
}

fn erspan_table(v: &Value, port: &str) -> R<Erspan> {
    let w = "[tap.erspan]";
    let t = as_table(v, w)?;
    let req = ["underlay", "local", "remote", "session_id", "version"];
    keys(t, w, &req, &req)?;
    let underlay = ifname(&t["underlay"], &format!("{w}.underlay"))?;
    if underlay == port {
        return err(format!("{w}.underlay is the tap port; the mirror arrives on another interface, which holds {w}.local"));
    }
    let local = addr(&t["local"], &format!("{w}.local"))?;
    let remote = addr(&t["remote"], &format!("{w}.remote"))?;
    if local.contains(':') || remote.contains(':') {
        return err(format!("{w}: ERSPAN over IPv6 is not built; local and remote are IPv4 addresses"));
    }
    if local == remote {
        return err(format!("{w}: local and remote must differ"));
    }
    let gre_key = int(t, "session_id", w, 0, 1023)?;
    let version = match &t["version"] {
        Value::Integer(n) if *n == 1 || *n == 2 => *n,
        _ => return err(format!("{w}.version must be 1 (ERSPAN type II) or 2 (type III)")),
    };
    Ok(Erspan { underlay, local, remote, gre_key, version })
}

/// The parts of a URL Python's urllib.parse.urlsplit gives: scheme, hostname, port, path.
pub struct Url {
    pub scheme: String,
    pub hostname: Option<String>,
    pub port: Option<Result<u16, ()>>,
    pub path: String,
}

pub fn urlsplit(url: &str) -> Url {
    let (scheme, rest) = match url.find(':') {
        Some(i)
            if i > 0
                && url.as_bytes()[0].is_ascii_alphabetic()
                && url[..i].bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')) =>
        {
            (url[..i].to_ascii_lowercase(), &url[i + 1..])
        }
        _ => (String::new(), url),
    };
    let (netloc, after) = match rest.strip_prefix("//") {
        Some(r) => {
            let end = r.find(['/', '?', '#']).unwrap_or(r.len());
            (Some(&r[..end]), &r[end..])
        }
        None => (None, rest),
    };
    let path = after.split(['?', '#']).next().unwrap_or("").to_string();
    let (mut hostname, mut port) = (None, None);
    if let Some(n) = netloc {
        let hp = n.rsplit_once('@').map(|x| x.1).unwrap_or(n);
        let (h, p) = if let Some(r) = hp.strip_prefix('[') {
            match r.split_once(']') {
                Some((h, tail)) => (h, tail.strip_prefix(':')),
                None => (r, None),
            }
        } else {
            match hp.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hp, None),
            }
        };
        if !h.is_empty() {
            hostname = Some(h.to_ascii_lowercase());
        }
        if let Some(p) = p {
            if !p.is_empty() {
                port = Some(p.parse::<u16>().map_err(|_| ()));
            }
        }
    }
    Url { scheme, hostname, port, path }
}

fn destination(u: &Value, where_: &str) -> R<Destination> {
    let owned;
    let t: &Table = match u {
        Value::String(s) => {
            let mut t = Table::new();
            t.insert("url".into(), Value::String(s.clone()));
            owned = t;
            &owned
        }
        Value::Table(t) => t,
        _ => return err(format!("{where_} must be a URL string or a table with url")),
    };
    keys(t, where_, &["url", "framing", "format", "max_mb"], &["url"])?;
    let url = string(t, "url", where_)?;
    let s = urlsplit(&url);
    if s.scheme != "file" && t.contains_key("max_mb") {
        return err(format!("{where_}: max_mb is for file destinations"));
    }
    let get = |k: &str| t.get(k);
    match s.scheme.as_str() {
        "udp" | "tcp" => {
            let port = match (&s.hostname, &s.port) {
                (Some(_), Some(Ok(p))) => *p,
                (_, Some(Err(_))) => return err(format!("{where_}: {url}: Port out of range 0-65535")),
                _ => return err(format!("{where_}: {url} needs an address and a port, e.g. {}://192.0.2.1:5000", s.scheme)),
            };
            let host = s.hostname.clone().unwrap();
            addr(&Value::String(host.clone()), where_)?;
            let framing = get("framing");
            let framing_s = match framing {
                Some(Value::String(f)) => Some(f.clone()),
                Some(_) => Some(String::new()),
                None => None,
            };
            if s.scheme == "tcp" && !matches!(framing_s.as_deref(), Some("len32be") | Some("raw")) {
                return err(format!("{where_}: a tcp destination needs framing = \"len32be\" or \"raw\""));
            }
            if s.scheme == "udp" && framing.is_some() {
                return err(format!("{where_}: framing is for tcp destinations"));
            }
            if t.contains_key("format") {
                return err(format!("{where_}: format is for file destinations"));
            }
            Ok(Destination {
                url,
                scheme: s.scheme,
                host: Some(host),
                port: Some(port),
                path: None,
                framing: framing_s,
                format: None,
                max_mb: None,
            })
        }
        "http" | "https" => {
            let Some(host) = s.hostname.clone() else {
                return err(format!("{where_}: {url} has no host"));
            };
            if t.contains_key("framing") || t.contains_key("format") {
                return err(format!("{where_}: an HTTP destination posts each message; no framing or format"));
            }
            let port = match s.port {
                Some(Ok(p)) => Some(p),
                Some(Err(_)) => return err(format!("{where_}: {url}: Port out of range 0-65535")),
                None => None,
            };
            let path = if s.path.is_empty() { "/".to_string() } else { s.path.clone() };
            Ok(Destination { url, scheme: s.scheme, host: Some(host), port, path: Some(path), framing: None, format: None, max_mb: None })
        }
        "file" => {
            if !s.path.starts_with("/var/lib/goatrope/") || s.path.contains("..") {
                return err(format!("{where_}: a file destination must be under /var/lib/goatrope/"));
            }
            let fmt = match get("format") {
                Some(Value::String(f)) if f == "jsonl" || f == "raw" => f.clone(),
                _ => return err(format!("{where_}: a file destination needs format = \"jsonl\" or \"raw\"")),
            };
            if t.contains_key("framing") {
                return err(format!("{where_}: framing is for tcp destinations"));
            }
            if !t.contains_key("max_mb") {
                return err(format!(
                    "{where_}: a file destination needs max_mb (the file is cut there and one older file is kept, so it holds at most twice max_mb)"
                ));
            }
            let max_mb = int(t, "max_mb", where_, 1, 100000)?;
            Ok(Destination {
                url,
                scheme: "file".into(),
                host: None,
                port: None,
                path: Some(s.path),
                framing: None,
                format: Some(fmt),
                max_mb: Some(max_mb),
            })
        }
        "zenoh" => err(format!("{where_}: goatrope sends no Zenoh itself; use a [[decode]] component's own sink")),
        _ => err(format!("{where_}: {url} is not udp://, tcp://, http(s):// or file://")),
    }
}

fn opt_port(m: &Table, key: &str, where_: &str) -> R<Option<u16>> {
    if m.contains_key(key) {
        Ok(Some(int(m, key, where_, 1, 65535)? as u16))
    } else {
        Ok(None)
    }
}

fn send(v: &Value, i: usize, tap: Option<&Tap>) -> R<Send> {
    let w0 = format!("[[send]] #{}", i + 1);
    let s = as_table(v, &w0)?;
    keys(s, &w0, &["name", "port", "match", "convert", "to", "capture_mb"], &["name", "port", "match", "to"])?;
    let name = string(s, "name", &w0)?;
    if !is_name(&name) {
        return err(format!("{w0}.name is lowercase letters, digits and hyphens"));
    }
    let w = format!("[[send]] {name}");
    let Some(tap) = tap else {
        return err(format!("{w}: decode-and-send reads a tap's copy; declare [tap] first"));
    };
    let port = ifname(&s["port"], &format!("{w}.port"))?;
    if !tap.ports.contains(&port) {
        return err(format!("{w}.port: {port} is not one of [tap].ports"));
    }
    let mw = format!("{w}.match");
    let m = as_table(&s["match"], &mw)?;
    keys(m, &mw, &["protocol", "src", "dst", "src_port", "dst_port"], &["protocol"])?;
    if m["protocol"].as_str() != Some("udp") {
        return err(format!("{w}.match.protocol: only \"udp\" is built (TCP stream reassembly is not)"));
    }
    if !["src", "dst", "src_port", "dst_port"].iter().any(|k| m.contains_key(*k)) {
        return err(format!("{w}.match names nothing but the protocol; declare at least one address or port"));
    }
    let matcher = Match {
        protocol: "udp".into(),
        src: m.get("src").map(|v| addr(v, &format!("{w}.match.src"))).transpose()?,
        dst: m.get("dst").map(|v| addr(v, &format!("{w}.match.dst"))).transpose()?,
        src_port: opt_port(m, "src_port", &mw)?,
        dst_port: opt_port(m, "dst_port", &mw)?,
    };
    let mut convert = None;
    if let Some(c) = s.get("convert") {
        let cw = format!("{w}.convert");
        let c = as_table(c, &cw)?;
        if c.contains_key("binary") || c.contains_key("sha256") {
            return err(format!(
                "{cw}: goatrope converts with the goat-transformers engine linked into it ({}), not a goat-xf binary; remove `binary` and `sha256`, and declare `packs_sha256` (goatrope packs-digest prints it)",
                crate::engine::describe()
            ));
        }
        let req = ["component", "version", "from", "to", "packs", "packs_sha256"];
        keys(c, &cw, &req, &req)?;
        if c["component"].as_str() != Some("goat-transformers") {
            return err(format!("{cw}.component: only \"goat-transformers\" converts"));
        }
        let version = string(c, "version", &cw)?;
        if version != crate::engine::VERSION {
            return err(format!("{cw}.version is {version}, but the engine linked into this goatrope is {}", crate::engine::describe()));
        }
        convert = Some(Convert {
            sha256: hex64(c, "packs_sha256", &cw)?,

            from_format: string(c, "from", &cw)?,
            to_format: string(c, "to", &cw)?,
            packs: string(c, "packs", &cw)?,
        });
    }
    let to = match &s["to"] {
        Value::Array(a) if !a.is_empty() => a,
        _ => return err(format!("{w}.to must list at least one destination")),
    };
    let to = to.iter().enumerate().map(|(j, d)| destination(d, &format!("{w}.to[{j}]"))).collect::<R<Vec<_>>>()?;
    let capture_mb = if s.contains_key("capture_mb") { int(s, "capture_mb", &w, 1, 1024)? } else { DEFAULT_CAPTURE_MB } as usize;
    Ok(Send { name, port, matcher, convert, to, capture_mb })
}

fn decode(v: &Value, i: usize, tap: Option<&Tap>) -> R<Decode> {
    let w0 = format!("[[decode]] #{}", i + 1);
    let d = as_table(v, &w0)?;
    // publishers: first-bite's record socket is an address and port, so it is declared, not defaulted
    let req = ["name", "component", "binary", "sha256", "version", "ports", "filter", "dictionary", "subscribers", "publishers"];
    keys(d, &w0, &req, &req)?;
    let name = string(d, "name", &w0)?;
    if !is_name(&name) {
        return err(format!("{w0}.name is lowercase letters, digits and hyphens"));
    }
    let w = format!("[[decode]] {name}");
    if d["component"].as_str() != Some("first-bite") {
        return err(format!("{w}.component: only \"first-bite\" decodes"));
    }
    let Some(tap) = tap else {
        return err(format!("{w}: a decoder reads a tap's copy; declare [tap] first"));
    };
    let ports = port_list(&d["ports"], &format!("{w}.ports"), 1, 2)?;
    for p in &ports {
        if !tap.ports.contains(p) {
            return err(format!("{w}.ports: {p} is not one of [tap].ports"));
        }
    }
    Ok(Decode {
        name,
        component: "first-bite".into(),
        binary: string(d, "binary", &w)?,
        sha256: sha(d, &w)?,
        version: string(d, "version", &w)?,
        ports,
        filter: string(d, "filter", &w)?,
        dictionary: string(d, "dictionary", &w)?,
        subscribers: string(d, "subscribers", &w)?,
        publishers: string(d, "publishers", &w)?,
    })
}

/// A WireGuard public key: 44 base64 characters, the last before "=" from the set a 32-byte key allows.
pub fn is_wg_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44
        && b[..42].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && b"AEIMQUYcgkosw480".contains(&b[42])
        && b[43] == b'='
}

fn abs_file(t: &Table, key: &str, where_: &str) -> R<String> {
    let v = string(t, key, where_)?;
    if !v.starts_with('/') || format!("{v}/").contains("/../") {
        return err(format!("{where_}.{key} must be an absolute path"));
    }
    Ok(v)
}

fn endpoint(v: &Value, where_: &str) -> R<String> {
    let Value::String(s) = v else {
        return err(format!("{where_} must be a string \"address:port\""));
    };
    let (host, sep, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, true, p),
        None => ("", false, s.as_str()),
    };
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let name_msg = format!(
        "{where_}: {} must be an IP address and a port; a name is not accepted, because the boundary point is fixed by the declaration",
        pyrepr(v)
    );
    let Some(ip) = parse_ip(host) else {
        return err(name_msg);
    };
    let t = port.trim();
    let n: i64 = match t.strip_prefix('+').unwrap_or(t).replace('_', "").parse() {
        Ok(n) if !t.is_empty() => n,
        _ => return err(name_msg),
    };
    if !sep || !(1..=65535).contains(&n) {
        return err(format!("{where_}: {} must end in a port from 1 to 65535", pyrepr(v)));
    }
    Ok(if ip.is_ipv6() { format!("[{ip}]:{n}") } else { format!("{ip}:{n}") })
}

fn boundary(v: &Value, w: &str) -> R<Boundary> {
    let t = as_table(v, w)?;
    let req = ["listen_port", "private_key_file", "address", "peer_public_key", "peer_endpoint", "peer_address"];
    let mut allowed = req.to_vec();
    allowed.extend(["preshared_key_file", "keepalive_s"]);
    keys(t, w, &allowed, &req)?;
    let port = int(t, "listen_port", w, 1024, 65535)?;
    if port == NETBIRD_PORT {
        return err(format!("{w}.listen_port {NETBIRD_PORT} is the mesh's own WireGuard port; choose another"));
    }
    let a = match &t["address"] {
        Value::String(s) => Iface::parse(s),
        _ => None,
    };
    let Some(a) = a else {
        return err(format!("{w}.address must be an address with a prefix, e.g. 10.200.0.2/30"));
    };
    let peer = addr(&t["peer_address"], &format!("{w}.peer_address"))?;
    let pip = parse_ip(&peer).unwrap();
    if !a.contains(pip) || pip == a.ip {
        return err(format!("{w}.peer_address {peer} must be another address in {}", a.network()));
    }
    match &t["peer_public_key"] {
        Value::String(k) if is_wg_key(k) => {}
        _ => return err(format!("{w}.peer_public_key must be a WireGuard public key (44 base64 characters)")),
    }
    let psk = if t.contains_key("preshared_key_file") { abs_file(t, "preshared_key_file", w)? } else { String::new() };
    let ka = if t.contains_key("keepalive_s") { int(t, "keepalive_s", w, 0, 65535)? } else { 0 };
    Ok(Boundary {
        listen_port: port as u16,
        private_key_file: abs_file(t, "private_key_file", w)?,
        address: a.to_string(),
        peer_public_key: t["peer_public_key"].as_str().unwrap().to_string(),
        peer_endpoint: endpoint(&t["peer_endpoint"], &format!("{w}.peer_endpoint"))?,
        peer_address: peer,
        preshared_key_file: psk,
        keepalive_s: ka as u16,
    })
}

fn relay(v: &Value, tap: Option<&Tap>) -> R<Relay> {
    let w = "[relay]";
    let r = as_table(v, w)?;
    keys(
        r,
        w,
        &["wip", "transport", "boundary", "remote_interface", "link_interface", "link_address", "allow", "proxy", "l2"],
        &["remote_interface", "link_interface", "link_address", "allow"],
    )?;
    let transport = match r.get("transport") {
        None => "mesh".to_string(),
        Some(Value::String(s)) if s == "mesh" || s == "boundary" => s.clone(),
        Some(_) => {
            return err(format!(
                "{w}.transport must be \"mesh\" (an existing WireGuard interface) or \"boundary\" (goatrope's own interface with one peer, the boundary point)"
            ))
        }
    };
    if transport == "boundary" && !r.contains_key("boundary") {
        return err(format!("{w}: transport \"boundary\" needs a [relay.boundary] table"));
    }
    if transport == "mesh" && r.contains_key("boundary") {
        return err(format!("{w}: [relay.boundary] applies only with transport = \"boundary\""));
    }
    let bnd = if transport == "boundary" { Some(boundary(&r["boundary"], &format!("{w}.boundary"))?) } else { None };
    // `wip` was required while the relay was work in progress; it is still accepted and does nothing
    if r.get("wip").is_some_and(|v| v.as_bool().is_none()) {
        return err(format!("{w}.wip must be true or false; it is no longer needed and does nothing"));
    }
    let remote_if = ifname(&r["remote_interface"], &format!("{w}.remote_interface"))?;
    let link_if = ifname(&r["link_interface"], &format!("{w}.link_interface"))?;
    if remote_if == link_if {
        return err(format!("{w}: remote_interface and link_interface must differ"));
    }
    if let Some(tap) = tap {
        for name in [&remote_if, &link_if] {
            if tap.ports.contains(name) {
                let kind = if tap.mode == "listen" {
                    "listen port: a listen port never transmits"
                } else {
                    "tap port: a relay transmits from its own interface, never through the tap's bridge"
                };
                return err(format!("{w}: {name} is a {kind}"));
            }
        }
        if tap.management == link_if {
            return err(format!("{w}.link_interface is the management interface"));
        }
    }
    let link = match &r["link_address"] {
        Value::String(s) => Iface::parse(s),
        _ => None,
    };
    let Some(link) = link else {
        return err(format!("{w}.link_address must be an address with a prefix, e.g. 192.0.2.50/24"));
    };
    let allow = match &r["allow"] {
        Value::Array(a) if !a.is_empty() => a,
        _ => return err(format!("{w}.allow must list at least one rule; everything else is denied")),
    };
    let mut rules = Vec::new();
    for (j, a) in allow.iter().enumerate() {
        let aw = format!("{w}.allow[{j}]");
        let a = as_table(a, &aw)?;
        let direction = match a.get("direction").and_then(|d| d.as_str()) {
            Some(d) if d == "remote-to-link" || d == "both" || d == "link-to-remote" => d.to_string(),
            _ => {
                return err(format!(
                    "{aw}.direction must be \"remote-to-link\", \"both\" (replies from the target only) or \"link-to-remote\" (a machine on the link sends first)"
                ))
            }
        };
        let protocol = match a.get("protocol").and_then(|p| p.as_str()) {
            Some(p) if p == "udp" || p == "tcp" => p.to_string(),
            _ => return err(format!("{aw}.protocol must be \"udp\" or \"tcp\"")),
        };
        if protocol == "tcp" && direction == "both" {
            return err(format!(
                "{aw}: direction \"both\" is refused for TCP: a connection always carries both directions; name who opens it, \"remote-to-link\" or \"link-to-remote\""
            ));
        }
        let l2r = direction == "link-to-remote";
        let mut req = vec!["direction", "protocol", "remote", "listen_port"];
        req.extend(if l2r { ["remote_port", "sources"] } else { ["target", "target_port"] });
        let mut allowed = req.clone();
        allowed.push("link_address");
        if protocol == "tcp" {
            allowed.push("max_connections");
        } else {
            allowed.push("receive_buffer_kb");
        }
        keys(a, &aw, &allowed, &req)?;
        // a machine on the link: one host address, not the relay's own, the network or a broadcast
        let on_link = |v: &Value, wk: &str| -> R<String> {
            let x = addr(v, wk)?;
            let t = parse_ip(&x).unwrap();
            if !link.contains(t) {
                return err(format!("{wk} {x} is not on the link ({})", link.network()));
            }
            if t == link.ip
                || (link.num_addresses() > 2 && (t == link.network_address() || t == link.broadcast_address()))
                || t.is_multicast()
            {
                return err(format!(
                    "{wk} {x} is the relay's own, the network, a broadcast or a multicast address; a rule names one machine"
                ));
            }
            Ok(x)
        };
        let (target, target_port, remote_port, sources) = if l2r {
            let list = match &a["sources"] {
                Value::Array(l) if !l.is_empty() => l,
                _ => {
                    return err(format!(
                        "{aw}.sources must list at least one link address: the link is not authenticated, so the list is the control"
                    ))
                }
            };
            let mut sources = Vec::new();
            for (k, v) in list.iter().enumerate() {
                let x = on_link(v, &format!("{aw}.sources[{k}]"))?;
                if sources.contains(&x) {
                    return err(format!("{aw}.sources: {x} is listed twice"));
                }
                sources.push(x);
            }
            (String::new(), 0, int(a, "remote_port", &aw, 1, 65535)? as u16, sources)
        } else {
            (on_link(&a["target"], &format!("{aw}.target"))?, int(a, "target_port", &aw, 1, 65535)? as u16, 0, vec![])
        };
        let max_connections =
            if a.contains_key("max_connections") { int(a, "max_connections", &aw, 1, 4096)? } else { DEFAULT_MAX_CONNECTIONS } as usize;
        let receive_buffer_kb =
            if a.contains_key("receive_buffer_kb") { int(a, "receive_buffer_kb", &aw, 256, 1 << 20)? } else { DEFAULT_RECEIVE_BUFFER_KB }
                as usize;
        rules.push(RelayRule {
            direction,
            remote: addr(&a["remote"], &format!("{aw}.remote"))?,
            listen_port: int(a, "listen_port", &aw, 1, 65535)? as u16,
            target,
            target_port,
            protocol,
            remote_port,
            sources,
            max_connections,
            receive_buffer_kb,
            link_address: a.get("link_address").map(|v| addr(v, &format!("{aw}.link_address"))).transpose()?,
        });
    }
    let mut seen = BTreeSet::new();
    for rule in &rules {
        // one socket per side, protocol and port: the remote interface, or the relay's link address
        let side = if rule.link_initiated() { "link" } else { "remote" };
        if !seen.insert((side, rule.protocol.clone(), rule.listen_port)) {
            return err(format!("{w}.allow: {} listen_port {} on the {side} side is used twice", rule.protocol, rule.listen_port));
        }
    }
    if let Some(b) = &bnd {
        for rule in &rules {
            if rule.remote != b.peer_address {
                return err(format!(
                    "{w}.allow: remote {} is not the boundary point; with transport \"boundary\" every rule's remote is {}",
                    rule.remote, b.peer_address
                ));
            }
        }
    }
    let proxies = proxies(r, &link, &rules)?;
    let l2 = match r.get("l2") {
        Some(v) => l2_lanes(v, &remote_if, &link_if, tap, bnd.as_ref())?,
        None => vec![],
    };
    Ok(Relay {
        remote_interface: remote_if,
        link_interface: link_if,
        link_address: link.to_string(),
        rules,
        transport,
        boundary: bnd,
        proxies,
        l2,
    })
}

/// `[[relay.proxy]]`: each address is IPv4, one machine's place on the link, used by a rule, and
/// stands for a remote that rule names (ADR 0004 §4).
fn proxies(r: &Table, link: &Iface, rules: &[RelayRule]) -> R<Vec<Proxy>> {
    let list = match r.get("proxy") {
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return err("[[relay.proxy]] must be an array of tables, each with address and remote"),
    };
    let mut out: Vec<Proxy> = Vec::new();
    for (j, p) in list.iter().enumerate() {
        let pw = format!("[[relay.proxy]][{j}]");
        let p = as_table(p, &pw)?;
        keys(p, &pw, &["address", "remote"], &["address", "remote"])?;
        let address = addr(&p["address"], &format!("{pw}.address"))?;
        let ip = parse_ip(&address).unwrap();
        if ip.is_ipv6() {
            return err(format!(
                "{pw}.address {address}: a proxy address is IPv4; IPv6 would need neighbor discovery, which the relay does not do"
            ));
        }
        if !link.contains(ip) {
            return err(format!("{pw}.address {address} is not on the link ({})", link.network()));
        }
        if ip == link.ip
            || (link.num_addresses() > 2 && (ip == link.network_address() || ip == link.broadcast_address()))
            || ip.is_multicast()
        {
            return err(format!("{pw}.address {address} is the relay's own, the network, a broadcast or a multicast address"));
        }
        if let Some(rule) = rules.iter().find(|rule| rule.target == address || rule.sources.contains(&address)) {
            return err(format!(
                "{pw}.address {address} is a machine on the link in the rule on listen_port {} (its target or a source); a proxy address stands for a remote machine",
                rule.listen_port
            ));
        }
        if out.iter().any(|o| o.address == address) {
            return err(format!("{pw}.address {address} is declared twice"));
        }
        let remote = addr(&p["remote"], &format!("{pw}.remote"))?;
        if !rules.iter().any(|rule| rule.remote == remote) {
            return err(format!("{pw}.remote {remote} is the remote of no rule"));
        }
        out.push(Proxy { address, remote });
    }
    for rule in rules {
        let Some(la) = &rule.link_address else { continue };
        let aw = format!("[relay].allow listen_port {}", rule.listen_port);
        match out.iter().find(|p| &p.address == la) {
            None => return err(format!("{aw}: link_address {la} is not a [[relay.proxy]] address")),
            Some(p) if p.remote != rule.remote => {
                return err(format!(
                    "{aw}: link_address {la} stands for {}, not for this rule's remote {}; machines on the link would see one machine's traffic under another's address",
                    p.remote, rule.remote
                ))
            }
            Some(_) => {}
        }
    }
    for p in &out {
        if !rules.iter().any(|rule| rule.link_address.as_deref() == Some(&p.address)) {
            return err(format!("[[relay.proxy]] {}: no rule uses it (link_address); held alone it would only answer ARP", p.address));
        }
    }
    Ok(out)
}

/// Most EtherTypes a lane may list, and most source MACs: every pair is one filter.
pub const L2_MAX_ETHERTYPES: usize = 16;
pub const L2_MAX_MACS: usize = 64;

fn l2_ethertype(v: &Value, w: &str) -> R<u16> {
    let bad = || err(format!("{w}: {} is not an EtherType; write it as a string of four hex digits, e.g. \"0x0806\"", pyrepr(v)));
    let Value::String(s) = v else { return bad() };
    let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else { return bad() };
    if h.len() != 4 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return bad();
    }
    let n = u16::from_str_radix(h, 16).unwrap();
    if n < 0x0600 {
        return err(format!("{w}: {s} is below 0x0600, a frame length (IEEE 802.3), not an EtherType"));
    }
    if [0x8100, 0x88a8, 0x9100].contains(&n) {
        return err(format!(
            "{w}: {s} is a VLAN tag; the filter sees only the outer EtherType, so a tag would carry any EtherType inside it"
        ));
    }
    Ok(n)
}

fn l2_mac(v: &Value, w: &str) -> R<String> {
    let bad = || err(format!("{w}: {} is not a MAC address (six pairs of hex digits joined by colons)", pyrepr(v)));
    let Value::String(s) = v else { return bad() };
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 || !parts.iter().all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit())) {
        return bad();
    }
    let b: Vec<u8> = parts.iter().map(|p| u8::from_str_radix(p, 16).unwrap()).collect();
    if b[0] & 1 == 1 || b.iter().all(|x| *x == 0) {
        return err(format!("{w}: {s} is a group (multicast or broadcast) or all-zero address; a frame's source is one machine"));
    }
    Ok(s.to_lowercase())
}

/// `[[relay.l2]]`. The lane must be accepted by name: it carries the remote side's frames onto the port's link.
fn l2_lanes(v: &Value, remote_if: &str, link_if: &str, tap: Option<&Tap>, bnd: Option<&Boundary>) -> R<Vec<L2>> {
    let items: Vec<Value> = match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    let mut lanes: Vec<L2> = Vec::new();
    for (j, item) in items.iter().enumerate() {
        let w = format!("[[relay.l2]][{j}]");
        let t = as_table(item, &w)?;
        let req = ["name", "port", "peer", "local", "key", "accept_layer2", "ethertypes", "macs"];
        keys(t, &w, &req, &req)?;
        let name = match &t["name"] {
            Value::String(s) if is_name(s) && s.len() <= 11 => s.clone(),
            other => {
                return err(format!(
                    "{w}.name: {} must be 1 to 11 lowercase letters, digits or hyphens; goatrope names the lane's interfaces after it",
                    pyrepr(other)
                ))
            }
        };
        let w = format!("[[relay.l2]] {}", pystr(&name));
        if t["accept_layer2"].as_bool() != Some(true) {
            return err(format!(
                "{w}: accept_layer2 = true is required. A layer-2 lane puts the far side's frames on this port's link: its ARP and \
                 broadcasts, any address it claims, and the tunnel's loss and latency on every frame (ADR 0002, the encrypted \
                 layer-2 tunnel). The declared ethertypes and macs bound it; they do not remove those risks"
            ));
        }
        let port = ifname(&t["port"], &format!("{w}.port"))?;
        if port == link_if || port == remote_if {
            return err(format!(
                "{w}.port {port} is the relay's {} interface; a lane takes a port of its own",
                if port == link_if { "link" } else { "remote" }
            ));
        }
        if let Some(tap) = tap {
            if tap.ports.contains(&port) {
                return err(format!("{w}.port {port} is a tap port; a lane takes a port of its own"));
            }
            if tap.management == port {
                return err(format!("{w}.port {port} is the management interface; a lane takes a port of its own"));
            }
        }
        let peer = addr(&t["peer"], &format!("{w}.peer"))?;
        let local = addr(&t["local"], &format!("{w}.local"))?;
        if peer.contains(':') || local.contains(':') {
            return err(format!("{w}: IPv6 tunnel addresses are not built; peer and local are IPv4"));
        }
        if peer == local {
            return err(format!("{w}: peer and local are the same address"));
        }
        if let Some(b) = bnd {
            let mine = b.address.split('/').next().unwrap_or_default();
            if peer != b.peer_address || local != mine {
                return err(format!(
                    "{w}: with transport \"boundary\", peer is the boundary point ({}) and local is this end's address ({mine})",
                    b.peer_address
                ));
            }
        }
        let key = int(t, "key", &w, 1, u32::MAX as i64)? as u32;
        let ethertypes = match &t["ethertypes"] {
            Value::Array(a) if !a.is_empty() && a.len() <= L2_MAX_ETHERTYPES => {
                a.iter().map(|x| l2_ethertype(x, &format!("{w}.ethertypes"))).collect::<R<Vec<u16>>>()?
            }
            _ => {
                return err(format!(
                    "{w}.ethertypes must list 1 to {L2_MAX_ETHERTYPES} EtherTypes, e.g. [\"0x0806\", \"0x0800\"]; every other EtherType is dropped"
                ))
            }
        };
        let macs = match &t["macs"] {
            Value::Array(a) if !a.is_empty() && a.len() <= L2_MAX_MACS => {
                a.iter().map(|x| l2_mac(x, &format!("{w}.macs"))).collect::<R<Vec<String>>>()?
            }
            _ => {
                return err(format!(
                    "{w}.macs must list 1 to {L2_MAX_MACS} source MAC addresses accepted from across the tunnel; frames from any other are dropped"
                ))
            }
        };
        if ethertypes.iter().collect::<BTreeSet<_>>().len() != ethertypes.len() {
            return err(format!("{w}.ethertypes lists an EtherType twice"));
        }
        if macs.iter().collect::<BTreeSet<_>>().len() != macs.len() {
            return err(format!("{w}.macs lists a MAC address twice"));
        }
        for other in &lanes {
            if other.name == name {
                return err(format!("{w}: the name is used twice"));
            }
            if other.port == port {
                return err(format!("{w}.port {port} is also the port of lane {}", pystr(&other.name)));
            }
            if other.peer == peer && other.local == local && other.key == key {
                return err(format!("{w}: lane {} has the same peer, local and key; each lane needs its own key", pystr(&other.name)));
            }
        }
        lanes.push(L2 { name, port, peer, local, key, ethertypes, macs });
    }
    Ok(lanes)
}

pub fn parse(text: &str, path: &str) -> R<Config> {
    let doc: Table = match text.parse::<Table>() {
        Ok(d) => d,
        Err(e) => return err(format!("{path}: not valid TOML: {}", e.message())),
    };
    keys(&doc, path, &["schema", "tap", "send", "decode", "relay"], &["schema"])?;
    if doc["schema"].as_integer() != Some(1) {
        return err(format!("{path}: schema must be 1"));
    }
    if !doc.contains_key("tap") && !doc.contains_key("relay") {
        return err(format!("{path}: declares no role; declare [tap] or [relay]"));
    }
    let tap = doc.get("tap").map(tap).transpose()?;
    let list = |k: &str| -> Vec<Value> {
        match doc.get(k) {
            Some(Value::Array(a)) => a.clone(),
            Some(other) => vec![other.clone()],
            None => vec![],
        }
    };
    let sends = list("send").iter().enumerate().map(|(i, s)| send(s, i, tap.as_ref())).collect::<R<Vec<_>>>()?;
    let decodes = list("decode").iter().enumerate().map(|(i, d)| decode(d, i, tap.as_ref())).collect::<R<Vec<_>>>()?;
    let mut names: Vec<&String> = sends.iter().map(|s| &s.name).chain(decodes.iter().map(|d| &d.name)).collect();
    let n = names.len();
    names.sort();
    names.dedup();
    if names.len() != n {
        return err(format!("{path}: a [[send]] or [[decode]] name is used twice"));
    }
    let relay = doc.get("relay").map(|r| relay(r, tap.as_ref())).transpose()?;
    Ok(Config { path: path.to_string(), tap, sends, decodes, relay })
}

pub fn load(path: &str) -> R<Config> {
    match std::fs::read(path) {
        Ok(b) => match String::from_utf8(b) {
            Ok(text) => parse(&text, path),
            Err(_) => err(format!("cannot read {path}: invalid UTF-8")),
        },
        Err(e) => err(format!("cannot read {path}: {}", crate::sys::strerror(&e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE: &str = r#"schema = 1
[tap]
mode = "inline"
ports = ["tp0", "tp1"]
management = "eth0"
[tap.record]
ports = ["tp0"]
filter = ""
file_mb = 5
files = 4
"#;

    fn e(text: &str) -> String {
        parse(text, "x.toml").unwrap_err().0
    }

    #[test]
    fn inline_parses() {
        let c = parse(INLINE, "x.toml").unwrap();
        assert_eq!(c.tap.unwrap().record.directory, RECORD_DIR);
    }

    #[test]
    fn messages_match_python() {
        assert!(e(&INLINE.replace("mode = \"inline\"\n", "")).contains("missing required key(s) mode"));
        assert!(e(&INLINE.replace("\"inline\"", "\"fail-open\"")).contains("not 'fail-open'"));
        assert!(e(&INLINE.replace("[\"tp0\", \"tp1\"]", "[\"tp0\"]")).contains("exactly 2"));
        assert!(e(&INLINE.replace("[\"tp0\", \"tp1\"]", "[\"tp0\", \"tp0\"]")).contains("listed twice"));
        assert!(e(&(INLINE.to_string() + "\n[tap.extra]\nx = 1\n")).contains("unknown key"));
        assert!(e(&INLINE.replace("filter = \"\"", "filter = \"udp' or 1\"")).contains("quote"));
    }

    const RELAY: &str = r#"schema = 1
[relay]
remote_interface = "wg0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [{ direction = "both", protocol = "udp", remote = "198.51.100.5", listen_port = 7000, target = "192.0.2.2", target_port = 7000 }]
"#;

    #[test]
    fn relay_wip_is_optional_and_does_nothing() {
        assert!(parse(RELAY, "x.toml").unwrap().tap.is_none());
        let with = |v: &str| RELAY.replace("[relay]\n", &format!("[relay]\nwip = {v}\n"));
        assert!(parse(&with("true"), "x.toml").is_ok());
        assert!(parse(&with("false"), "x.toml").is_ok());
        assert!(e(&with("\"yes\"")).contains("wip must be true or false"));
    }

    const LANE: &str = r#"
[[relay.l2]]
name = "lane0"
port = "lp0"
peer = "198.51.100.5"
local = "198.51.100.1"
key = 4242
accept_layer2 = true
ethertypes = ["0x0806", "0x0800"]
macs = ["02:00:00:00:b0:01"]
"#;

    #[test]
    fn l2_lane_parses_and_refuses() {
        let ok = format!("{RELAY}{LANE}");
        let c = parse(&ok, "x.toml").unwrap();
        let l = &c.relay.unwrap().l2[0];
        assert_eq!((l.key, l.ethertypes.clone(), l.macs[0].as_str()), (4242, vec![0x0806, 0x0800], "02:00:00:00:b0:01"));
        let bad = |from: &str, to: &str| e(&ok.replace(from, to));
        assert!(bad("accept_layer2 = true\n", "").contains("missing required key(s) accept_layer2"));
        assert!(bad("accept_layer2 = true", "accept_layer2 = false").contains("ADR 0002"));
        assert!(bad("[\"0x0806\", \"0x0800\"]", "[]").contains("ethertypes must list"));
        assert!(bad("\"0x0800\"", "\"0x8100\"").contains("VLAN tag"));
        assert!(bad("\"0x0800\"", "\"0x05dc\"").contains("frame length"));
        assert!(bad("\"0x0800\"", "\"0x0806\"").contains("twice"));
        assert!(bad("02:00:00:00:b0:01", "ff:ff:ff:ff:ff:ff").contains("group"));
        assert!(bad("02:00:00:00:b0:01", "02:00:00:00:b0").contains("not a MAC address"));
        assert!(bad("port = \"lp0\"", "port = \"r0\"").contains("relay's link interface"));
        assert!(bad("port = \"lp0\"", "port = \"wg0\"").contains("relay's remote interface"));
        assert!(bad("peer = \"198.51.100.5\"", "peer = \"2001:db8::5\"").contains("IPv6"));
        assert!(bad("key = 4242", "key = 0").contains("key must be a whole number"));
        assert!(bad("name = \"lane0\"", "name = \"a-very-long-name\"").contains("1 to 11"));
        assert!(e(&format!("{ok}{LANE}")).contains("used twice"));
    }

    #[test]
    fn relay_receive_buffer() {
        let r = parse(RELAY, "x.toml").unwrap().relay.unwrap();
        assert_eq!(r.rules[0].receive_buffer_kb, 8192);
        let with = |kb: &str| RELAY.replace("target_port = 7000 }", &format!("target_port = 7000, receive_buffer_kb = {kb} }}"));
        assert_eq!(parse(&with("1024"), "x.toml").unwrap().relay.unwrap().rules[0].receive_buffer_kb, 1024);
        assert!(e(&with("16")).contains("receive_buffer_kb"));
        let tcp = with("1024").replace("\"both\", protocol = \"udp\"", "\"remote-to-link\", protocol = \"tcp\"");
        assert!(e(&tcp).contains("receive_buffer_kb"));
    }

    const SEND: &str = r#"schema = 1
[tap]
mode = "listen"
source = "mirror-port"
ports = ["tp0"]
management = "eth0"
[tap.record]
ports = ["tp0"]
filter = ""
file_mb = 5
files = 4
[[send]]
name = "s"
port = "tp0"
match = { protocol = "udp", dst_port = 5000 }
to = ["udp://127.0.0.1:9000"]
CONVERT
"#;

    #[test]
    fn convert_is_the_linked_engine_only() {
        let c = |line: &str| SEND.replace("CONVERT", line);
        let linked = format!(
            "convert = {{ component = \"goat-transformers\", version = \"{}\", from = \"a\", to = \"b\", packs = \"/p\", packs_sha256 = \"{}\" }}",
            crate::engine::VERSION,
            "0".repeat(64)
        );
        assert!(parse(&c(&linked), "x.toml").is_ok());
        assert!(e(&c(&linked.replace(crate::engine::VERSION, "0.0.1"))).contains("linked into this goatrope"));
        let binary = linked.replace("packs_sha256", "binary = \"/x\", sha256");
        assert!(e(&c(&binary)).contains("not a goat-xf binary"));
    }

    #[test]
    fn relay_tcp_and_link_to_remote() {
        let tcp = RELAY.replace("\"both\", protocol = \"udp\"", "\"remote-to-link\", protocol = \"tcp\"");
        let r = parse(&tcp, "x.toml").unwrap().relay.unwrap();
        assert_eq!((r.rules[0].protocol.as_str(), r.rules[0].max_connections), ("tcp", 64));
        assert!(e(&RELAY.replace("protocol = \"udp\"", "protocol = \"tcp\"")).contains("refused for TCP"));
        let l2r = RELAY.replace(
            "{ direction = \"both\", protocol = \"udp\", remote = \"198.51.100.5\", listen_port = 7000, target = \"192.0.2.2\", target_port = 7000 }",
            "{ direction = \"link-to-remote\", protocol = \"udp\", remote = \"198.51.100.5\", listen_port = 7000, remote_port = 9000, sources = [\"192.0.2.2\"] }",
        );
        let r = parse(&l2r, "x.toml").unwrap().relay.unwrap();
        assert_eq!((r.rules[0].remote_port, r.rules[0].sources.clone()), (9000, vec!["192.0.2.2".to_string()]));
        assert!(e(&l2r.replace(", sources = [\"192.0.2.2\"]", "")).contains("missing required key(s) sources"));
        assert!(e(&l2r.replace("[\"192.0.2.2\"]", "[]")).contains("sources must list"));
        assert!(e(&l2r.replace("[\"192.0.2.2\"]", "[\"192.0.2.50\"]")).contains("the relay's own"));
        assert!(e(&l2r.replace("remote_port = 9000", "remote_port = 9000, target = \"192.0.2.2\"")).contains("unknown key"));
    }

    #[test]
    fn relay_proxy() {
        let proxy = |addr: &str, remote: &str, la: &str| {
            RELAY.replace("target_port = 7000 }", &format!("target_port = 7000, link_address = \"{la}\" }}"))
                + &format!("[[relay.proxy]]\naddress = \"{addr}\"\nremote = \"{remote}\"\n")
        };
        let c = parse(&proxy("192.0.2.60", "198.51.100.5", "192.0.2.60"), "x.toml").unwrap();
        let r = c.relay.unwrap();
        assert_eq!(r.proxies[0].address, "192.0.2.60");
        assert_eq!(r.rules[0].link_address.as_deref(), Some("192.0.2.60"));
        assert!(parse(RELAY, "x.toml").unwrap().relay.unwrap().proxies.is_empty());
        assert!(e(&proxy("2001:db8::60", "198.51.100.5", "2001:db8::60")).contains("a proxy address is IPv4"));
        assert!(e(&proxy("203.0.113.60", "198.51.100.5", "203.0.113.60")).contains("is not on the link"));
        assert!(e(&proxy("192.0.2.50", "198.51.100.5", "192.0.2.50")).contains("the relay's own"));
        assert!(e(&proxy("192.0.2.255", "198.51.100.5", "192.0.2.255")).contains("broadcast"));
        assert!(e(&proxy("192.0.2.2", "198.51.100.5", "192.0.2.2")).contains("is a machine on the link"));
        assert!(e(&proxy("192.0.2.60", "198.51.100.9", "192.0.2.60")).contains("is the remote of no rule"));
        assert!(e(&proxy("192.0.2.60", "198.51.100.5", "192.0.2.61")).contains("is not a [[relay.proxy]] address"));
        let unused = RELAY.to_string() + "[[relay.proxy]]\naddress = \"192.0.2.60\"\nremote = \"198.51.100.5\"\n";
        assert!(e(&unused).contains("no rule uses it"));
        let twice =
            proxy("192.0.2.60", "198.51.100.5", "192.0.2.60") + "[[relay.proxy]]\naddress = \"192.0.2.60\"\nremote = \"198.51.100.5\"\n";
        assert!(e(&twice).contains("declared twice"));
        let extra = proxy("192.0.2.60", "198.51.100.5", "192.0.2.60") + "mac = \"02:00:00:00:00:01\"\n";
        assert!(e(&extra).contains("unknown key"));
    }

    #[test]
    fn iface_math() {
        let i = Iface::parse("192.0.2.50/24").unwrap();
        assert_eq!(i.network(), "192.0.2.0/24");
        assert_eq!(i.broadcast_address().to_string(), "192.0.2.255");
        assert!(i.contains("192.0.2.2".parse().unwrap()));
        assert!(!i.contains("192.0.3.2".parse().unwrap()));
    }

    #[test]
    fn endpoints() {
        assert_eq!(endpoint(&Value::String("203.0.113.7:51900".into()), "w").unwrap(), "203.0.113.7:51900");
        assert_eq!(endpoint(&Value::String("[2001:db8::1]:51900".into()), "w").unwrap(), "[2001:db8::1]:51900");
        assert!(endpoint(&Value::String("example.org:51900".into()), "w").unwrap_err().0.contains("a name is not accepted"));
    }

    #[test]
    fn wg_keys() {
        assert!(is_wg_key("YNqHbfBQKaGvzefSSGy7kBMHjbXIGOGqtyUr0dOmVnM="));
        assert!(!is_wg_key("YNqHbfBQKaGvzefSSGy7kBMHjbXIGOGqtyUr0dOmVnB="));
    }
}
