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
pub const SOURCES: [&str; 3] = ["copper-tap", "mirror-port", "bypass-relay"];
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
    pub binary: String,
    pub sha256: String,
    pub version: String,
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
}

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

#[derive(Debug, Clone)]
pub struct RelayRule {
    pub direction: String,
    pub remote: String,
    pub listen_port: u16,
    pub target: String,
    pub target_port: u16,
    #[allow(dead_code)] // "udp", the one protocol built; kept as declared
    pub protocol: String,
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
    let v = string(table, "sha256", where_)?;
    if v.len() != 64 || !v.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return err(format!("{where_}.sha256 must be 64 lowercase hex digits"));
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
    keys(t, w, &["mode", "ports", "management", "source", "speed_mbps", "record"], &["mode", "ports", "management", "record"])?;
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
    })
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
    keys(s, &w0, &["name", "port", "match", "convert", "to"], &["name", "port", "match", "to"])?;
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
        let req = ["component", "binary", "sha256", "version", "from", "to", "packs"];
        keys(c, &cw, &req, &req)?;
        if c["component"].as_str() != Some("goat-transformers") {
            return err(format!("{cw}.component: only \"goat-transformers\" converts"));
        }
        convert = Some(Convert {
            binary: string(c, "binary", &cw)?,
            sha256: sha(c, &cw)?,
            version: string(c, "version", &cw)?,
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
    Ok(Send { name, port, matcher, convert, to })
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
        &["wip", "transport", "boundary", "remote_interface", "link_interface", "link_address", "allow"],
        &["wip", "remote_interface", "link_interface", "link_address", "allow"],
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
    if r["wip"].as_bool() != Some(true) {
        return err(format!("{w}.wip must be true: the relay is work in progress and transmits on the link"));
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
        let req = ["direction", "protocol", "remote", "listen_port", "target", "target_port"];
        keys(a, &aw, &req, &req)?;
        let direction = match a["direction"].as_str() {
            Some(d) if d == "remote-to-link" || d == "both" => d.to_string(),
            _ => return err(format!("{aw}.direction must be \"remote-to-link\" or \"both\" (replies from the target only)")),
        };
        if a["protocol"].as_str() != Some("udp") {
            return err(format!("{aw}.protocol: only \"udp\" is built"));
        }
        let target = addr(&a["target"], &format!("{aw}.target"))?;
        let t = parse_ip(&target).unwrap();
        if !link.contains(t) {
            return err(format!("{aw}.target {target} is not on the link ({})", link.network()));
        }
        if t == link.ip || (link.num_addresses() > 2 && (t == link.network_address() || t == link.broadcast_address())) || t.is_multicast()
        {
            return err(format!(
                "{aw}.target {target} is the relay's own, the network, a broadcast or a multicast address; a rule names one machine"
            ));
        }
        rules.push(RelayRule {
            direction,
            remote: addr(&a["remote"], &format!("{aw}.remote"))?,
            listen_port: int(a, "listen_port", &aw, 1, 65535)? as u16,
            target,
            target_port: int(a, "target_port", &aw, 1, 65535)? as u16,
            protocol: "udp".into(),
        });
    }
    let mut seen = BTreeSet::new();
    for rule in &rules {
        if !seen.insert(rule.listen_port) {
            return err(format!("{w}.allow: listen_port {} is used twice", rule.listen_port));
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
    Ok(Relay { remote_interface: remote_if, link_interface: link_if, link_address: link.to_string(), rules, transport, boundary: bnd })
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
