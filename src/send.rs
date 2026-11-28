// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Decode-and-send at run time: take the tap's copy, optionally convert, and send.
//!
//! `[[send]]` reads frames on a tap port (receive only), reassembles IPv4 fragments,
//! keeps the UDP datagrams the match names, optionally converts each payload with the
//! goat-transformers engine linked into goatrope (packs pinned by digest), and sends it to UDP, TCP, HTTP or a file. It never
//! sends through a tap port: a destination routed through one is not sent to.
//! `verify-component` checks a pinned first-bite binary and copies it where it runs.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::config::{Config, Destination, Match};
use crate::link;
use crate::sys::strerror;

/// verified copies of pinned binaries, root-owned, executed from here
pub const COMPONENTS: &str = "/var/lib/goatrope/components";

pub fn component_path(sha: &str) -> String {
    format!("{COMPONENTS}/{sha}")
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_file(path: &str) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Hash binary and copy the same bytes to a root-only place, so what was checked is what runs.
/// Returns the copy's path, or None when the binary is not the pinned one.
pub fn install_component(binary: &str, sha: &str) -> Option<String> {
    let data = fs::read(binary).ok()?;
    if sha256_hex(&data) != sha {
        return None;
    }
    let dest = component_path(sha);
    if sha256_file(&dest).as_deref() != Some(sha) {
        fs::create_dir_all(COMPONENTS).ok()?;
        let _ = fs::set_permissions(COMPONENTS, fs::Permissions::from_mode(0o755));
        let tmp = format!("{dest}.new");
        let mut f =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o555).custom_flags(libc::O_NOFOLLOW).open(&tmp).ok()?;
        f.write_all(&data).ok()?;
        f.set_permissions(fs::Permissions::from_mode(0o555)).ok()?;
        f.sync_all().ok()?;
        drop(f);
        fs::rename(&tmp, &dest).ok()?;
    }
    Some(dest)
}

pub fn verify_component(cfg: &Config, kind: &str, name: &str) -> i32 {
    let found = if kind == "decode" { cfg.decodes.iter().find(|d| d.name == name) } else { None };
    let Some(d) = found else {
        eprintln!("goatrope: no [[decode]] {name}");
        return 2;
    };
    if install_component(&d.binary, &d.sha256).is_none() {
        let have = sha256_file(&d.binary).unwrap_or_else(|| "None".into());
        eprintln!("goatrope: {} is not the pinned first-bite {} (sha256 {have})", d.binary, d.version);
        return 1;
    }
    0
}

// ---------------------------------------------------------------- the route guard

/// Every device a destination's addresses leave through, down to the physical port, or an error.
pub fn destination_devices(host: &str) -> Result<BTreeSet<String>, String> {
    let addrs: Vec<SocketAddr> = match (host, 0u16).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => return Err(format!("cannot resolve {host}: {}", strerror(&e))),
    };
    if addrs.is_empty() {
        return Err(format!("cannot resolve {host}: no address"));
    }
    let mut devs = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for a in addrs {
        let ip = a.ip();
        if !seen.insert(ip) {
            continue;
        }
        let scope = match a {
            SocketAddr::V6(v6) if v6.scope_id() != 0 => link::ifname_of(v6.scope_id()),
            _ => None,
        };
        let found = link::peer_devices(&ip.to_string(), scope.as_deref());
        if found.is_empty() {
            return Err(format!("no route to {ip}"));
        }
        devs.extend(found);
    }
    Ok(devs)
}

// ---------------------------------------------------------------- frames

/// IPv4 reassembly, bounded: 30 s, 256 datagrams and 4 MiB in flight. Only fragments whose
/// addresses the match allows are held.
pub struct Fragments {
    pending: HashMap<(String, String, u16), Pending>,
    bytes: usize,
}

struct Pending {
    t: Instant,
    parts: std::collections::BTreeMap<usize, Vec<u8>>,
    end: Option<usize>,
}

impl Default for Fragments {
    fn default() -> Self {
        Self::new()
    }
}

impl Fragments {
    pub const MAX_BYTES: usize = 4 << 20;

    pub fn new() -> Self {
        Fragments { pending: HashMap::new(), bytes: 0 }
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.pending.values().map(|e| e.parts.values().map(Vec::len).sum::<usize>()).sum()
    }

    pub fn add(&mut self, key: (String, String, u16), offset: usize, more: bool, data: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let old: Vec<_> =
            self.pending.iter().filter(|(_, v)| now.duration_since(v.t) > Duration::from_secs(30)).map(|(k, _)| k.clone()).collect();
        for k in old {
            if let Some(e) = self.pending.remove(&k) {
                self.bytes -= e.parts.values().map(Vec::len).sum::<usize>();
            }
        }
        if self.pending.len() > 256 || self.bytes + data.len() > Self::MAX_BYTES || offset + data.len() > 65535 {
            self.pending.clear();
            self.bytes = 0;
            if offset + data.len() > 65535 {
                return None;
            }
        }
        let e = self.pending.entry(key.clone()).or_insert_with(|| Pending { t: now, parts: Default::default(), end: None });
        let prev = e.parts.get(&offset).map(Vec::len).unwrap_or(0);
        self.bytes = self.bytes + data.len() - prev;
        e.parts.insert(offset, data.to_vec());
        if !more {
            e.end = Some(offset + data.len());
        }
        let end = e.end?;
        let mut buf = Vec::new();
        let mut pos = 0;
        for (off, part) in &e.parts {
            if *off != pos {
                return None;
            }
            buf.extend_from_slice(part);
            pos = off + part.len();
        }
        if pos != end {
            return None;
        }
        if let Some(e) = self.pending.remove(&key) {
            self.bytes -= e.parts.values().map(Vec::len).sum::<usize>();
        }
        Some(buf)
    }
}

pub struct Datagram {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub payload: Vec<u8>,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn slice(b: &[u8], from: usize, to: usize) -> &[u8] {
    let to = to.min(b.len());
    if from >= to {
        &[]
    } else {
        &b[from..to]
    }
}

/// The UDP datagram in an Ethernet frame, or None. Fragments of datagrams whose
/// addresses m excludes are dropped before reassembly.
pub fn parse(frame: &[u8], frags: &mut Fragments, m: Option<&Match>) -> Option<Datagram> {
    if frame.len() < 14 {
        return None;
    }
    let mut et = be16(frame, 12);
    let mut off = 14;
    while (et == 0x8100 || et == 0x88A8) && frame.len() >= off + 4 {
        et = be16(frame, off + 2);
        off += 4;
    }
    let (src, dst, body): (String, String, Vec<u8>) = if et == 0x0800 {
        if frame.len() < off + 20 {
            return None;
        }
        let ihl = ((frame[off] & 0x0F) as usize) * 4;
        let total = be16(frame, off + 2) as usize;
        let ident = be16(frame, off + 4);
        let fl = be16(frame, off + 6);
        let proto = frame[off + 9];
        let src = IpAddr::from(<[u8; 4]>::try_from(&frame[off + 12..off + 16]).ok()?).to_string();
        let dst = IpAddr::from(<[u8; 4]>::try_from(&frame[off + 16..off + 20]).ok()?).to_string();
        if proto != 17 {
            return None;
        }
        let mut body = slice(frame, off + ihl, off + total).to_vec();
        let foff = ((fl & 0x1FFF) as usize) * 8;
        let more = fl & 0x2000 != 0;
        if foff != 0 || more {
            if let Some(m) = m {
                if m.src.as_ref().is_some_and(|s| *s != src) || m.dst.as_ref().is_some_and(|d| *d != dst) {
                    return None;
                }
            }
            body = frags.add((src.clone(), dst.clone(), ident), foff, more, &body)?;
        }
        (src, dst, body)
    } else if et == 0x86DD {
        if frame.len() < off + 40 {
            return None;
        }
        let plen = be16(frame, off + 4) as usize;
        if frame[off + 6] != 17 {
            return None;
        }
        let src = IpAddr::from(<[u8; 16]>::try_from(&frame[off + 8..off + 24]).ok()?).to_string();
        let dst = IpAddr::from(<[u8; 16]>::try_from(&frame[off + 24..off + 40]).ok()?).to_string();
        (src, dst, slice(frame, off + 40, off + 40 + plen).to_vec())
    } else {
        return None;
    };
    if body.len() < 8 {
        return None;
    }
    let sport = be16(&body, 0);
    let dport = be16(&body, 2);
    let ulen = be16(&body, 4) as usize;
    let payload = if ulen >= 8 { slice(&body, 8, ulen).to_vec() } else { body[8..].to_vec() };
    Some(Datagram { src, dst, sport, dport, payload })
}

pub fn matches(m: &Match, d: &Datagram) -> bool {
    m.src.as_ref().is_none_or(|s| *s == d.src)
        && m.dst.as_ref().is_none_or(|s| *s == d.dst)
        && m.src_port.is_none_or(|p| p == d.sport)
        && m.dst_port.is_none_or(|p| p == d.dport)
}

// ---------------------------------------------------------------- JSON as Python writes it

pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A float as Python's repr prints it: the shortest text that reads back the same, with ".0" on whole numbers.
pub fn py_float(x: f64) -> String {
    let s = format!("{x}");
    if s.contains('.') || s.contains('e') || s.contains("inf") || s.contains("NaN") {
        s
    } else {
        format!("{s}.0")
    }
}

fn now_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

// ---------------------------------------------------------------- sinks

pub struct Meta {
    pub feed: String,
    pub time: f64,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

pub struct Sink {
    pub d: Destination,
    taken: BTreeSet<String>,
    udp: Option<UdpSocket>,
    tcp: Option<TcpStream>,
    file: Option<File>,
    http: Option<ureq::Agent>,
}

impl Sink {
    pub fn new(d: Destination, taken: BTreeSet<String>) -> Sink {
        Sink { d, taken, udp: None, tcp: None, file: None, http: None }
    }

    fn guard(&self) -> Result<(), String> {
        if let Some(h) = &self.d.host {
            let devs = destination_devices(h).map_err(|e| format!("{}: {e}; not sending", self.d.url))?;
            let bad: Vec<&String> = devs.iter().filter(|d| self.taken.contains(*d)).collect();
            if !bad.is_empty() {
                return Err(format!(
                    "{} is reached through tap port {}; not sending",
                    self.d.url,
                    bad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
        Ok(())
    }

    fn target(&self) -> String {
        let h = self.d.host.as_deref().unwrap_or("");
        let p = self.d.port.unwrap_or(0);
        if h.contains(':') {
            format!("[{h}]:{p}")
        } else {
            format!("{h}:{p}")
        }
    }

    pub fn send(&mut self, payload: &[u8], meta: &Meta) -> Result<(), String> {
        match self.d.scheme.as_str() {
            "udp" => {
                if self.udp.is_none() {
                    self.guard()?;
                    let bind = if self.d.host.as_deref().unwrap_or("").contains(':') { "[::]:0" } else { "0.0.0.0:0" };
                    self.udp = Some(UdpSocket::bind(bind).map_err(|e| strerror(&e))?);
                }
                self.udp.as_ref().unwrap().send_to(payload, self.target()).map_err(|e| strerror(&e))?;
                Ok(())
            }
            "tcp" => {
                if self.tcp.is_none() {
                    self.guard()?;
                    let addr: SocketAddr = self.target().parse().map_err(|_| "bad address".to_string())?;
                    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| strerror(&e))?;
                    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                    self.tcp = Some(s);
                }
                let mut data = Vec::with_capacity(payload.len() + 4);
                if self.d.framing.as_deref() == Some("len32be") {
                    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                }
                data.extend_from_slice(payload);
                if let Err(e) = self.tcp.as_mut().unwrap().write_all(&data) {
                    if let Some(s) = self.tcp.take() {
                        let _ = s.shutdown(Shutdown::Both);
                    }
                    return Err(strerror(&e));
                }
                Ok(())
            }
            "http" | "https" => {
                self.guard()?;
                let agent = self.http.get_or_insert_with(|| {
                    ureq::Agent::config_builder()
                        .max_redirects(0)
                        .http_status_as_error(false)
                        .timeout_global(Some(Duration::from_secs(5)))
                        .build()
                        .into()
                });
                let r = agent
                    .post(&self.d.url)
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Goatrope-Feed", &meta.feed)
                    .send(payload)
                    .map_err(|e| format!("HTTP: {e}"))?;
                let code = r.status().as_u16();
                if (300..400).contains(&code) {
                    let to = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    return Err(format!("HTTP Error {code}: redirect to {to} refused"));
                }
                if code >= 400 {
                    return Err(format!("HTTP Error {code}: {}", r.status().canonical_reason().unwrap_or("")));
                }
                let mut body = r.into_body();
                let _ = body.read_to_vec();
                Ok(())
            }
            "file" => {
                let path = self.d.path.clone().unwrap_or_default();
                if self.file.is_none() {
                    if let Some(dir) = std::path::Path::new(&path).parent() {
                        if !dir.exists() {
                            fs::create_dir_all(dir).map_err(|e| strerror(&e))?;
                            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
                        }
                    }
                    let f = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .mode(0o640)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&path)
                        .map_err(|e| strerror(&e))?;
                    self.file = Some(f);
                }
                let f = self.file.as_mut().unwrap();
                if self.d.format.as_deref() == Some("jsonl") {
                    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
                    let line = format!(
                        "{{\"dport\": {}, \"dst\": {}, \"feed\": {}, \"payload_hex\": {}, \"sport\": {}, \"src\": {}, \"time\": {}}}\n",
                        meta.dport,
                        json_str(&meta.dst),
                        json_str(&meta.feed),
                        json_str(&hex),
                        meta.sport,
                        json_str(&meta.src),
                        py_float(meta.time)
                    );
                    f.write_all(line.as_bytes()).map_err(|e| strerror(&e))?;
                } else {
                    f.write_all(payload).map_err(|e| strerror(&e))?;
                }
                let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                // cut: the file and one older file, at most 2 x max_mb
                if size >= self.d.max_mb.unwrap_or(0) as u64 * 1_000_000 {
                    self.file = None;
                    fs::rename(&path, format!("{path}.1")).map_err(|e| strerror(&e))?;
                }
                Ok(())
            }
            other => Err(format!("{other}: not a destination")),
        }
    }
}

// ---------------------------------------------------------------- the forwarder

fn write_heartbeat(path: &str, matched: u64, sent: u64, errors: u64, now: f64, extra: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.new");
    fs::write(&tmp, format!("{{\"matched\": {matched}, \"sent\": {sent}, \"errors\": {errors}, \"time\": {}{extra}}}", py_float(now)))?;
    fs::rename(&tmp, path)
}

pub fn run_send(cfg: &Config, name: &str) -> i32 {
    let Some(s) = cfg.sends.iter().find(|s| s.name == name) else {
        eprintln!("goatrope: no [[send]] {name}");
        return 2;
    };
    let mut converter = None;
    if let Some(c) = &s.convert {
        match crate::engine::Linked::load(c, &c.sha256) {
            Ok(l) => {
                println!(
                    "goatrope send {name}: {} loaded {} files of {} in {:.3} s; resident {} KiB, peak {} KiB",
                    crate::engine::describe(),
                    l.files,
                    c.packs,
                    l.load_s,
                    l.rss_kib,
                    l.peak_rss_kib
                );
                converter = Some(l);
            }
            Err(e) => {
                eprintln!("goatrope send {name}: {e}");
                return 1;
            }
        }
    }
    let mut taken: BTreeSet<String> = cfg.tap_ports().into_iter().collect();
    taken.insert("goatrope0".into());
    // each destination has its own queue and thread: a slow one drops its own messages, counted,
    // and neither stalls the capture nor the other destinations
    let dests: Vec<Dest> = s.to.iter().map(|d| Dest::start(Sink::new(d.clone(), taken.clone()), name)).collect();
    let mut cap = match crate::capture::Capture::open(&s.port, s.capture_mb) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("goatrope send {name}: {}: {e}", s.port);
            return 1;
        }
    };
    let mut frags = Fragments::new();
    let (mut matched, mut convert_errors) = (0u64, 0u64);
    let mut convert_log = Throttle::default();
    let health = format!("/var/lib/goatrope/send/{name}.health");
    let _ = fs::create_dir_all("/var/lib/goatrope/send");
    let mut last_hb = 0.0f64;
    let urls: Vec<&str> = s.to.iter().map(|d| d.url.as_str()).collect();
    println!(
        "goatrope send {name}: {} udp {} -> {}; capture ring {} MiB ({} frames), {QUEUE} messages queued per destination at most",
        s.port,
        s.matcher,
        urls.join(", "),
        s.capture_mb,
        cap.slots()
    );
    let _ = std::io::stdout().flush();
    let mut timings = crate::engine::Timings::default();
    loop {
        let now = now_f64();
        if now - last_hb >= 2.0 {
            last_hb = now;
            cap.read_stats();
            let sent: u64 = dests.iter().map(|d| d.stats.sent.load(Ordering::Relaxed)).sum();
            let errors: u64 = convert_errors + dests.iter().map(|d| d.stats.errors.load(Ordering::Relaxed)).sum::<u64>();
            let rows: Vec<String> = dests.iter().map(|d| d.json()).collect();
            let mut extra = format!(
                ", \"capture_packets\": {}, \"capture_dropped\": {}, \"capture_truncated\": {}, \"convert_errors\": {convert_errors}, \"destinations\": [{}]",
                cap.packets,
                cap.dropped,
                cap.truncated,
                rows.join(", ")
            );
            if let Some(l) = &converter {
                extra.push_str(&format!(
                    ", \"convert\": {}, \"load\": {{\"seconds\": {:.4}, \"files\": {}, \"rss_kib\": {}, \"peak_rss_kib\": {}}}",
                    timings.json(),
                    l.load_s,
                    l.files,
                    l.rss_kib,
                    l.peak_rss_kib
                ));
            }
            // a full disk: keep forwarding; check reports the stale heartbeat
            if let Err(e) = write_heartbeat(&health, matched, sent, errors, now, &extra) {
                println!("heartbeat: {}", strerror(&e));
            }
            if let Some(line) = convert_log.flush() {
                println!("convert failed: {line}");
            }
            for d in &dests {
                d.flush_log();
            }
            let _ = std::io::stdout().flush();
        }
        cap.next_frames(1000, |frame| {
            // In inline mode a bridge port also shows each frame it transmits (pkttype OUTGOING);
            // that is the other direction of the link, so it is kept.
            let Some(d) = parse(frame, &mut frags, Some(&s.matcher)) else {
                return;
            };
            if !matches(&s.matcher, &d) {
                return;
            }
            matched += 1;
            let meta = Meta {
                feed: name.to_string(),
                time: round6(now_f64()),
                src: d.src.clone(),
                dst: d.dst.clone(),
                sport: d.sport,
                dport: d.dport,
            };
            let out = match converter.as_ref() {
                Some(conv) => {
                    let t = Instant::now();
                    let r = conv.convert(&d.payload);
                    timings.record(t.elapsed().as_nanos() as u64);
                    match r {
                        Ok(o) => o,
                        Err(e) => {
                            convert_errors += 1;
                            convert_log.note(&e);
                            return;
                        }
                    }
                }
                None => d.payload,
            };
            let msg = std::sync::Arc::new((out, meta));
            for dest in &dests {
                dest.offer(&msg);
            }
        });
    }
}

/// Messages queued for one destination at most; a full queue drops the newest, counted.
pub const QUEUE: usize = 8192;

/// One error line per destination (or for conversions) every 10 s at most, with the count of
/// those not printed.
#[derive(Default)]
struct Throttle {
    last: Option<Instant>,
    held: u64,
    first: Option<String>,
}

impl Throttle {
    /// An error happened: print it now if the last line is 10 s old, else count it.
    fn note(&mut self, e: &str) {
        if self.last.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
            println!("{e}");
            let _ = std::io::stdout().flush();
            self.last = Some(Instant::now());
        } else {
            self.held += 1;
            self.first.get_or_insert_with(|| e.to_string());
        }
    }
    /// The line for the errors held back, once 10 s have passed.
    fn flush(&mut self) -> Option<String> {
        if self.held == 0 || self.last.is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
            return None;
        }
        let line = format!("{} more like: {}", self.held, self.first.take().unwrap_or_default());
        self.held = 0;
        self.last = Some(Instant::now());
        Some(line)
    }
}

#[derive(Default)]
struct DestStats {
    sent: AtomicU64,
    errors: AtomicU64,
    dropped: AtomicU64,
}

/// A destination with its own bounded queue and thread.
struct Dest {
    url: String,
    tx: SyncSender<std::sync::Arc<(Vec<u8>, Meta)>>,
    stats: std::sync::Arc<DestStats>,
    log: std::sync::Arc<std::sync::Mutex<Throttle>>,
}

impl Dest {
    fn start(mut sink: Sink, feed: &str) -> Dest {
        let (tx, rx) = sync_channel::<std::sync::Arc<(Vec<u8>, Meta)>>(QUEUE);
        let stats = std::sync::Arc::new(DestStats::default());
        let log = std::sync::Arc::new(std::sync::Mutex::new(Throttle::default()));
        let url = sink.d.url.clone();
        let (st, lg, u) = (stats.clone(), log.clone(), url.clone());
        let _ = std::thread::Builder::new().name(format!("send-{feed}")).spawn(move || {
            for m in rx {
                match sink.send(&m.0, &m.1) {
                    Ok(()) => {
                        st.sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        st.errors.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut l) = lg.lock() {
                            l.note(&format!("{u}: {e}"));
                        }
                    }
                }
            }
        });
        Dest { url, tx, stats, log }
    }

    /// Queue a message; when the queue is full, drop it and count it.
    fn offer(&self, m: &std::sync::Arc<(Vec<u8>, Meta)>) {
        if self.tx.try_send(m.clone()).is_err() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut l) = self.log.lock() {
                l.note(&format!("{}: its queue is full ({QUEUE} messages); dropping", self.url));
            }
        }
    }

    fn flush_log(&self) {
        if let Ok(mut l) = self.log.lock() {
            if let Some(line) = l.flush() {
                println!("{line}");
            }
        }
    }

    fn json(&self) -> String {
        format!(
            "{{\"url\": {}, \"sent\": {}, \"errors\": {}, \"dropped\": {}}}",
            json_str(&self.url),
            self.stats.sent.load(Ordering::Relaxed),
            self.stats.errors.load(Ordering::Relaxed),
            self.stats.dropped.load(Ordering::Relaxed)
        )
    }
}

// ---------------------------------------------------------------- install time: units, check, status

const UNITS: &str = "/etc/systemd/system";
const BIN: &str = "/usr/local/sbin/goatrope";
const ETC: &str = "/etc/goatrope";

pub fn units(cfg: &Config) -> Vec<String> {
    let mut u: Vec<String> = cfg.sends.iter().map(|s| format!("goatrope-send@{}.service", s.name)).collect();
    u.extend(cfg.decodes.iter().map(|d| format!("goatrope-decode@{}.service", d.name)));
    u
}

/// The files decode-and-send needs, and the mode of each file not written 0644.
pub fn render(cfg: &Config) -> (std::collections::BTreeMap<String, String>, HashMap<String, u32>) {
    let mut files = std::collections::BTreeMap::new();
    let mut modes = HashMap::new();
    let h = format!("# Written by goatrope {} from {ETC}/goatrope.toml. goatrope uninstall removes it; do not edit.\n", crate::version());
    if !cfg.sends.is_empty() {
        files.insert(
            format!("{UNITS}/goatrope-send@.service"),
            format!(
                "{h}[Unit]
Description=goatrope: decode-and-send %i
After=goatrope-ports.service network-online.target
Wants=goatrope-ports.service

[Service]
ExecStart={BIN} run-send %i --config {ETC}/goatrope.toml
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/goatrope
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"
            ),
        );
    }
    if !cfg.decodes.is_empty() {
        files.insert(
            format!("{UNITS}/goatrope-decode@.service"),
            format!(
                "{h}[Unit]
Description=goatrope: first-bite decoder %i
After=goatrope-ports.service
Wants=goatrope-ports.service

[Service]
EnvironmentFile={ETC}/decode-%i.env
# \"+\": verification runs as root; it copies the pinned binary to {COMPONENTS}, and the copy runs.
ExecStartPre=+{BIN} verify-component decode %i --config {ETC}/goatrope.toml
ExecStart=/bin/sh -c 'exec \"$$MIND\" $$PORTS --dictionary \"$$DICTIONARY\" $${{FILTER:+--filter \"$$FILTER\"}}'
Restart=always
RestartSec=5
# The decoder parses link traffic: its own user, capture capabilities only, a read-only system.
DynamicUser=yes
StateDirectory=goatrope-decode-%i
WorkingDirectory=/var/lib/goatrope-decode-%i
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK AF_UNIX

[Install]
WantedBy=multi-user.target
"
            ),
        );
        for d in &cfg.decodes {
            let path = format!("{ETC}/decode-{}.env", d.name);
            // single-quoted: the declaration refuses quotes, backslashes and control characters
            files.insert(
                path.clone(),
                format!(
                    "{h}MIND='{}'\nPORTS='{}'\nDICTIONARY='{}'\nFILTER='{}'\nSUBSCRIBER_CONFIG_PATH='{}'\nPUBLISHER_CONFIG_PATH='{}'\n",
                    component_path(&d.sha256),
                    d.ports.join(" "),
                    d.dictionary,
                    d.filter,
                    d.subscribers,
                    d.publishers
                ),
            );
            modes.insert(path, 0o640);
        }
    }
    (files, modes)
}

/// Destinations whose route leaves through a tap port: sending there would transmit on the link.
pub fn refuse_tap_routes(cfg: &Config) -> Vec<String> {
    let mut taken: BTreeSet<String> = cfg.tap_ports().into_iter().collect();
    taken.insert("goatrope0".into());
    let mut bad = Vec::new();
    for s in &cfg.sends {
        for d in &s.to {
            if !matches!(d.scheme.as_str(), "udp" | "tcp" | "http" | "https") {
                continue;
            }
            let Some(h) = &d.host else { continue };
            match destination_devices(h) {
                Err(e) => bad.push(format!("[[send]] {}: {}: {e}", s.name, d.url)),
                Ok(devs) => {
                    let hit: Vec<&str> = devs.iter().filter(|x| taken.contains(*x)).map(String::as_str).collect();
                    if !hit.is_empty() {
                        bad.push(format!("[[send]] {}: {} is reached through {}, a tap port", s.name, d.url, hit.join(", ")));
                    }
                }
            }
        }
    }
    bad
}

pub fn start(cfg: &Config) {
    for u in units(cfg) {
        crate::sysutil::systemctl(&["enable", &u]);
        crate::sysutil::systemctl(&["restart", &u]);
    }
}

/// The heartbeat as the forwarder wrote it, and its parsed value.
fn heartbeat(name: &str) -> Option<(String, serde_json::Value)> {
    let s = crate::sysutil::read(&format!("/var/lib/goatrope/send/{name}.health"))?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    Some((s, v))
}

pub fn check(cfg: &Config) -> Vec<crate::tap::Item> {
    use crate::tap::item;
    let mut items = Vec::new();
    for s in &cfg.sends {
        if let Some(c) = &s.convert {
            let (h, what) =
                (crate::engine::digest(c).ok(), format!("linked {}, packs_sha256 {}", crate::engine::describe(), &c.sha256[..12]));
            item(
                &mut items,
                format!("pin:send:{}", s.name),
                Some(h.as_deref() == Some(c.sha256.as_str())),
                what,
                h.map(|x| x[..12].to_string()).unwrap_or_else(|| "absent".into()),
            );
        }
        let hb = heartbeat(&s.name);
        let fresh = hb.as_ref().map(|(_, v)| now_f64() - v.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0) < 30.0).unwrap_or(false);
        item(
            &mut items,
            format!("send-health:{}", s.name),
            Some(fresh),
            "heartbeat within 30 s",
            hb.map(|(raw, _)| raw).unwrap_or_else(|| "none".into()),
        );
    }
    for d in &cfg.decodes {
        let h = sha256_file(&d.binary);
        item(
            &mut items,
            format!("pin:decode:{}", d.name),
            Some(h.as_deref() == Some(d.sha256.as_str())),
            format!("first-bite {} sha256 {}", d.version, &d.sha256[..12]),
            h.map(|x| x[..12].to_string()).unwrap_or_else(|| "absent".into()),
        );
    }
    for b in refuse_tap_routes(cfg) {
        item(&mut items, "send-route", Some(false), "no destination through a tap port", b);
    }
    items
}

pub fn status(cfg: &Config) {
    for s in &cfg.sends {
        let hb = heartbeat(&s.name).map(|x| x.1).unwrap_or(serde_json::Value::Null);
        let n = |k: &str| hb.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let urls: Vec<&str> = s.to.iter().map(|d| d.url.as_str()).collect();
        println!(
            "  send   {:<14} {:<9} matched={} sent={} errors={} -> {}",
            s.name,
            crate::sysutil::unit_active(&format!("goatrope-send@{}.service", s.name)),
            n("matched"),
            n("sent"),
            n("errors"),
            urls.join(", ")
        );
        println!(
            "         capture: {} frame(s) in the {} MiB ring, {} dropped by the kernel (ring full)",
            n("capture_packets"),
            s.capture_mb,
            n("capture_dropped")
        );
        for d in hb.get("destinations").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let k = |x: &str| d.get(x).and_then(|v| v.as_u64()).unwrap_or(0);
            println!(
                "         {}: {} sent, {} could not be sent, {} dropped (queue full)",
                d.get("url").and_then(|v| v.as_str()).unwrap_or(""),
                k("sent"),
                k("errors"),
                k("dropped")
            );
        }
        if let (Some(c), Some(l)) = (hb.get("convert"), hb.get("load")) {
            let f = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
            println!(
                "         convert: {} message(s), p50 {:.0} us, p99 {:.0} us, max {:.0} us; packs loaded in {:.3} s, resident {:.0} KiB",
                f(c, "count"),
                f(c, "p50_us"),
                f(c, "p99_us"),
                f(c, "max_us"),
                f(l, "seconds"),
                f(l, "rss_kib")
            );
        }
    }
    for d in &cfg.decodes {
        println!(
            "  decode {:<14} {:<9} first-bite {} on {}",
            d.name,
            crate::sysutil::unit_active(&format!("goatrope-decode@{}.service", d.name)),
            d.version,
            d.ports.join(" ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_holds_errors_for_10_s() {
        let mut t = Throttle::default();
        t.note("first");
        for _ in 0..1000 {
            t.note("again");
        }
        assert_eq!(t.held, 1000);
        assert!(t.flush().is_none(), "within 10 s nothing more is printed");
        t.last = Some(Instant::now() - Duration::from_secs(11));
        assert_eq!(t.flush().as_deref(), Some("1000 more like: again"));
        assert_eq!(t.held, 0);
    }

    #[test]
    fn reassembly_is_bounded() {
        let mut f = Fragments::new();
        for i in 0..250u16 {
            for j in 0..40usize {
                f.add(("a".into(), "b".into(), i), j * 1480, true, &[b'x'; 1480]);
            }
        }
        assert!(f.held() <= 4 << 20, "{} bytes held", f.held());
    }

    #[test]
    fn reassembles_two_fragments() {
        let mut f = Fragments::new();
        assert!(f.add(("a".into(), "b".into(), 1), 0, true, &[1; 8]).is_none());
        assert_eq!(f.add(("a".into(), "b".into(), 1), 8, false, &[2; 4]).unwrap(), [1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2]);
    }

    #[test]
    fn floats_print_as_python() {
        assert_eq!(py_float(1764000000.0), "1764000000.0");
        assert_eq!(py_float(1764000000.123456), "1764000000.123456");
    }

    #[test]
    fn parses_udp_in_ipv4() {
        let mut fr = vec![0u8; 14];
        fr[12] = 0x08;
        let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2];
        let udp = [0x13, 0x88, 0x13, 0x89, 0, 11, 0, 0, b'a', b'b', b'c'];
        let total = (ip.len() + udp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        fr.extend_from_slice(&ip);
        fr.extend_from_slice(&udp);
        let d = parse(&fr, &mut Fragments::new(), None).unwrap();
        assert_eq!(
            (d.src.as_str(), d.dst.as_str(), d.sport, d.dport, d.payload.as_slice()),
            ("192.0.2.1", "192.0.2.2", 5000, 5001, &b"abc"[..])
        );
    }
}
