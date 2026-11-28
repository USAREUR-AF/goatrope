// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Address proxy (docs/adr/0004 §4): a remote machine appears on the link under a local
//! address of its own.
//!
//! Each `[[relay.proxy]]` address is added to the relay's link interface as a /32 with
//! `noprefixroute`, so routing is unchanged, and only while the remote's tunnel is up: the
//! WireGuard peer on the remote interface whose allowed IPs hold the remote has a handshake
//! younger than 180 s. Before the address is added, an ARP probe (RFC 5227: three probes from
//! 0.0.0.0, then a 2 s wait) must find no other holder; after it is added, two gratuitous ARP
//! announcements are sent. The kernel then answers ARP for it, and a rule whose `link_address`
//! names it sends from it. When the tunnel goes stale, or another machine claims the address,
//! the relay removes it. It removes every address it added when it stops.
//!
//! A rule's sockets on the address are bound with IP_FREEBIND, so they exist while it is absent:
//! the kernel delivers to them only while it is on the interface, and the relay sends from it
//! only while it holds it (otherwise a send error); TCP connections on it close when it is given up.
//!
//! Nothing else changes: IP forwarding stays off and no route names the remote, so the kernel
//! never routes to it. Only the rules' sockets on the address forward anything.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::{Proxy as ProxyDecl, Relay};
use crate::nl;
use crate::sys;

// RFC 5227 §1.1
const PROBE_WAIT_MS: u64 = 1000;
const PROBE_NUM: u8 = 3;
const PROBE_MIN_MS: u64 = 1000;
const PROBE_MAX_MS: u64 = 2000;
const ANNOUNCE_WAIT_MS: u64 = 2000;
const ANNOUNCE_NUM: u8 = 2;
const ANNOUNCE_INTERVAL_MS: u64 = 2000;
/// After a conflict, the relay waits this long before it probes again.
const RETRY_AFTER_CONFLICT_S: u64 = 10;
const ETH_P_ARP: u16 = 0x0806;

// ---------------------------------------------------------------- ARP on the link (AF_PACKET)

/// One ARP packet for IPv4 over Ethernet, as RFC 826 lays it out after the Ethernet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: Ipv4Addr,
    pub tha: [u8; 6],
    pub tpa: Ipv4Addr,
}

impl Arp {
    pub fn encode(&self) -> [u8; 28] {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
        b[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        b[4] = 6;
        b[5] = 4;
        b[6..8].copy_from_slice(&self.op.to_be_bytes());
        b[8..14].copy_from_slice(&self.sha);
        b[14..18].copy_from_slice(&self.spa.octets());
        b[18..24].copy_from_slice(&self.tha);
        b[24..28].copy_from_slice(&self.tpa.octets());
        b
    }

    /// None unless it is an ARP request or reply for IPv4 over Ethernet.
    pub fn decode(b: &[u8]) -> Option<Arp> {
        if b.len() < 28 || b[0..6] != [0, 1, 8, 0, 6, 4] {
            return None;
        }
        let op = u16::from_be_bytes([b[6], b[7]]);
        if op != 1 && op != 2 {
            return None;
        }
        let ip = |o: usize| Ipv4Addr::new(b[o], b[o + 1], b[o + 2], b[o + 3]);
        let mac = |o: usize| -> [u8; 6] { b[o..o + 6].try_into().unwrap() };
        Some(Arp { op, sha: mac(8), spa: ip(14), tha: mac(18), tpa: ip(24) })
    }

    /// RFC 5227 §2.1.1: a probe asks for the address from 0.0.0.0, so no host caches the prober.
    pub fn probe(mac: [u8; 6], ip: Ipv4Addr) -> Arp {
        Arp { op: 1, sha: mac, spa: Ipv4Addr::UNSPECIFIED, tha: [0; 6], tpa: ip }
    }

    /// RFC 5227 §2.3: an announcement is a request with the address as sender and target.
    pub fn announce(mac: [u8; 6], ip: Ipv4Addr) -> Arp {
        Arp { op: 1, sha: mac, spa: ip, tha: [0; 6], tpa: ip }
    }
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let v: Vec<u8> = s.split(':').map(|x| u8::from_str_radix(x, 16)).collect::<Result<_, _>>().ok()?;
    v.try_into().ok()
}

/// A packet socket on the link interface that sends and receives ARP only.
struct ArpSock {
    fd: OwnedFd,
    ifindex: i32,
}

fn sockaddr_ll(ifindex: i32, dst: Option<[u8; 6]>) -> libc::sockaddr_ll {
    // SAFETY: an all-zero sockaddr_ll is valid; the fields are filled below.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ARP.to_be();
    sa.sll_ifindex = ifindex;
    if let Some(d) = dst {
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&d);
    }
    sa
}

impl ArpSock {
    fn open(ifname: &str) -> io::Result<ArpSock> {
        let c = std::ffi::CString::new(ifname).map_err(|_| io::Error::from_raw_os_error(libc::ENODEV))?;
        // SAFETY: c is a valid C string.
        let ifindex = unsafe { libc::if_nametoindex(c.as_ptr()) } as i32;
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain socket(2) call; the descriptor is owned by the OwnedFd below.
        let fd =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, ETH_P_ARP.to_be() as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh socket that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let sa = sockaddr_ll(ifindex, None);
        // SAFETY: sa is a sockaddr_ll of the size given.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ArpSock { fd, ifindex })
    }

    fn send(&self, a: &Arp) -> io::Result<()> {
        let b = a.encode();
        let sa = sockaddr_ll(self.ifindex, Some([0xff; 6]));
        // SAFETY: b and sa are valid for the lengths given.
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                b.as_ptr() as *const libc::c_void,
                b.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The next ARP packet another machine sent; None when there is none waiting. Frames this
    /// machine sent itself (PACKET_OUTGOING) are skipped.
    fn recv(&self) -> Option<Arp> {
        let mut b = [0u8; 128];
        loop {
            let mut sa = sockaddr_ll(0, None);
            let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: b and sa are valid for the lengths given.
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    b.as_mut_ptr() as *mut libc::c_void,
                    b.len(),
                    0,
                    &mut sa as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            if n < 0 {
                return None;
            }
            if sa.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            if let Some(a) = Arp::decode(&b[..n as usize]) {
                return Some(a);
            }
        }
    }
}

// ---------------------------------------------------------------- the tunnel

fn wall_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn jitter_ms(lo: u64, hi: u64) -> u64 {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        return lo;
    }
    lo + u64::from_le_bytes(b) % (hi - lo + 1)
}

// ---------------------------------------------------------------- each proxy address

/// What a rule shares with the relay about its proxy address: whether it is held, and the TCP
/// connections open on it, which the relay closes before it removes the address (so their FIN
/// still leaves from an address the machine has).
#[derive(Clone)]
pub struct Hold {
    flag: Arc<AtomicBool>,
    conns: Arc<Mutex<Conns>>,
}

/// The last id given out, and the open connections by id.
type Conns = (u64, Vec<(u64, std::net::TcpStream)>);

impl Hold {
    fn new() -> Hold {
        Hold { flag: Arc::new(AtomicBool::new(false)), conns: Arc::new(Mutex::new((0, Vec::new()))) }
    }

    pub fn held(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Record a connection's link-side stream; None when it cannot be (it is then not made).
    pub fn register(&self, s: &std::net::TcpStream) -> Option<u64> {
        let c = s.try_clone().ok()?;
        let mut g = self.conns.lock().ok()?;
        g.0 += 1;
        let id = g.0;
        g.1.push((id, c));
        Some(id)
    }

    pub fn unregister(&self, id: u64) {
        if let Ok(mut g) = self.conns.lock() {
            g.1.retain(|(i, _)| *i != id);
        }
    }

    /// Mark the address not held and close every connection on it, both ways.
    fn release(&self) -> usize {
        self.flag.store(false, Ordering::SeqCst);
        let Ok(mut g) = self.conns.lock() else { return 0 };
        for (_, s) in g.1.iter() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        let n = g.1.len();
        g.1.clear();
        n
    }
}

#[derive(Debug, Clone, PartialEq)]
enum State {
    /// not held; probing starts once the tunnel is up and `retry` has passed
    Down { retry: Option<Instant> },
    /// RFC 5227 probing: `sent` probes so far, the next step at `next`
    Probing { sent: u8, next: Instant },
    /// on the interface; `announce_left` announcements still to send at `next`
    Held { announce_left: u8, next: Instant },
}

struct One {
    decl: ProxyDecl,
    ip: Ipv4Addr,
    remote: IpAddr,
    state: State,
    why: String,
    handshake_age: Option<i64>,
    tunnel_up: bool,
    /// shared with the rules that use the address (UDP in the loop, TCP on their threads)
    hold: Hold,
    probes: u64,
    conflicts: u64,
    added: u64,
    removed: u64,
}

pub struct Proxies {
    link_if: String,
    remote_if: String,
    mac: [u8; 6],
    sock: Option<ArpSock>,
    list: Vec<One>,
}

/// What preflight refuses for the proxy addresses: an interface without ARP, and an address the
/// relay would not own (held on another interface, or not as the /32 it adds itself).
pub fn preflight(r: &Relay) -> Result<(), String> {
    if r.proxies.is_empty() {
        return Ok(());
    }
    let sysnet = format!("/sys/class/net/{}", r.link_interface);
    let flags = sys::read(&format!("{sysnet}/flags")).and_then(|f| i64::from_str_radix(f.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
    if sys::read(&format!("{sysnet}/type")).as_deref() != Some("1") || flags & libc::IFF_NOARP as i64 != 0 {
        return Err(format!(
            "{} does not use ARP (not Ethernet, or NOARP); a proxy address must be found by ARP on the link",
            r.link_interface
        ));
    }
    if sys::read(&format!("{sysnet}/address")).and_then(|m| parse_mac(&m)).is_none() {
        return Err(format!("{} has no Ethernet address", r.link_interface));
    }
    let all = nl::address_list(None).map_err(|e| format!("cannot list addresses: {}", sys::strerror(&e)))?;
    let link_idx = link_index(&r.link_interface);
    for p in &r.proxies {
        let ip: IpAddr = p.address.parse().unwrap();
        for (idx, a) in all.iter().filter(|(_, a)| a.ip == ip) {
            if Some(*idx) != link_idx {
                return Err(format!(
                    "{} is already an address of another interface of this machine; the relay adds it to {} itself",
                    p.address, r.link_interface
                ));
            }
            if a.prefix != 32 || !a.noprefixroute {
                return Err(format!(
                    "{} holds {}/{}; remove it: the relay adds the proxy address itself (as a /32, noprefixroute) while {}'s tunnel is up",
                    r.link_interface, p.address, a.prefix, p.remote
                ));
            }
        }
    }
    Ok(())
}

fn link_index(ifname: &str) -> Option<u32> {
    sys::read(&format!("/sys/class/net/{ifname}/ifindex")).and_then(|s| s.parse().ok())
}

fn remove(link_if: &str, o: &mut One, why: &str) {
    let closed = o.hold.release();
    if closed > 0 {
        println!("proxy {}: closed {closed} TCP connection(s) on it", o.ip);
    }
    match nl::del_address(link_if, IpAddr::V4(o.ip), 32) {
        Ok(()) => {
            o.removed += 1;
            println!("proxy {}: removed from {link_if}: {why}", o.ip);
        }
        Err(e) => println!("proxy {}: could not remove it from {link_if}: {}", o.ip, sys::strerror(&e)),
    }
}

impl Proxies {
    /// Opens the ARP socket and removes a proxy address an earlier run left on the link
    /// interface (a relay that was killed cannot remove its addresses). Nothing is added yet.
    pub fn new(r: &Relay) -> Result<Proxies, String> {
        let mut p =
            Proxies { link_if: r.link_interface.clone(), remote_if: r.remote_interface.clone(), mac: [0; 6], sock: None, list: vec![] };
        if r.proxies.is_empty() {
            return Ok(p);
        }
        p.mac = sys::read(&format!("/sys/class/net/{}/address", r.link_interface))
            .and_then(|m| parse_mac(&m))
            .ok_or_else(|| format!("{} has no Ethernet address", r.link_interface))?;
        p.sock = Some(ArpSock::open(&r.link_interface).map_err(|e| format!("ARP socket on {}: {}", r.link_interface, sys::strerror(&e)))?);
        let have = nl::address_list(Some(&r.link_interface)).unwrap_or_default();
        for d in &r.proxies {
            let ip: Ipv4Addr = d.address.parse().map_err(|_| format!("bad proxy address {}", d.address))?;
            if have.iter().any(|(_, a)| a.ip == IpAddr::V4(ip) && a.prefix == 32) {
                nl::del_address(&r.link_interface, IpAddr::V4(ip), 32)
                    .map_err(|e| format!("cannot remove {ip}/32 from {}: {}", r.link_interface, sys::strerror(&e)))?;
                println!(
                    "proxy {ip}: removed from {}, left there by an earlier run; it is probed again before it is taken",
                    r.link_interface
                );
            }
            p.list.push(One {
                remote: d.remote.parse().map_err(|_| format!("bad proxy remote {}", d.remote))?,
                decl: d.clone(),
                ip,
                state: State::Down { retry: None },
                why: "not checked yet".into(),
                handshake_age: None,
                tunnel_up: false,
                hold: Hold::new(),
                probes: 0,
                conflicts: 0,
                added: 0,
                removed: 0,
            });
        }
        Ok(p)
    }

    pub fn fd(&self) -> Option<RawFd> {
        self.sock.as_ref().map(|s| s.fd.as_raw_fd())
    }

    /// What a rule on ip shares with the relay; None when ip is not a proxy address.
    pub fn hold(&self, ip: IpAddr) -> Option<Hold> {
        self.list.iter().find(|o| IpAddr::V4(o.ip) == ip).map(|o| o.hold.clone())
    }

    /// The poll timeout, in ms, that wakes the loop in time for the next probe or announcement.
    pub fn timeout_ms(&self, max: i32) -> i32 {
        let now = Instant::now();
        self.list
            .iter()
            .filter_map(|o| match o.state {
                State::Probing { next, .. } => Some(next),
                State::Held { announce_left, next } if announce_left > 0 => Some(next),
                State::Down { retry: Some(t) } => Some(t),
                _ => None,
            })
            .map(|t| t.saturating_duration_since(now).as_millis().min(max as u128) as i32 + 1)
            .min()
            .unwrap_or(max)
            .min(max)
    }

    /// Every 2 s: read each remote's handshake; a stale tunnel gives its address up.
    pub fn check_tunnels(&mut self) {
        let now = wall_now();
        for i in 0..self.list.len() {
            let age = nl::handshake_age(&self.remote_if, self.list[i].remote, now);
            let o = &mut self.list[i];
            o.handshake_age = age.as_ref().ok().copied();
            let (up, why) = match &age {
                Ok(a) if *a < nl::HANDSHAKE_FRESH_S => (true, String::new()),
                Ok(a) => (
                    false,
                    format!(
                        "the tunnel to {} is down: its latest handshake was {a} s ago (held below {} s)",
                        o.decl.remote,
                        nl::HANDSHAKE_FRESH_S
                    ),
                ),
                Err(e) => (false, format!("the tunnel to {} is down: {e}", o.decl.remote)),
            };
            o.tunnel_up = up;
            if !up {
                let was_held = matches!(o.state, State::Held { .. });
                if was_held || matches!(o.state, State::Probing { .. }) {
                    o.state = State::Down { retry: None };
                }
                if was_held {
                    remove(&self.link_if, &mut self.list[i], &why);
                }
                self.list[i].why = why;
            }
        }
    }

    /// Every loop pass: read ARP from the link, and take the next probe or announcement step.
    pub fn step(&mut self) {
        let Some(sock) = &self.sock else { return };
        let mut seen = Vec::new();
        while let Some(a) = sock.recv() {
            if a.sha != self.mac {
                seen.push(a);
            }
        }
        let now = Instant::now();
        for i in 0..self.list.len() {
            // a conflict: another machine uses the address as its own, or probes for it while the relay does
            let ip = self.list[i].ip;
            let probing = matches!(self.list[i].state, State::Probing { .. });
            if let Some(a) = seen.iter().find(|a| a.spa == ip || (probing && a.spa.is_unspecified() && a.tpa == ip)) {
                let why = if a.spa == ip {
                    format!("another machine ({}) holds {ip} on {}", fmt_mac(&a.sha), self.link_if)
                } else {
                    format!("another machine ({}) is probing for {ip} on {}", fmt_mac(&a.sha), self.link_if)
                };
                let was_held = matches!(self.list[i].state, State::Held { .. });
                if was_held || probing {
                    self.list[i].conflicts += 1;
                    self.list[i].state = State::Down { retry: Some(now + Duration::from_secs(RETRY_AFTER_CONFLICT_S)) };
                    if was_held {
                        remove(&self.link_if, &mut self.list[i], &why);
                    } else {
                        println!("proxy {ip}: not taken: {why}; probing again in {RETRY_AFTER_CONFLICT_S} s");
                    }
                    self.list[i].why = why;
                }
            }
            let mac = self.mac;
            let o = &mut self.list[i];
            match o.state.clone() {
                State::Down { retry } if o.tunnel_up && retry.is_none_or(|t| now >= t) => {
                    o.state = State::Probing { sent: 0, next: now + Duration::from_millis(jitter_ms(0, PROBE_WAIT_MS)) };
                    o.why = format!("probing: ARP for {ip} on {} (RFC 5227)", self.link_if);
                }
                State::Probing { sent, next } if now >= next => {
                    if sent < PROBE_NUM {
                        let _ = sock.send(&Arp::probe(mac, ip));
                        o.probes += 1;
                        let wait = if sent + 1 < PROBE_NUM { jitter_ms(PROBE_MIN_MS, PROBE_MAX_MS) } else { ANNOUNCE_WAIT_MS };
                        o.state = State::Probing { sent: sent + 1, next: now + Duration::from_millis(wait) };
                    } else {
                        match nl::add_address_noprefixroute(&self.link_if, IpAddr::V4(ip), 32) {
                            Ok(()) => {
                                o.hold.flag.store(true, Ordering::SeqCst);
                                o.added += 1;
                                let _ = sock.send(&Arp::announce(mac, ip));
                                o.state = State::Held {
                                    announce_left: ANNOUNCE_NUM - 1,
                                    next: now + Duration::from_millis(ANNOUNCE_INTERVAL_MS),
                                };
                                o.why = String::new();
                                println!(
                                    "proxy {ip}: held on {} for {}: no other holder answered {PROBE_NUM} probes",
                                    self.link_if, o.decl.remote
                                );
                            }
                            Err(e) => {
                                o.why = format!("could not add {ip}/32 to {}: {}", self.link_if, sys::strerror(&e));
                                println!("proxy {ip}: {}", o.why);
                                o.state = State::Down { retry: Some(now + Duration::from_secs(RETRY_AFTER_CONFLICT_S)) };
                            }
                        }
                    }
                }
                State::Held { announce_left, next } if announce_left > 0 && now >= next => {
                    let _ = sock.send(&Arp::announce(mac, ip));
                    o.state = State::Held { announce_left: announce_left - 1, next: now + Duration::from_millis(ANNOUNCE_INTERVAL_MS) };
                }
                _ => {}
            }
        }
    }

    /// The health file's "proxies" list, as JSON.
    pub fn health_json(&self) -> String {
        let rows: Vec<String> = self
            .list
            .iter()
            .map(|o| {
                let held = matches!(o.state, State::Held { .. });
                let why = if held { String::new() } else { o.why.clone() };
                format!(
                    "{{\"address\": \"{}\", \"remote\": \"{}\", \"held\": {held}, \"why\": {}, \"handshake_age\": {}, \"probes\": {}, \"conflicts\": {}, \"added\": {}, \"removed\": {}}}",
                    o.ip,
                    o.decl.remote,
                    serde_json::Value::String(why),
                    o.handshake_age.map(|a| a.to_string()).unwrap_or_else(|| "null".into()),
                    o.probes,
                    o.conflicts,
                    o.added,
                    o.removed
                )
            })
            .collect();
        format!("[{}]", rows.join(", "))
    }
}

impl Drop for Proxies {
    /// Every path out of the relay, a signal included, gives the addresses back.
    fn drop(&mut self) {
        for i in 0..self.list.len() {
            if matches!(self.list[i].state, State::Held { .. }) {
                self.list[i].state = State::Down { retry: None };
                remove(&self.link_if, &mut self.list[i], "the relay is stopping");
            }
        }
    }
}

// ---------------------------------------------------------------- check and status

/// For check: whether the link interface holds each proxy address as the relay says it does.
pub fn check(r: &Relay, health: Option<&serde_json::Value>, items: &mut Vec<crate::tap::Item>) {
    let have = nl::address_list(Some(&r.link_interface)).unwrap_or_default();
    for p in &r.proxies {
        let ip: IpAddr = p.address.parse().unwrap();
        let on_link = have.iter().any(|(_, a)| a.ip == ip && a.prefix == 32);
        let row = health.and_then(|v| v["proxies"].as_array()?.iter().find(|x| x["address"].as_str() == Some(&p.address)).cloned());
        let want = format!("held while {}'s tunnel is up, and on {} exactly when held", p.remote, r.link_interface);
        let (ok, desc) = match row {
            None => (false, "the relay reports nothing for it".to_string()),
            Some(x) => {
                let held = x["held"].as_bool().unwrap_or(false);
                let desc = if held {
                    format!("held (handshake {} s ago)", x["handshake_age"].as_i64().map(|a| a.to_string()).unwrap_or("?".into()))
                } else {
                    format!("not held: {}", x["why"].as_str().unwrap_or(""))
                };
                let place = if on_link { "on" } else { "not on" };
                (held == on_link, format!("{desc}; {place} {}", r.link_interface))
            }
        };
        crate::tap::item(items, format!("relay-proxy-{}", p.address), Some(ok), want, desc);
    }
}

pub fn status(r: &Relay, health: Option<&serde_json::Value>) {
    for p in &r.proxies {
        let row = health.and_then(|v| v["proxies"].as_array()?.iter().find(|x| x["address"].as_str() == Some(&p.address)).cloned());
        let state = match &row {
            Some(x) if x["held"].as_bool() == Some(true) => {
                format!("held (handshake {} s ago)", x["handshake_age"].as_i64().map(|a| a.to_string()).unwrap_or("?".into()))
            }
            Some(x) => format!("not held: {}", x["why"].as_str().unwrap_or("")),
            None => "not reported".into(),
        };
        println!("  proxy  {} on {} stands for {}: {state}", p.address, r.link_interface, p.remote);
        if let Some(x) = row {
            let n = |k: &str| x[k].as_u64().unwrap_or(0);
            println!(
                "         {} probes sent, {} conflicts, added {} times, removed {} times",
                n("probes"),
                n("conflicts"),
                n("added"),
                n("removed")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_round_trip_and_probe_shape() {
        let mac = [2, 0, 0, 0, 0, 1];
        let ip: Ipv4Addr = "192.0.2.60".parse().unwrap();
        let p = Arp::probe(mac, ip);
        let b = p.encode();
        assert_eq!(&b[0..8], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&b[14..18], &[0, 0, 0, 0]);
        assert_eq!(&b[24..28], &[192, 0, 2, 60]);
        assert_eq!(Arp::decode(&b), Some(p));
        let a = Arp::announce(mac, ip);
        assert_eq!(a.spa, a.tpa);
        assert!(Arp::decode(&b[..27]).is_none());
        let mut rarp = b;
        rarp[7] = 3;
        assert!(Arp::decode(&rarp).is_none());
    }

    #[test]
    fn macs() {
        assert_eq!(parse_mac("02:00:5e:10:00:01"), Some([2, 0, 0x5e, 0x10, 0, 1]));
        assert_eq!(fmt_mac(&[2, 0, 0x5e, 0x10, 0, 1]), "02:00:5e:10:00:01");
        assert!(parse_mac("02:00").is_none());
    }
}
