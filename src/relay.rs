// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Relay: the fixed-port forwarder of docs/adr/0002, run as a service (docs/adr/0004 §1), for
//! UDP and TCP (relay_tcp.rs), opened from the remote or from the link (docs/adr/0004 §2).
//!
//! A remote machine reaches the relay through a WireGuard interface. WireGuard
//! authenticates the remote machine by its key and binds its tunnel address to that
//! key, so a datagram's source address inside the tunnel names an authenticated
//! machine. Each allow rule names that address, a port on the tunnel, and one
//! address and port on the link; or, for traffic a machine on the link starts
//! (link-to-remote), a port on the relay's link address, the link addresses
//! accepted, and the remote's port. Everything else is dropped and counted.
//!
//! The relay TRANSMITS on the link, from its own interface and address. It never
//! uses a tap port, never bridges and forwards no broadcast or multicast.
//! An interface that is not there (a mesh client not started yet, or restarting) is waited for,
//! at start and after a restart, and is never a refusal: relay.health and `check` say what the
//! relay is waiting for. The relay stops (exit 1) when IP forwarding is turned on, or when one of
//! its interfaces vanishes or comes back under a new index, so the service starts it again: it
//! waits for the interface, then binds its sockets to it as it is.
//! `goatrope install` installs goatrope-relay.service, which runs `goatrope relay`;
//! a refusal exits with the refusal code, which the unit does not restart.
//! `goatrope relay` also runs it in the foreground.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::boundary;
use crate::config::{Config, Relay, RelayRule};
use crate::nl;
use crate::proxy::{self, Hold, Proxies};
use crate::relay_tcp;
use crate::sys;
use crate::sysutil as su;
use crate::tap::{item, Item};

pub const HEALTH: &str = "/var/lib/goatrope/relay.health";
pub const UNIT: &str = "goatrope-relay.service";
/// relay.health is rewritten every 2 s while the relay runs; older than this, it is stale.
pub const STALE_S: f64 = 10.0;

pub struct RelayRefusal(pub String);

fn refuse<T>(msg: String) -> Result<T, RelayRefusal> {
    Err(RelayRefusal(msg))
}

pub fn preflight(cfg: &Config) -> Result<(), RelayRefusal> {
    let Some(r) = &cfg.relay else {
        return refuse("this declaration has no [relay]".to_string());
    };
    let is_wg = |i: &str| nl::kind(i).as_deref() == Some("wireguard");
    if r.transport == "mesh" && !is_wg(&r.remote_interface) {
        return refuse(format!(
            "{} is not a WireGuard interface; the relay authenticates the remote machine through WireGuard and accepts nothing else",
            r.remote_interface
        ));
    }
    if r.transport == "boundary" && sys::exists(&r.remote_interface) && !is_wg(&r.remote_interface) {
        return refuse(format!("{} exists and is not a WireGuard interface; it cannot be the boundary interface", r.remote_interface));
    }
    if !sys::exists(&r.link_interface) {
        return refuse(format!("no interface {}", r.link_interface));
    }
    let link_kind = nl::kind(&r.link_interface);
    if matches!(link_kind.as_deref(), Some("bridge") | Some("wireguard")) || sys::master(&r.link_interface).is_some() {
        return refuse(format!(
            "{} is a bridge, a tunnel or a bridge member; the relay sends from a plain interface of its own",
            r.link_interface
        ));
    }
    let mut taps = cfg.tap_ports();
    taps.push("goatrope0".to_string());
    if taps.contains(&r.link_interface) || taps.contains(&r.remote_interface) {
        return refuse("a relay interface is a tap interface".to_string());
    }
    if !r.link_address.contains(':')
        && sys::read(&format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", r.link_interface)).as_deref() != Some("1")
    {
        return refuse(format!(
            "IPv6 is on for {}: the kernel would send neighbor discovery and MLD frames on the link. Disable it (net.ipv6.conf.<if>.disable_ipv6 = 1) or declare an IPv6 address",
            r.link_interface
        ));
    }
    let fwd = forwarding(r);
    if !fwd.is_empty() {
        return refuse(format!(
            "IP forwarding is on ({}): the kernel would route between the tunnel and the link, around the relay's allow rules. Turn it off for both interfaces (net.ipv4.conf.<if>.forwarding = 0, net.ipv6.conf.<if>.forwarding = 0); a machine that must route (Docker, a mesh router) cannot be the relay",
            fwd.join(", ")
        ));
    }
    crate::relay_filter::preflight(r).map_err(RelayRefusal)?;
    proxy::preflight(r).map_err(RelayRefusal)?;
    let addrs = nl::addresses(&r.link_interface);
    if !addrs.contains(&r.link_address) {
        let have = if addrs.is_empty() { "none".to_string() } else { addrs.join(", ") };
        return refuse(format!(
            "{} does not hold {} (it has {have}); configure the relay's own address on its interface first",
            r.link_interface, r.link_address
        ));
    }
    crate::l2::preflight(cfg).map_err(RelayRefusal)?;
    if r.transport == "boundary" {
        // last, so a refusal above leaves the machine as it was
        let b = r.boundary.as_ref().expect("transport boundary has a [relay.boundary]");
        let made = boundary::up(b, &r.remote_interface).map_err(|e| RelayRefusal(e.0))?;
        println!(
            "goatrope relay: boundary interface {} {}, one peer {} at {}",
            r.remote_interface,
            if made { "made" } else { "present" },
            b.peer_address,
            b.peer_endpoint
        );
    }
    // from here the link reaches only the rules' ports on this machine
    crate::relay_filter::up(r).map_err(RelayRefusal)?;
    crate::l2::up(cfg).map_err(RelayRefusal)?;
    Ok(())
}

fn forwarding(r: &Relay) -> Vec<String> {
    let mut ifs = vec![r.remote_interface.clone(), r.link_interface.clone()];
    ifs.extend(crate::l2::interfaces(r)); // a lane bridges and never routes
    let mut on: Vec<String> = ifs.iter().flat_map(|i| sys::forwarding(i).into_iter().map(move |fam| format!("{fam} on {i}"))).collect();
    if sys::read("/proc/sys/net/ipv6/conf/all/forwarding").as_deref() == Some("1") {
        // IPv6 forwards on the global setting, whatever each interface says
        on.push("ipv6 on all interfaces".to_string());
    }
    on
}

/// addr:port as a sockaddr for bind(2) and connect(2).
fn sockaddr(addr: IpAddr, port: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is valid; the fields are filled below.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        IpAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large enough and suitably aligned for a sockaddr_in.
            let sa = unsafe { &mut *(&mut ss as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = port.to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(a.octets());
            std::mem::size_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(a) => {
            // SAFETY: sockaddr_storage is large enough and suitably aligned for a sockaddr_in6.
            let sa = unsafe { &mut *(&mut ss as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = port.to_be();
            sa.sin6_addr.s6_addr = a.octets();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

pub(crate) fn sockaddr_of(a: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    sockaddr(a.ip(), a.port())
}

fn setopt<T>(fd: libc::c_int, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: v points to a value of the size given.
    let rc =
        unsafe { libc::setsockopt(fd, level, name, v as *const T as *const libc::c_void, std::mem::size_of::<T>() as libc::socklen_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A socket of type `ty` (SOCK_DGRAM, SOCK_STREAM) bound to one device (SO_BINDTODEVICE) and to
/// addr:port. With `freebind` (IP_FREEBIND), addr need not be on the machine yet. A proxy address
/// (ADR 0004 §4) is bound that way: the kernel delivers to the socket only while the address is
/// on the link interface, and the relay sends from it only while it holds it.
pub(crate) fn bound_fd_free(dev: &str, addr: IpAddr, port: u16, ty: libc::c_int, freebind: bool) -> io::Result<OwnedFd> {
    let fam = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: plain socket(2) call; the descriptor is owned by the OwnedFd below.
    let fd = unsafe { libc::socket(fam, ty | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh socket that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: the option value is dev's bytes with their length.
    let rc = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr() as *const libc::c_void, dev.len() as libc::socklen_t)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if freebind {
        setopt(fd, libc::IPPROTO_IP, libc::IP_FREEBIND, &(1 as libc::c_int))?;
    }
    if ty == libc::SOCK_STREAM && port != 0 {
        setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &(1 as libc::c_int))?; // a restart binds again at once
    }
    let (sa, len) = sockaddr(addr, port);
    // SAFETY: sa is a socket address of the length given.
    if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// A UDP socket bound to one device (SO_BINDTODEVICE) and to addr:port, non-blocking.
fn bound(dev: &str, addr: IpAddr, port: u16) -> io::Result<UdpSocket> {
    bound_free(dev, addr, port, false)
}

fn bound_free(dev: &str, addr: IpAddr, port: u16, freebind: bool) -> io::Result<UdpSocket> {
    let sock = UdpSocket::from(bound_fd_free(dev, addr, port, libc::SOCK_DGRAM, freebind)?);
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// A rule's socket with its receive buffer (`receive_buffer_kb`, docs/adr/0006-data-path.md): a burst
/// that arrives while the relay's one thread is not running waits there instead of being dropped.
/// SO_RCVBUFFORCE (the unit has CAP_NET_ADMIN) sets it past net.core.rmem_max; without the capability,
/// SO_RCVBUF sets as much as rmem_max allows.
fn sized(sock: io::Result<UdpSocket>, rule: &RelayRule) -> io::Result<UdpSocket> {
    let sock = sock?;
    let bytes: libc::c_int = (rule.receive_buffer_kb * 1024).min(i32::MAX as usize) as libc::c_int;
    let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
        // SAFETY: the option value is a c_int of the size given.
        let rc = unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, opt, &bytes as *const _ as *const libc::c_void, size) };
        if rc == 0 {
            break;
        }
    }
    Ok(sock)
}

/// The unspecified address of addr's family.
pub(crate) fn any_of(addr: IpAddr) -> IpAddr {
    if addr.is_ipv4() {
        IpAddr::from([0u8; 4])
    } else {
        IpAddr::from([0u16; 8])
    }
}

/// One UDP rule. `listen` receives from the side that sends first: the remote (remote-to-link,
/// both) or machines on the link (link-to-remote). Each accepted sender has its own outgoing
/// socket, so a reply goes back to the sender it answers.
struct RuleState<'a> {
    rule: &'a RelayRule,
    /// the senders `listen` accepts
    clients: Vec<IpAddr>,
    /// where their datagrams go
    dest: Option<SocketAddr>,
    listen: UdpSocket,
    /// one per client
    outs: Vec<UdpSocket>,
    /// each client's last address and port, where its replies go
    peers: Vec<Option<SocketAddr>>,
    replies: bool,
    /// the rule's proxy address is held (None: the rule sends from the relay's own address)
    held: Option<Hold>,
    to_link: u64,
    to_remote: u64,
    denied: u64,
    send_errors: u64,
}

/// The time as Python's json module writes a float: the shortest form that reads back the
/// same, with ".0" on a whole number.
fn json_float(f: f64) -> String {
    let s = format!("{f}");
    if s.contains(['.', 'e', 'E']) || !f.is_finite() {
        s
    } else {
        format!("{s}.0")
    }
}

/// Where a rule sends: the target on the link, or (link-to-remote) the remote.
fn dest_of(rule: &RelayRule) -> String {
    let (a, p) = if rule.link_initiated() { (&rule.remote, rule.remote_port) } else { (&rule.target, rule.target_port) };
    if a.contains(':') {
        format!("[{a}]:{p}")
    } else {
        format!("{a}:{p}")
    }
}

/// This machine's IP reassembly failures and timeouts so far, IPv4 and IPv6 together
/// (/proc/net/snmp ReasmFails and ReasmTimeout, /proc/net/snmp6 Ip6ReasmFails and Ip6ReasmTimeout).
/// A fragmented datagram that the tunnel half-dropped holds reassembly memory until it times out,
/// and while that memory is full every fragmented datagram is lost (docs/adr/0006-data-path.md).
pub fn reassembly() -> (u64, u64) {
    let mut fails = 0;
    let mut timeouts = 0;
    if let Some(t) = su::read("/proc/net/snmp") {
        let ip: Vec<&str> = t.lines().filter(|l| l.starts_with("Ip:")).collect();
        if ip.len() == 2 {
            for (k, v) in ip[0].split_whitespace().zip(ip[1].split_whitespace()) {
                match k {
                    "ReasmFails" => fails += v.parse::<u64>().unwrap_or(0),
                    "ReasmTimeout" => timeouts += v.parse::<u64>().unwrap_or(0),
                    _ => {}
                }
            }
        }
    }
    if let Some(t) = su::read("/proc/net/snmp6") {
        for l in t.lines() {
            let mut w = l.split_whitespace();
            match (w.next(), w.next().and_then(|v| v.parse::<u64>().ok())) {
                (Some("Ip6ReasmFails"), Some(n)) => fails += n,
                (Some("Ip6ReasmTimeout"), Some(n)) => timeouts += n,
                _ => {}
            }
        }
    }
    (fails, timeouts)
}

/// Each interface the relay's sockets are bound to, and its index then.
type Bound = Vec<(String, Option<u32>)>;

fn bound_json(bound: &Bound) -> String {
    let rows: Vec<String> = bound
        .iter()
        .map(|(n, i)| format!("{}: {}", serde_json::Value::String(n.clone()), i.map(|i| i.to_string()).unwrap_or("null".into())))
        .collect();
    format!("{{{}}}", rows.join(", "))
}

fn health_json(
    r: &Relay,
    time: f64,
    state: &[RuleState],
    tcp: &[(&RelayRule, Arc<relay_tcp::Counters>)],
    proxies: &Proxies,
    bound: &Bound,
) -> String {
    let mut rows: Vec<String> = state
        .iter()
        .map(|s| {
            format!(
                "{{\"listen_port\": {}, \"protocol\": \"udp\", \"direction\": \"{}\", \"target\": \"{}\", \"to_link\": {}, \"to_remote\": {}, \"denied\": {}, \"send_errors\": {}}}",
                s.rule.listen_port, s.rule.direction, dest_of(s.rule), s.to_link, s.to_remote, s.denied, s.send_errors
            )
        })
        .collect();
    rows.extend(tcp.iter().map(|(rule, c)| {
        format!(
            "{{\"listen_port\": {}, \"protocol\": \"tcp\", \"direction\": \"{}\", \"target\": \"{}\", {}}}",
            rule.listen_port,
            rule.direction,
            dest_of(rule),
            c.json()
        )
    }));
    let (fails, timeouts) = reassembly();
    let (f0, t0) = *REASM_AT_START.get_or_init(reassembly);
    format!(
        "{{\"time\": {}, \"interfaces\": {}, \"rules\": [{}], \"proxies\": {}, \"link_filter\": {}, \"reassembly\": {{\"failed\": {}, \"timed_out\": {}}}}}",
        json_float(time),
        bound_json(bound),
        rows.join(", "),
        proxies.health_json(),
        crate::relay_filter::health_json(r),
        fails.saturating_sub(f0),
        timeouts.saturating_sub(t0)
    )
}

fn health(
    r: &Relay,
    state: &[RuleState],
    tcp: &[(&RelayRule, Arc<relay_tcp::Counters>)],
    proxies: &Proxies,
    bound: &Bound,
) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    write_health(&health_json(r, now, state, tcp, proxies, bound));
    Ok(())
}

/// relay.health, written whole (a new file renamed over the old); an error is printed, not fatal.
fn write_health(body: &str) {
    let dir = std::path::Path::new(HEALTH).parent().unwrap();
    if let Err(e) = std::fs::create_dir_all(dir) {
        println!("health: {}", sys::oserror(&e, &dir.to_string_lossy()));
        return;
    }
    let tmp = format!("{HEALTH}.new");
    let res = std::fs::write(&tmp, body)
        .map_err(|e| sys::oserror(&e, &tmp))
        .and_then(|_| std::fs::rename(&tmp, HEALTH).map_err(|e| sys::oserror(&e, &tmp)));
    if let Err(e) = res {
        println!("health: {e}");
    }
}

/// The interfaces the relay needs before it can start: the link interface, the remote interface
/// unless the relay makes it itself (transport "boundary"), and each lane's port.
fn needed(r: &Relay) -> Vec<&String> {
    let mut v = vec![&r.link_interface];
    if r.transport != "boundary" {
        v.insert(0, &r.remote_interface);
    }
    v.extend(r.l2.iter().map(|l| &l.port)); // a lane's dedicated port: a USB adapter may come late too
    v
}

/// Wait until every needed interface exists, and each lane's address and peer are on the mesh
/// interface, writing relay.health (what it waits for) every 2 s.
/// Some(exit code) when a stop signal comes first.
fn wait_interfaces(r: &Relay) -> Option<i32> {
    let mut said: Vec<String> = Vec::new();
    let mut last: Option<Instant> = None;
    loop {
        let mut missing: Vec<String> = needed(r).into_iter().filter(|i| !sys::exists(i)).cloned().collect();
        if missing.is_empty() {
            missing = crate::l2::waiting_for(r); // the lane's address and peer, which the mesh client adds after its interface
        }
        if missing.is_empty() {
            if !said.is_empty() {
                println!("goatrope relay: {} is there; starting", said.join(", "));
            }
            return None;
        }
        if missing != said {
            println!("goatrope relay: waiting for {} (not there yet)", missing.join(", "));
            said = missing.clone();
        }
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(2)) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
            let w: Vec<String> = missing.iter().map(|m| serde_json::Value::String(m.clone()).to_string()).collect();
            write_health(&format!("{{\"time\": {}, \"waiting\": [{}], \"rules\": [], \"proxies\": []}}", json_float(now), w.join(", ")));
            last = Some(Instant::now());
        }
        if sys::stop_requested() {
            println!("goatrope relay: stopping on a signal");
            return Some(crate::EXIT_OK);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The reassembly counters when the relay started; relay.health reports what happened since.
static REASM_AT_START: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

pub fn run(cfg: &Config) -> i32 {
    // first, so a stop request during start-up still ends in the loop, which removes what it added
    sys::catch_stop_signals();
    if let Some(code) = wait_interfaces(cfg.relay.as_ref().unwrap()) {
        return code;
    }
    if let Err(e) = preflight(cfg) {
        eprintln!("goatrope relay: refused: {}", e.0);
        return crate::EXIT_REFUSED;
    }
    match serve(cfg) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("goatrope relay: {e}");
            crate::EXIT_ERROR
        }
    }
}

fn serve(cfg: &Config) -> Result<i32, String> {
    REASM_AT_START.get_or_init(reassembly);
    let r = cfg.relay.as_ref().unwrap();
    let link_ip = r.link_address.split('/').next().unwrap_or_default();
    let link_addr: IpAddr = link_ip.parse().map_err(|_| format!("bad link address {link_ip}"))?;
    let ip = |s: &str| -> Result<IpAddr, String> { s.parse().map_err(|_| format!("bad address {s}")) };
    // Every socket is bound to an interface (SO_BINDTODEVICE), which the kernel keeps as its index. A mesh client
    // that restarts deletes and recreates its interface (NetBird's wt0 does), and a USB adapter that is replugged
    // comes back the same way: under a new index the sockets receive nothing.
    let bound_to: Bound = [&r.remote_interface, &r.link_interface].iter().map(|i| (i.to_string(), ifindex(i))).collect();
    let mut state: Vec<RuleState> = Vec::new();
    let mut tcp: Vec<(&RelayRule, Arc<relay_tcp::Counters>)> = Vec::new();
    // dropped on every path out of serve, which removes the proxy addresses it added
    let mut proxies = Proxies::new(r)?;
    proxies.check_tunnels();
    let own = link_addr;
    for rule in &r.rules {
        let link_addr = rule_link_ip(rule, own);
        let held = proxies.hold(link_addr);
        let free = held.is_some();
        let link_ip = link_addr.to_string();
        let l2r = rule.link_initiated();
        let remote = ip(&rule.remote)?;
        let (clients, dest) = if l2r {
            (rule.sources.iter().map(|s| ip(s)).collect::<Result<Vec<_>, _>>()?, SocketAddr::new(remote, rule.remote_port))
        } else {
            (vec![remote], SocketAddr::new(ip(&rule.target)?, rule.target_port))
        };
        let shown = if l2r {
            format!(
                "{} -> {link_ip}:{} on {} => {} -> {} on {} ({} {})",
                rule.sources.join(","),
                rule.listen_port,
                r.link_interface,
                r.remote_interface,
                dest_of(rule),
                r.remote_interface,
                rule.protocol,
                rule.direction
            )
        } else {
            format!(
                "{} -> {}:{} => {link_ip} -> {} on {} ({} {})",
                rule.remote,
                r.remote_interface,
                rule.listen_port,
                dest_of(rule),
                r.link_interface,
                rule.protocol,
                rule.direction
            )
        };
        if rule.protocol == "tcp" {
            let c = relay_tcp::start(r, rule, link_addr, held, clients, dest)?;
            tcp.push((rule, c));
            println!("goatrope relay: {shown}");
            continue;
        }
        let (listen, outs) = if l2r {
            let listen = sized(bound_free(&r.link_interface, link_addr, rule.listen_port, free), rule).map_err(|e| sys::strerror(&e))?;
            let outs = clients.iter().map(|_| sized(bound(&r.remote_interface, any_of(remote), 0), rule)).collect::<io::Result<Vec<_>>>();
            (listen, outs.map_err(|e| sys::strerror(&e))?)
        } else {
            let listen = sized(bound(&r.remote_interface, any_of(remote), rule.listen_port), rule).map_err(|e| sys::strerror(&e))?;
            (listen, vec![sized(bound_free(&r.link_interface, link_addr, 0, free), rule).map_err(|e| sys::strerror(&e))?])
        };
        let n = clients.len();
        state.push(RuleState {
            rule,
            clients,
            dest: Some(dest),
            listen,
            outs,
            peers: vec![None; n],
            replies: l2r || rule.direction == "both",
            held,
            to_link: 0,
            to_remote: 0,
            denied: 0,
            send_errors: 0,
        });
        println!("goatrope relay: {shown}");
    }
    // each polled socket: (rule state, None for its listening socket or Some(client) for an outgoing one)
    let slots: Vec<(usize, Option<usize>)> = state
        .iter()
        .enumerate()
        .flat_map(|(i, s)| std::iter::once((i, None)).chain((0..s.outs.len()).map(move |k| (i, Some(k)))))
        .collect();
    health(r, &state, &tcp, &proxies, &bound_to)?; // at once, so a service manager sees it running
    let mut last = Instant::now();
    let mut path = Batched::new();
    let mut denied_log = DeniedLog(None);
    loop {
        if sys::stop_requested() {
            crate::l2::close_all();
            println!("goatrope relay: stopping on a signal");
            return Ok(crate::EXIT_OK);
        }
        proxies.step();
        let mut fds: Vec<libc::pollfd> = slots
            .iter()
            .map(|&(i, o)| match o {
                None => state[i].listen.as_raw_fd(),
                Some(k) => state[i].outs[k].as_raw_fd(),
            })
            .map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
            .collect();
        if let Some(fd) = proxies.fd() {
            fds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 }); // last; read in proxies.step()
        }
        // SAFETY: fds is a valid array of pollfd of the length given (poll with none is a sleep).
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, proxies.timeout_ms(1000)) };
        if n > 0 {
            // the proxy's fd, if any, is last and has no slot: zip stops before it
            for (pfd, &(i, out)) in fds.iter().zip(slots.iter()) {
                if pfd.revents != 0 {
                    path.pump(&mut state[i], out, &mut denied_log);
                }
            }
        }
        if last.elapsed() >= Duration::from_secs(2) {
            proxies.check_tunnels();
            health(r, &state, &tcp, &proxies, &bound_to)?;
            last = Instant::now();
            let fwd = forwarding(r);
            if !fwd.is_empty() {
                crate::l2::close_all();
                eprintln!("goatrope relay: stopping: IP forwarding was turned on ({})", fwd.join(", "));
                return Ok(crate::EXIT_ERROR);
            }
            // an interface gone or made again under a new index: the sockets on it receive nothing. Stop; the
            // service starts the relay again, which waits for the interface and binds to it as it is then.
            for (name, was) in &bound_to {
                match ifindex(name) {
                    Some(n) if Some(n) == *was => {}
                    Some(n) => {
                        crate::l2::close_all();
                        eprintln!(
                            "goatrope relay: stopping: {name} was made again (index {} -> {n}); the service starts the relay again on it",
                            was.map(|w| w.to_string()).unwrap_or("none".into())
                        );
                        return Ok(crate::EXIT_ERROR);
                    }
                    None => {
                        crate::l2::close_all();
                        eprintln!("goatrope relay: stopping: {name} is gone; the service starts the relay again, and it waits for {name}");
                        return Ok(crate::EXIT_ERROR);
                    }
                }
            }
            if r.transport == "boundary" {
                let drift = boundary::check(r.boundary.as_ref().unwrap(), &r.remote_interface);
                if !drift.is_empty() {
                    eprintln!("goatrope relay: stopping: {} no longer matches the declaration: {}", r.remote_interface, drift.join("; "));
                    return Ok(crate::EXIT_ERROR);
                }
            }
            if let Err(e) = crate::relay_filter::tick(r) {
                crate::l2::close_all();
                eprintln!("goatrope relay: stopping: {e}");
                return Ok(crate::EXIT_ERROR);
            }
            if let Err(e) = crate::l2::tick(r) {
                eprintln!("goatrope relay: stopping: {e}");
                return Ok(crate::EXIT_ERROR);
            }
        }
    }
}

/// The interface's index; None when there is no such interface.
pub(crate) fn ifindex(name: &str) -> Option<u32> {
    sys::read(&format!("/sys/class/net/{name}/ifindex")).and_then(|s| s.parse().ok())
}

/// The address a rule's link-side sockets bind to: its proxy address, else the relay's own.
fn rule_link_ip(rule: &RelayRule, own: IpAddr) -> IpAddr {
    rule.link_address.as_deref().and_then(|a| a.parse().ok()).unwrap_or(own)
}

// ---------------------------------------------------------------- the UDP data path (docs/adr/0006)

/// Rate-limits the "denied" line: one every 10 s at most.
struct DeniedLog(Option<Instant>);

/// How datagrams cross the relay. Every UDP rule is forwarded through this one interface; ADR 0006
/// records what was measured for each way of doing it.
trait Datapath {
    /// Forward what is waiting on one of a rule's sockets: its listening socket (`out` None), or the
    /// outgoing socket of client `out` (the replies). Every datagram is either sent and counted, or
    /// denied or failed and counted.
    fn pump(&mut self, st: &mut RuleState, out: Option<usize>, log: &mut DeniedLog);
}

/// Datagrams per system call.
const BATCH: usize = 64;
/// Batches taken from one socket before the others are served.
const ROUNDS: usize = 8;
const DGRAM: usize = 65535;

/// User space, batched: recvmmsg takes up to BATCH datagrams in one call, the rule is applied to each,
/// and sendmmsg sends the allowed ones in one call. The bytes are not copied in between.
struct Batched {
    bufs: Vec<u8>,
    lens: Vec<usize>,
    from: Vec<libc::sockaddr_storage>,
    to: Vec<libc::sockaddr_storage>,
    keep: Vec<usize>,
}

impl Batched {
    fn new() -> Batched {
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let zero: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        Batched {
            bufs: vec![0u8; BATCH * DGRAM],
            lens: vec![0; BATCH],
            from: vec![zero; BATCH],
            to: vec![zero; BATCH],
            keep: Vec::with_capacity(BATCH),
        }
    }

    /// Up to BATCH datagrams from sock, without waiting; their lengths and sources are in self.
    fn recv(&mut self, sock: &UdpSocket) -> usize {
        let base = self.bufs.as_mut_ptr();
        let mut iov: Vec<libc::iovec> =
            // SAFETY: each pointer is inside bufs, DGRAM bytes apart.
            (0..BATCH).map(|i| libc::iovec { iov_base: unsafe { base.add(i * DGRAM) } as *mut libc::c_void, iov_len: DGRAM }).collect();
        // SAFETY: an all-zero mmsghdr is a valid value; the pointers are filled below.
        let mut msgs: Vec<libc::mmsghdr> = (0..BATCH).map(|_| unsafe { std::mem::zeroed() }).collect();
        for (i, m) in msgs.iter_mut().enumerate() {
            m.msg_hdr.msg_name = &mut self.from[i] as *mut _ as *mut libc::c_void;
            m.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            m.msg_hdr.msg_iov = &mut iov[i];
            m.msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: msgs, iov, from and bufs outlive the call and hold BATCH entries each.
        let n = unsafe {
            libc::recvmmsg(sock.as_raw_fd(), msgs.as_mut_ptr(), BATCH as libc::c_uint, libc::MSG_DONTWAIT as _, std::ptr::null_mut())
        };
        if n <= 0 {
            return 0;
        }
        for (i, m) in msgs.iter().take(n as usize).enumerate() {
            self.lens[i] = m.msg_len as usize;
        }
        n as usize
    }

    /// Send the datagrams in self.keep to the addresses in self.to; returns (sent, failed).
    fn send(&mut self, sock: &UdpSocket) -> (u64, u64) {
        let base = self.bufs.as_mut_ptr();
        let mut iov: Vec<libc::iovec> = self
            .keep
            .iter()
            // SAFETY: each pointer is inside bufs, at a datagram received into it.
            .map(|&i| libc::iovec { iov_base: unsafe { base.add(i * DGRAM) } as *mut libc::c_void, iov_len: self.lens[i] })
            .collect();
        // SAFETY: an all-zero mmsghdr is a valid value; the pointers are filled below.
        let mut msgs: Vec<libc::mmsghdr> = (0..self.keep.len()).map(|_| unsafe { std::mem::zeroed() }).collect();
        for (j, m) in msgs.iter_mut().enumerate() {
            let len = match self.to[j].ss_family as libc::c_int {
                libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                _ => std::mem::size_of::<libc::sockaddr_in>(),
            };
            m.msg_hdr.msg_name = &mut self.to[j] as *mut _ as *mut libc::c_void;
            m.msg_hdr.msg_namelen = len as libc::socklen_t;
            m.msg_hdr.msg_iov = &mut iov[j];
            m.msg_hdr.msg_iovlen = 1;
        }
        let (mut sent, mut failed, mut at) = (0u64, 0u64, 0usize);
        while at < msgs.len() {
            // SAFETY: msgs[at..] and what it points to outlive the call.
            let k = unsafe {
                libc::sendmmsg(sock.as_raw_fd(), msgs[at..].as_mut_ptr(), (msgs.len() - at) as libc::c_uint, libc::MSG_DONTWAIT as _)
            };
            if k > 0 {
                sent += k as u64;
                at += k as usize;
            } else {
                // the datagram at `at` cannot be sent (no route, no peer, a full buffer): dropped and counted
                failed += 1;
                at += 1;
            }
        }
        (sent, failed)
    }
}

fn to_sockaddr(a: SocketAddr, out: &mut libc::sockaddr_storage) {
    match a {
        SocketAddr::V4(v) => {
            // SAFETY: sockaddr_storage is large enough and aligned for a sockaddr_in.
            let sa = unsafe { &mut *(out as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v.ip().octets());
        }
        SocketAddr::V6(v) => {
            // SAFETY: sockaddr_storage is large enough and aligned for a sockaddr_in6.
            let sa = unsafe { &mut *(out as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v.port().to_be();
            sa.sin6_addr.s6_addr = v.ip().octets();
            sa.sin6_flowinfo = 0;
            sa.sin6_scope_id = v.scope_id();
        }
    }
}

fn from_sockaddr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match s.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: the family says this storage holds a sockaddr_in.
            let sa = unsafe { &*(s as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            Some(SocketAddr::new(IpAddr::from(sa.sin_addr.s_addr.to_ne_bytes()), u16::from_be(sa.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this storage holds a sockaddr_in6.
            let sa = unsafe { &*(s as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            Some(SocketAddr::new(IpAddr::from(sa.sin6_addr.s6_addr), u16::from_be(sa.sin6_port)))
        }
        _ => None,
    }
}

impl Datapath for Batched {
    fn pump(&mut self, st: &mut RuleState, out: Option<usize>, log: &mut DeniedLog) {
        let rule = st.rule;
        let l2r = rule.link_initiated();
        // a send toward the link from a proxy address the relay does not hold is a send error
        let link_blocked = st.held.as_ref().is_some_and(|h| !h.held());
        for _ in 0..ROUNDS {
            let n = self.recv(match out {
                None => &st.listen,
                Some(k) => &st.outs[k],
            });
            if n == 0 {
                return;
            }
            // (datagram, the socket it leaves by: Some(client) for an outgoing one, None for the listening one)
            let mut via: Vec<(usize, Option<usize>, SocketAddr)> = Vec::with_capacity(n);
            for i in 0..n {
                let Some(src) = from_sockaddr(&self.from[i]) else {
                    st.denied += 1;
                    continue;
                };
                match out {
                    None => {
                        let Some(c) = st.clients.iter().position(|a| *a == src.ip()) else {
                            st.denied += 1;
                            if log.0.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
                                let allowed = if l2r { rule.sources.join(", ") } else { rule.remote.clone() };
                                println!("denied: {}:{} -> port {} (allowed: {allowed})", src.ip(), src.port(), rule.listen_port);
                                log.0 = Some(Instant::now());
                            }
                            continue;
                        };
                        st.peers[c] = Some(src);
                        match st.dest {
                            Some(_) if !l2r && link_blocked => st.send_errors += 1,
                            Some(to) => via.push((i, Some(c), to)),
                            None => st.send_errors += 1,
                        }
                    }
                    Some(k) => match st.peers[k].filter(|_| st.replies && Some(src) == st.dest) {
                        Some(_) if l2r && link_blocked => st.send_errors += 1,
                        Some(peer) => via.push((i, None, peer)),
                        None => st.denied += 1,
                    },
                }
            }
            // one sendmmsg per socket the datagrams leave by; each socket's datagrams in the order they arrived
            let mut socks: Vec<Option<usize>> = via.iter().map(|v| v.1).collect();
            socks.sort();
            socks.dedup();
            for sk in socks {
                self.keep.clear();
                for &(i, _, to) in via.iter().filter(|v| v.1 == sk) {
                    let j = self.keep.len();
                    to_sockaddr(to, &mut self.to[j]);
                    self.keep.push(i);
                }
                let (sent, failed) = self.send(match sk {
                    Some(c) => &st.outs[c],
                    None => &st.listen,
                });
                // from the listening socket toward the rule's destination; back toward the sender for replies
                let toward_link = if sk.is_some() { !l2r } else { l2r };
                if toward_link {
                    st.to_link += sent;
                } else {
                    st.to_remote += sent;
                }
                st.send_errors += failed;
            }
            if n < BATCH {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- install time: unit, check, status

pub fn banner(r: &Relay) -> String {
    let mut b = format!(
        "relay: default deny. It forwards only the {} declared rule(s) between {} and machines on {}, from its own address {}; everything else is dropped and counted.",
        r.rules.len(),
        r.remote_interface,
        r.link_interface,
        r.link_address
    );
    for p in &r.proxies {
        b.push_str(&format!(
            " Proxy address {} stands for {} on the link, held only while its tunnel is up and no other machine answers for it.",
            p.address, p.remote
        ));
    }
    b
}

/// The relay's unit, keyed by its path. Empty without a [relay].
pub fn render(cfg: &Config) -> std::collections::BTreeMap<String, String> {
    let mut files = std::collections::BTreeMap::new();
    if cfg.relay.is_none() {
        return files;
    }
    let proxy = !cfg.relay.as_ref().unwrap().proxies.is_empty();
    let h = format!(
        "# Written by goatrope {} from {}/goatrope.toml. goatrope uninstall removes it; do not edit.\n",
        crate::version(),
        crate::tap::ETC
    );
    files.insert(
        format!("/etc/systemd/system/{UNIT}"),
        format!(
            "{h}[Unit]
Description=goatrope: relay, the declared rules only (default deny)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart={bin} relay --config {etc}/goatrope.toml
Restart=on-failure
RestartSec=3
# a refusal (exit {refused}) is not restarted: the unit stays failed, and goatrope check shows it
RestartPreventExitStatus={refused}
{l2}# SO_BINDTODEVICE (and ARP probes for a proxy address) need CAP_NET_RAW; the boundary interface and proxy addresses (netlink) need CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={state}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX{packet}

[Install]
WantedBy=multi-user.target
",
            bin = crate::tap::BIN,
            etc = crate::tap::ETC,
            state = crate::tap::STATE_DIR,
            refused = crate::EXIT_REFUSED,
            // ARP probes and announcements for a proxy address go through a packet socket
            packet = if proxy { " AF_PACKET" } else { "" },
            l2 = crate::l2::unit_lines(cfg),
        ),
    );
    let r = cfg.relay.as_ref().unwrap();
    files.insert(crate::relay_filter::SYSCTL.to_string(), crate::relay_filter::sysctl_file(r, &h));
    files
}

pub fn units(cfg: &Config) -> Vec<String> {
    if cfg.relay.is_some() {
        vec![UNIT.to_string()]
    } else {
        vec![]
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// relay.health as the relay wrote it, parsed, and its age in seconds.
fn read_health() -> Option<(serde_json::Value, f64)> {
    let v: serde_json::Value = serde_json::from_str(&su::read(HEALTH)?).ok()?;
    let t = v.get("time")?.as_f64()?;
    Some((v, now() - t))
}

/// Wait up to `seconds` for the relay to write relay.health or for its unit to stop.
pub fn settle(cfg: &Config, seconds: f64) {
    if cfg.relay.is_none() {
        return;
    }
    let end = Instant::now() + Duration::from_secs_f64(seconds);
    while Instant::now() < end {
        if read_health().is_some_and(|(_, age)| age < 1.5) || su::unit_active(UNIT) != "active" {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn check(cfg: &Config) -> Vec<Item> {
    let mut items = Vec::new();
    if cfg.relay.is_none() {
        return items;
    }
    let (want, have) = match read_health() {
        Some((_, age)) => (Some(age <= STALE_S), format!("written {age:.1} s ago")),
        None => (Some(false), "absent".to_string()),
    };
    item(&mut items, "relay-health", want, format!("written in the last {STALE_S:.0} s"), have);
    let health = read_health();
    if let Some((v, _)) = &health {
        let (ok, have) = interfaces_state(v, cfg.relay.as_ref().unwrap());
        item(&mut items, "relay-interfaces", Some(ok), "the relay's sockets are bound to its interfaces as they are now", have);
    }
    proxy::check(cfg.relay.as_ref().unwrap(), health.as_ref().map(|(v, _)| v), &mut items);
    items.extend(crate::relay_filter::check(cfg, health.as_ref().map(|(v, _)| v)));
    items
}

/// From relay.health: whether the relay is bound to the declaration's interfaces under their live index,
/// and in words. Only the interfaces this declaration names are compared.
fn interfaces_state(v: &serde_json::Value, r: &Relay) -> (bool, String) {
    if let Some(w) = v["waiting"].as_array().filter(|w| !w.is_empty()) {
        let names: Vec<&str> = w.iter().filter_map(|x| x.as_str()).collect();
        return (false, format!("waiting for {}", names.join(", ")));
    }
    let Some(bound) = v["interfaces"].as_object() else {
        return (true, "not reported".into());
    };
    let mut bad = Vec::new();
    let mut good = Vec::new();
    let declared = [&r.remote_interface, &r.link_interface];
    for (name, idx) in bound.iter().filter(|(n, _)| declared.contains(n)) {
        let was = idx.as_u64().map(|i| i as u32);
        match (was, ifindex(name)) {
            (Some(w), Some(n)) if w == n => good.push(format!("{name} (index {n})")),
            (w, n) => bad.push(format!(
                "{name} bound under index {}, now {}",
                w.map(|x| x.to_string()).unwrap_or("none".into()),
                n.map(|x| x.to_string()).unwrap_or("gone".into())
            )),
        }
    }
    if good.is_empty() && bad.is_empty() {
        (true, "not reported for this declaration's interfaces".into())
    } else if bad.is_empty() {
        (true, format!("bound to {}", good.join(", ")))
    } else {
        (false, bad.join("; "))
    }
}

pub fn status(cfg: &Config) {
    let Some(r) = &cfg.relay else { return };
    println!("  relay  {} ({UNIT}), from {} to {} as {}", su::unit_active(UNIT), r.remote_interface, r.link_interface, r.link_address);
    let health = read_health();
    match &health {
        Some((_, age)) => println!("  relay  counters written {age:.1} s ago{}", if *age > STALE_S { " (stale)" } else { "" }),
        None => println!("  relay  no counters yet ({HEALTH} absent)"),
    }
    if let Some((v, _)) = &health {
        let (ok, have) = interfaces_state(v, r);
        println!("  relay  {have}{}", if ok { "" } else { " (not forwarding)" });
        let n = |k: &str| v["reassembly"][k].as_u64().unwrap_or(0);
        if n("failed") + n("timed_out") > 0 {
            println!(
                "  relay  this machine failed to reassemble {} fragmented datagram(s), {} timed out, since the relay started: fragmented traffic is lost while that lasts",
                n("failed"),
                n("timed_out")
            );
        }
    }
    crate::relay_filter::status(r);
    proxy::status(r, health.as_ref().map(|(v, _)| v));
    for rule in &r.rules {
        let line = match (rule.link_initiated(), rule.protocol.as_str()) {
            (true, "tcp") => format!(
                "tcp port {} on {}: connections from {} go to {} (at most {} at once)",
                rule.listen_port,
                r.link_interface,
                rule.sources.join(", "),
                dest_of(rule),
                rule.max_connections
            ),
            (true, _) => format!(
                "udp port {} on {}: datagrams from {} go to {}, and its replies back",
                rule.listen_port,
                r.link_interface,
                rule.sources.join(", "),
                dest_of(rule)
            ),
            (false, "tcp") => format!(
                "tcp port {}: connections from {} go to {} (at most {} at once)",
                rule.listen_port,
                rule.remote,
                dest_of(rule),
                rule.max_connections
            ),
            (false, _) => format!(
                "udp port {}: from {} to {}{}",
                rule.listen_port,
                rule.remote,
                dest_of(rule),
                if rule.direction == "both" { ", and the target's replies back" } else { "" }
            ),
        };
        let from = rule.link_address.as_ref().map(|a| format!(" (on the link as proxy address {a})")).unwrap_or_default();
        println!("  rule   {line}{from}");
        let row = health.as_ref().and_then(|(v, _)| {
            v["rules"]
                .as_array()?
                .iter()
                .find(|x| {
                    x["listen_port"].as_u64() == Some(rule.listen_port as u64)
                        && x["protocol"].as_str().unwrap_or("udp") == rule.protocol
                        && x["direction"].as_str().is_none_or(|d| d == rule.direction)
                })
                .cloned()
        });
        if let Some(x) = row {
            let n = |k: &str| x[k].as_u64().unwrap_or(0);
            if rule.protocol == "tcp" {
                println!(
                    "         {} open now, {} accepted, {} bytes to the link, {} bytes to the remote, {} denied, {} over the limit, {} could not connect, {} broken",
                    n("connections"),
                    n("accepted"),
                    n("bytes_to_link"),
                    n("bytes_to_remote"),
                    n("denied"),
                    n("over_limit"),
                    n("send_errors"),
                    n("broken")
                );
            } else {
                println!(
                    "         {} sent to the link, {} sent to the remote, {} denied, {} could not be sent",
                    n("to_link"),
                    n("to_remote"),
                    n("denied"),
                    n("send_errors")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_float_matches_python() {
        assert_eq!(json_float(1764000000.0), "1764000000.0");
        assert_eq!(json_float(1764000000.25), "1764000000.25");
        assert_eq!(json_float(0.1), "0.1");
    }
}
