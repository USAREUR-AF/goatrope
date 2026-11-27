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
    let addrs = nl::addresses(&r.link_interface);
    if !addrs.contains(&r.link_address) {
        let have = if addrs.is_empty() { "none".to_string() } else { addrs.join(", ") };
        return refuse(format!(
            "{} does not hold {} (it has {have}); configure the relay's own address on its interface first",
            r.link_interface, r.link_address
        ));
    }
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
    Ok(())
}

fn forwarding(r: &Relay) -> Vec<String> {
    let mut on: Vec<String> = [&r.remote_interface, &r.link_interface]
        .iter()
        .flat_map(|i| sys::forwarding(i).into_iter().map(move |fam| format!("{fam} on {i}")))
        .collect();
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

/// A socket of type `ty` (SOCK_DGRAM, SOCK_STREAM) bound to one device (SO_BINDTODEVICE) and to addr:port.
pub(crate) fn bound_fd(dev: &str, addr: IpAddr, port: u16, ty: libc::c_int) -> io::Result<OwnedFd> {
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
    let sock = UdpSocket::from(bound_fd(dev, addr, port, libc::SOCK_DGRAM)?);
    sock.set_nonblocking(true)?;
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
    to_link: u64,
    to_remote: u64,
    denied: u64,
    send_errors: u64,
}

impl RuleState<'_> {
    fn count(&mut self, toward_link: bool) {
        if toward_link {
            self.to_link += 1;
        } else {
            self.to_remote += 1;
        }
    }
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

fn health_json(time: f64, state: &[RuleState], tcp: &[(&RelayRule, Arc<relay_tcp::Counters>)]) -> String {
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
    format!("{{\"time\": {}, \"rules\": [{}]}}", json_float(time), rows.join(", "))
}

fn health(state: &[RuleState], tcp: &[(&RelayRule, Arc<relay_tcp::Counters>)]) -> Result<(), String> {
    let dir = std::path::Path::new(HEALTH).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| sys::oserror(&e, &dir.to_string_lossy()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let tmp = format!("{HEALTH}.new");
    let res = std::fs::write(&tmp, health_json(now, state, tcp))
        .map_err(|e| sys::oserror(&e, &tmp))
        .and_then(|_| std::fs::rename(&tmp, HEALTH).map_err(|e| sys::oserror(&e, &tmp)));
    if let Err(e) = res {
        println!("health: {e}");
    }
    Ok(())
}

pub fn run(cfg: &Config) -> i32 {
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
    let r = cfg.relay.as_ref().unwrap();
    let link_ip = r.link_address.split('/').next().unwrap_or_default();
    let link_addr: IpAddr = link_ip.parse().map_err(|_| format!("bad link address {link_ip}"))?;
    let ip = |s: &str| -> Result<IpAddr, String> { s.parse().map_err(|_| format!("bad address {s}")) };
    let mut state: Vec<RuleState> = Vec::new();
    let mut tcp: Vec<(&RelayRule, Arc<relay_tcp::Counters>)> = Vec::new();
    for rule in &r.rules {
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
            let c = relay_tcp::start(r, rule, link_addr, clients, dest)?;
            tcp.push((rule, c));
            println!("goatrope relay: {shown}");
            continue;
        }
        let (listen, outs) = if l2r {
            let listen = bound(&r.link_interface, link_addr, rule.listen_port).map_err(|e| sys::strerror(&e))?;
            let outs = clients.iter().map(|_| bound(&r.remote_interface, any_of(remote), 0)).collect::<io::Result<Vec<_>>>();
            (listen, outs.map_err(|e| sys::strerror(&e))?)
        } else {
            let listen = bound(&r.remote_interface, any_of(remote), rule.listen_port).map_err(|e| sys::strerror(&e))?;
            (listen, vec![bound(&r.link_interface, link_addr, 0).map_err(|e| sys::strerror(&e))?])
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
    health(&state, &tcp)?; // at once, so a service manager sees it running
    let mut last = Instant::now();
    let mut last_denied_log: Option<Instant> = None;
    let mut buf = vec![0u8; 65535];
    loop {
        let mut fds: Vec<libc::pollfd> = slots
            .iter()
            .map(|&(i, o)| match o {
                None => state[i].listen.as_raw_fd(),
                Some(k) => state[i].outs[k].as_raw_fd(),
            })
            .map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
            .collect();
        // SAFETY: fds is a valid array of pollfd of the length given (poll with none is a sleep).
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) };
        if n > 0 {
            for (j, pfd) in fds.iter().enumerate() {
                if pfd.revents == 0 {
                    continue;
                }
                let (i, out) = slots[j];
                let st = &mut state[i];
                let l2r = st.rule.link_initiated();
                let sock = match out {
                    None => &st.listen,
                    Some(k) => &st.outs[k],
                };
                let Ok((len, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let data = &buf[..len];
                let rule = st.rule;
                match out {
                    None => {
                        let Some(c) = st.clients.iter().position(|a| *a == src.ip()) else {
                            st.denied += 1;
                            if last_denied_log.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
                                let allowed = if l2r { rule.sources.join(", ") } else { rule.remote.clone() };
                                println!("denied: {}:{} -> port {} (allowed: {allowed})", src.ip(), src.port(), rule.listen_port);
                                last_denied_log = Some(Instant::now());
                            }
                            continue;
                        };
                        st.peers[c] = Some(src);
                        let Some(to) = st.dest else {
                            st.send_errors += 1;
                            continue;
                        };
                        match st.outs[c].send_to(data, to) {
                            Ok(_) => st.count(!l2r),
                            // dropped and counted; the relay keeps running
                            Err(_) => st.send_errors += 1,
                        }
                    }
                    Some(k) => {
                        let Some(peer) = st.peers[k].filter(|_| st.replies && Some(src) == st.dest) else {
                            st.denied += 1;
                            continue;
                        };
                        match st.listen.send_to(data, peer) {
                            Ok(_) => st.count(l2r),
                            // the tunnel is down or the peer has no endpoint: dropped and counted
                            Err(_) => st.send_errors += 1,
                        }
                    }
                }
            }
        }
        if last.elapsed() >= Duration::from_secs(2) {
            health(&state, &tcp)?;
            last = Instant::now();
            let fwd = forwarding(r);
            if !fwd.is_empty() {
                eprintln!("goatrope relay: stopping: IP forwarding was turned on ({})", fwd.join(", "));
                return Ok(crate::EXIT_ERROR);
            }
            if r.transport == "boundary" {
                let drift = boundary::check(r.boundary.as_ref().unwrap(), &r.remote_interface);
                if !drift.is_empty() {
                    eprintln!("goatrope relay: stopping: {} no longer matches the declaration: {}", r.remote_interface, drift.join("; "));
                    return Ok(crate::EXIT_ERROR);
                }
            }
        }
    }
}

// ---------------------------------------------------------------- install time: unit, check, status

pub fn banner(r: &Relay) -> String {
    format!(
        "relay: default deny. It forwards only the {} declared rule(s) between {} and machines on {}, from its own address {}; everything else is dropped and counted.",
        r.rules.len(),
        r.remote_interface,
        r.link_interface,
        r.link_address
    )
}

/// The relay's unit, keyed by its path. Empty without a [relay].
pub fn render(cfg: &Config) -> std::collections::BTreeMap<String, String> {
    let mut files = std::collections::BTreeMap::new();
    if cfg.relay.is_none() {
        return files;
    }
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
# SO_BINDTODEVICE needs CAP_NET_RAW; the boundary interface (netlink) needs CAP_NET_ADMIN
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX

[Install]
WantedBy=multi-user.target
",
            bin = crate::tap::BIN,
            etc = crate::tap::ETC,
            state = crate::tap::STATE_DIR,
            refused = crate::EXIT_REFUSED,
        ),
    );
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
    items
}

pub fn status(cfg: &Config) {
    let Some(r) = &cfg.relay else { return };
    println!("  relay  {} ({UNIT}), from {} to {} as {}", su::unit_active(UNIT), r.remote_interface, r.link_interface, r.link_address);
    let health = read_health();
    match &health {
        Some((_, age)) => println!("  relay  counters written {age:.1} s ago{}", if *age > STALE_S { " (stale)" } else { "" }),
        None => println!("  relay  no counters yet ({HEALTH} absent)"),
    }
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
        println!("  rule   {line}");
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
                    "         {} open now, {} accepted, {} bytes to the link, {} bytes to the remote, {} denied, {} over the limit, {} could not connect",
                    n("connections"),
                    n("accepted"),
                    n("bytes_to_link"),
                    n("bytes_to_remote"),
                    n("denied"),
                    n("over_limit"),
                    n("send_errors")
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
