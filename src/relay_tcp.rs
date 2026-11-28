// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Relay TCP rules (docs/adr/0004 §2).
//!
//! A rule listens on one side and connects on the other. remote-to-link: it listens on the
//! remote interface, accepts a connection only from the rule's `remote` (WireGuard has
//! authenticated that address), and connects to the target from the relay's link address.
//! link-to-remote: it listens on the relay's link address, accepts a connection only from a
//! declared `sources` address (the link is not authenticated, so the list is the control), and
//! connects to the remote through the remote interface. It then copies both ways until each side
//! has closed; a side that closes its sending half (shutdown) is passed on as a half-close.
//!
//! Every other connection is closed at once and counted as denied. At most `max_connections`
//! are open on a rule at once; one more is closed and counted as over the limit.
//!
//! A peer that vanishes without closing (the normal case when a WireGuard path dies) is found
//! within DEAD_PEER_S: both sockets of a connection send keepalive probes after 60 s idle, every
//! 10 s, and give up after 6 unanswered (TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT), and data
//! not acknowledged within the same 120 s fails the connection (TCP_USER_TIMEOUT). The
//! connection is then closed both ways and counted as broken. TCP_NODELAY is set on both
//! sockets: tactical feeds are small messages, and Nagle's algorithm would hold them back.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{Relay, RelayRule};
use crate::proxy::Hold;
use crate::relay::{any_of, bound_fd_free};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPIDLE_S: libc::c_int = 60;
const KEEPINTVL_S: libc::c_int = 10;
const KEEPCNT: libc::c_int = 6;
/// The longest a dead peer holds a connection slot: KEEPIDLE_S + KEEPINTVL_S * KEEPCNT.
pub const DEAD_PEER_S: libc::c_int = KEEPIDLE_S + KEEPINTVL_S * KEEPCNT;

/// A rule's counters, written to relay.health by the relay's main loop.
#[derive(Default)]
pub struct Counters {
    /// connections open now
    pub open: AtomicU64,
    pub accepted: AtomicU64,
    pub bytes_to_link: AtomicU64,
    pub bytes_to_remote: AtomicU64,
    pub denied: AtomicU64,
    pub over_limit: AtomicU64,
    /// connections to the far side that failed
    pub send_errors: AtomicU64,
    /// connections ended by an error: a reset, or a peer that stopped answering (keepalive, user timeout)
    pub broken: AtomicU64,
}

impl Counters {
    /// The counters as the fields of a relay.health row.
    pub fn json(&self) -> String {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "\"connections\": {}, \"accepted\": {}, \"bytes_to_link\": {}, \"bytes_to_remote\": {}, \"denied\": {}, \"over_limit\": {}, \"send_errors\": {}, \"broken\": {}",
            n(&self.open),
            n(&self.accepted),
            n(&self.bytes_to_link),
            n(&self.bytes_to_remote),
            n(&self.denied),
            n(&self.over_limit),
            n(&self.send_errors),
            n(&self.broken)
        )
    }
}

fn listener(dev: &str, addr: IpAddr, port: u16, freebind: bool) -> io::Result<TcpListener> {
    let fd = bound_fd_free(dev, addr, port, libc::SOCK_STREAM, freebind)?;
    // SAFETY: fd is a bound stream socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

/// A connection to `to` from a socket bound to `dev` and `from`, given up after CONNECT_TIMEOUT.
pub(crate) fn connect(dev: &str, from: IpAddr, to: SocketAddr) -> io::Result<TcpStream> {
    let fd = bound_fd_free(dev, from, 0, libc::SOCK_STREAM, false)?;
    let tv = |d: Duration| libc::timeval { tv_sec: d.as_secs() as libc::time_t, tv_usec: 0 };
    // a blocking connect gives up after the send timeout
    set_timeval(fd.as_raw_fd(), tv(CONNECT_TIMEOUT))?;
    let (sa, len) = crate::relay::sockaddr_of(to);
    // SAFETY: sa is a socket address of the length given.
    if unsafe { libc::connect(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    set_timeval(fd.as_raw_fd(), tv(Duration::ZERO))?;
    Ok(TcpStream::from(fd))
}

fn opt(fd: libc::c_int, level: libc::c_int, name: libc::c_int, v: libc::c_int) -> io::Result<()> {
    // SAFETY: v is a c_int of the size given.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Keepalive, the user timeout and no Nagle delay, on one connection's socket.
fn tune(s: &TcpStream) -> io::Result<()> {
    let fd = s.as_raw_fd();
    opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, KEEPIDLE_S)?;
    opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, KEEPINTVL_S)?;
    opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, KEEPCNT)?;
    opt(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, DEAD_PEER_S * 1000)?;
    opt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)
}

fn set_timeval(fd: libc::c_int, tv: libc::timeval) -> io::Result<()> {
    // SAFETY: tv is a timeval of the size given.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Copy from one stream to the other until the sender closes, then close the sending half of
/// the other (a half-close). An error closes both streams both ways; it returns false then.
fn pump(mut from: TcpStream, mut to: TcpStream, bytes: &AtomicU64) -> bool {
    let mut buf = vec![0u8; 16384];
    loop {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return true;
            }
            Ok(k) => {
                if to.write_all(&buf[..k]).is_err() {
                    break;
                }
                bytes.fetch_add(k as u64, Ordering::Relaxed);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
    false
}

/// Bind the rule's listening socket (an error is returned at once), then accept on a thread of its own.
///
/// `held`: the rule uses a proxy address (ADR 0004 §4). The link-side listener is then bound with
/// IP_FREEBIND, a connection toward the link is not made while the address is not held (a send
/// error), and each connection's link-side stream is registered, so the relay closes it before
/// it gives the address up.
pub fn start(
    r: &Relay,
    rule: &RelayRule,
    link_addr: IpAddr,
    held: Option<Hold>,
    clients: Vec<IpAddr>,
    dest: SocketAddr,
) -> Result<Arc<Counters>, String> {
    let l2r = rule.link_initiated();
    let (listen_dev, listen_addr) = if l2r { (&r.link_interface, link_addr) } else { (&r.remote_interface, any_of(clients[0])) };
    let (out_dev, out_addr) = if l2r { (r.remote_interface.clone(), any_of(dest.ip())) } else { (r.link_interface.clone(), link_addr) };
    let l = listener(listen_dev, listen_addr, rule.listen_port, l2r && held.is_some()).map_err(|e| crate::sys::strerror(&e))?;
    let c = Arc::new(Counters::default());
    let counters = c.clone();
    let max = rule.max_connections as u64;
    let port = rule.listen_port;
    let allowed = clients.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
    std::thread::spawn(move || {
        let mut last_log: Option<Instant> = None;
        let mut log = |msg: String| {
            if last_log.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
                println!("{msg}");
                last_log = Some(Instant::now());
            }
        };
        loop {
            let (conn, peer) = match l.accept() {
                Ok(x) => x,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(100)); // out of descriptors, for one: try again
                    continue;
                }
            };
            if !clients.contains(&peer.ip()) {
                c.denied.fetch_add(1, Ordering::Relaxed);
                log(format!("denied: tcp {peer} -> port {port} (allowed: {allowed})"));
                drop(conn);
                continue;
            }
            if c.open.load(Ordering::Relaxed) >= max {
                c.over_limit.fetch_add(1, Ordering::Relaxed);
                log(format!("over the limit: tcp {peer} -> port {port} ({max} connections open)"));
                drop(conn);
                continue;
            }
            c.open.fetch_add(1, Ordering::Relaxed);
            c.accepted.fetch_add(1, Ordering::Relaxed);
            let c = c.clone();
            let out_dev = out_dev.clone();
            let held = held.clone();
            std::thread::spawn(move || {
                session(conn, &out_dev, out_addr, dest, l2r, &c, held);
                c.open.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(counters)
}

fn session(conn: TcpStream, out_dev: &str, out_addr: IpAddr, dest: SocketAddr, l2r: bool, c: &Arc<Counters>, held: Option<Hold>) {
    // remote-to-link connects from the proxy address: not while the relay does not hold it
    if !l2r && held.as_ref().is_some_and(|h| !h.held()) {
        c.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if tune(&conn).is_err() {
        c.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let out = match connect(out_dev, out_addr, dest) {
        Ok(s) => s,
        Err(_) => {
            c.send_errors.fetch_add(1, Ordering::Relaxed);
            return; // conn is dropped: the client sees the connection closed
        }
    };
    if tune(&out).is_err() {
        c.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let (Ok(conn2), Ok(out2)) = (conn.try_clone(), out.try_clone()) else {
        c.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // the link-side stream, so the relay can close it before it gives the proxy address up
    let reg = match &held {
        Some(h) => match h.register(if l2r { &conn } else { &out }) {
            Some(id) => Some((h, id)),
            None => {
                c.send_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        },
        None => None,
    };
    let c2 = c.clone();
    // forward: what the side that connected sends; back: what the far side answers
    let forward = std::thread::spawn(move || {
        let bytes = if l2r { &c2.bytes_to_remote } else { &c2.bytes_to_link };
        pump(conn2, out2, bytes)
    });
    let back = pump(out, conn, if l2r { &c.bytes_to_link } else { &c.bytes_to_remote });
    let fwd = forward.join().unwrap_or(false);
    if let Some((h, id)) = reg {
        h.unregister(id);
    }
    if !(back && fwd) {
        c.broken.fetch_add(1, Ordering::Relaxed);
    }
}
