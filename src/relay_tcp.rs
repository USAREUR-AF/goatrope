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
//! A socket filter on the listening socket passes only SYNs (and every other segment) from those
//! addresses, so the kernel never answers another sender: no SYN-ACK, the port looks closed, as a
//! UDP rule's does, and the drop is counted (listener_drops). The relay checks the peer again after
//! accept; a connection that got past the filter is closed at once and counted as denied. At most `max_connections`
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
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
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
    /// the listening socket, whose kernel drop count is read for relay.health (-1: none yet)
    pub listen_fd: AtomicI32,
}

impl Default for Counters {
    fn default() -> Counters {
        Counters {
            open: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            bytes_to_link: AtomicU64::new(0),
            bytes_to_remote: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            over_limit: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            broken: AtomicU64::new(0),
            listen_fd: AtomicI32::new(-1),
        }
    }
}

impl Counters {
    /// The counters as the fields of a relay.health row.
    pub fn json(&self) -> String {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "\"connections\": {}, \"accepted\": {}, \"bytes_to_link\": {}, \"bytes_to_remote\": {}, \"denied\": {}, \"over_limit\": {}, \"send_errors\": {}, \"broken\": {}, \"listener_drops\": {}",
            n(&self.open),
            n(&self.accepted),
            n(&self.bytes_to_link),
            n(&self.bytes_to_remote),
            n(&self.denied),
            n(&self.over_limit),
            n(&self.send_errors),
            n(&self.broken),
            listener_drops(self.listen_fd.load(Ordering::Relaxed))
        )
    }
}

/// Packets the kernel dropped at a listening socket (SO_MEMINFO, SK_MEMINFO_DROPS): the SYNs and
/// other segments its source filter refused, and any dropped because the accept queue was full.
fn listener_drops(fd: libc::c_int) -> u64 {
    if fd < 0 {
        return 0;
    }
    let mut info = [0u32; 16]; // SK_MEMINFO_VARS is 9 today; room for more
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: info is a buffer of len bytes.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_MEMINFO, info.as_mut_ptr() as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return 0;
    }
    info[libc::SK_MEMINFO_DROPS as usize] as u64
}

/// A classic BPF socket filter that passes a packet only when its IP source address is one of
/// `allowed` (those of the listening socket's family). On a listening TCP socket the kernel runs it
/// before it answers a SYN, so a sender the rule does not name gets no SYN-ACK: the port looks
/// closed to it, as a UDP rule's does. Accepted connections inherit it.
fn source_filter(allowed: &[IpAddr], v6: bool) -> Vec<libc::sock_filter> {
    const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let net = |off: i32| (libc::SKF_NET_OFF + off) as u32;
    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let words: Vec<[u32; 4]> = allowed
        .iter()
        .filter_map(|a| match (a, v6) {
            (IpAddr::V4(x), false) => Some([u32::from_be_bytes(x.octets()), 0, 0, 0]),
            (IpAddr::V6(x), true) => {
                let o = x.octets();
                let w = |i: usize| u32::from_be_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
                Some([w(0), w(4), w(8), w(12)])
            }
            _ => None,
        })
        .collect();
    let mut prog = Vec::new();
    if !v6 {
        // the IPv4 source address, then one comparison per allowed address
        prog.push(ins(LD_W_ABS, 0, 0, net(12)));
        let n = words.len();
        for (k, w) in words.iter().enumerate() {
            prog.push(ins(JEQ_K, (n - k) as u8, 0, w[0])); // jump over the rest and the drop, to the accept
        }
    } else {
        // the IPv6 source address, four words, one block of eight per allowed address
        let n = words.len();
        for (b, w) in words.iter().enumerate() {
            // from the instruction at `at` in this block to the accept, past the rest and the drop
            let to_accept = |at: usize| ((n - b) * 8 - at) as u8;
            for (i, &word) in w.iter().enumerate() {
                prog.push(ins(LD_W_ABS, 0, 0, net(8 + 4 * i as i32)));
                let at = 2 * i + 1; // this comparison's index in the block
                if i == 3 {
                    prog.push(ins(JEQ_K, to_accept(at), 0, word));
                } else {
                    prog.push(ins(JEQ_K, 0, (6 - 2 * i) as u8, word)); // a mismatch skips to the next block
                }
            }
        }
    }
    prog.push(ins(RET_K, 0, 0, 0)); // drop
    prog.push(ins(RET_K, 0, 0, u32::MAX)); // accept the whole packet
    prog
}

fn attach_source_filter(fd: libc::c_int, allowed: &[IpAddr], v6: bool) -> io::Result<()> {
    let mut prog = source_filter(allowed, v6);
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
    // SAFETY: fprog points to prog, which outlives the call; the kernel copies it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const libc::sock_fprog as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // no process can take the filter off or replace it
    opt(fd, libc::SOL_SOCKET, libc::SO_LOCK_FILTER, 1)
}

fn listener(dev: &str, addr: IpAddr, port: u16, freebind: bool, allowed: &[IpAddr]) -> io::Result<TcpListener> {
    let fd = bound_fd_free(dev, addr, port, libc::SOCK_STREAM, freebind)?;
    // before listen(2): no SYN from another sender is answered, even for a moment
    attach_source_filter(fd.as_raw_fd(), allowed, addr.is_ipv6())?;
    // SAFETY: fd is a bound stream socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

/// A connection to `to` from a socket bound to `dev` and `from`, given up after CONNECT_TIMEOUT.
fn connect(dev: &str, from: IpAddr, to: SocketAddr) -> io::Result<TcpStream> {
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
    let l = listener(listen_dev, listen_addr, rule.listen_port, l2r && held.is_some(), &clients).map_err(|e| crate::sys::strerror(&e))?;
    let c = Arc::new(Counters::default());
    c.listen_fd.store(l.as_raw_fd(), Ordering::Relaxed);
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
            // the second layer: the source filter has already refused other senders' SYNs
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_filter_jumps_land_on_accept() {
        // the accept is the last instruction, the drop the one before; every comparison's true branch is the accept
        for (allowed, v6) in [
            (vec!["10.99.0.2".parse().unwrap(), "10.99.0.5".parse().unwrap()], false),
            (vec!["2001:db8::2".parse().unwrap(), "2001:db8::5".parse().unwrap(), "2001:db8::7".parse().unwrap()], true),
        ] {
            let p = source_filter(&allowed, v6);
            let accept = p.len() - 1;
            assert_eq!((p[accept].k, p[accept - 1].k), (u32::MAX, 0));
            let mut to_accept = 0;
            for (i, x) in p.iter().enumerate() {
                if x.code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16 {
                    if x.jt > 0 {
                        assert_eq!(i + 1 + x.jt as usize, accept, "instruction {i}");
                        to_accept += 1;
                    }
                    assert!(i + 1 + (x.jf as usize) < accept, "instruction {i} falls past the drop");
                }
            }
            assert_eq!(to_accept, allowed.len());
        }
    }
}
