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

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{Relay, RelayRule};
use crate::relay::{any_of, bound_fd};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
}

impl Counters {
    /// The counters as the fields of a relay.health row.
    pub fn json(&self) -> String {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "\"connections\": {}, \"accepted\": {}, \"bytes_to_link\": {}, \"bytes_to_remote\": {}, \"denied\": {}, \"over_limit\": {}, \"send_errors\": {}",
            n(&self.open),
            n(&self.accepted),
            n(&self.bytes_to_link),
            n(&self.bytes_to_remote),
            n(&self.denied),
            n(&self.over_limit),
            n(&self.send_errors)
        )
    }
}

fn listener(dev: &str, addr: IpAddr, port: u16) -> io::Result<TcpListener> {
    let fd = bound_fd(dev, addr, port, libc::SOCK_STREAM)?;
    // SAFETY: fd is a bound stream socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

/// A connection to `to` from a socket bound to `dev` and `from`, given up after CONNECT_TIMEOUT.
fn connect(dev: &str, from: IpAddr, to: SocketAddr) -> io::Result<TcpStream> {
    let fd = bound_fd(dev, from, 0, libc::SOCK_STREAM)?;
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
/// the other (a half-close). An error closes both streams both ways.
fn pump(mut from: TcpStream, mut to: TcpStream, bytes: &AtomicU64) {
    let mut buf = vec![0u8; 16384];
    loop {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
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
}

/// Bind the rule's listening socket (an error is returned at once), then accept on a thread of its own.
pub fn start(r: &Relay, rule: &RelayRule, link_addr: IpAddr, clients: Vec<IpAddr>, dest: SocketAddr) -> Result<Arc<Counters>, String> {
    let l2r = rule.link_initiated();
    let (listen_dev, listen_addr) = if l2r { (&r.link_interface, link_addr) } else { (&r.remote_interface, any_of(clients[0])) };
    let (out_dev, out_addr) = if l2r { (r.remote_interface.clone(), any_of(dest.ip())) } else { (r.link_interface.clone(), link_addr) };
    let l = listener(listen_dev, listen_addr, rule.listen_port).map_err(|e| crate::sys::strerror(&e))?;
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
            std::thread::spawn(move || {
                session(conn, &out_dev, out_addr, dest, l2r, &c);
                c.open.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(counters)
}

fn session(conn: TcpStream, out_dev: &str, out_addr: IpAddr, dest: SocketAddr, l2r: bool, c: &Arc<Counters>) {
    let out = match connect(out_dev, out_addr, dest) {
        Ok(s) => s,
        Err(_) => {
            c.send_errors.fetch_add(1, Ordering::Relaxed);
            return; // conn is dropped: the client sees the connection closed
        }
    };
    let (Ok(conn2), Ok(out2)) = (conn.try_clone(), out.try_clone()) else {
        c.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let c2 = c.clone();
    // forward: what the side that connected sends; back: what the far side answers
    let forward = std::thread::spawn(move || {
        let bytes = if l2r { &c2.bytes_to_remote } else { &c2.bytes_to_link };
        pump(conn2, out2, bytes)
    });
    pump(out, conn, if l2r { &c.bytes_to_link } else { &c.bytes_to_remote });
    let _ = forward.join();
}
