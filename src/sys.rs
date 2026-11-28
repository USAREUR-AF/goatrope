// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Small helpers for reading the machine and reporting errors as the Python tree did.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::link::SYS_NET;

/// The C library's message for an I/O error, without Rust's " (os error N)" suffix.
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// An I/O error as Python shows an OSError about a file: "[Errno 2] No such file or directory: 'path'".
pub fn oserror(e: &std::io::Error, path: &str) -> String {
    match e.raw_os_error() {
        Some(n) => format!("[Errno {n}] {}: '{path}'", strerror(e)),
        None => format!("{}: '{path}'", strerror(e)),
    }
}

/// A file's content without surrounding whitespace; None when it cannot be read.
pub fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Write a value to a file such as a sysctl under /proc/sys; false when it cannot be written.
pub fn write(path: &str, value: &str) -> bool {
    std::fs::write(path, value).is_ok()
}

pub fn exists(ifname: &str) -> bool {
    Path::new(&format!("{SYS_NET}/{ifname}")).exists()
}

/// The bridge or bond ifname belongs to, if any.
pub fn master(ifname: &str) -> Option<String> {
    let link = format!("{SYS_NET}/{ifname}/master");
    if !Path::new(&link).exists() {
        return None;
    }
    let target = std::fs::canonicalize(&link).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

/// Which IP families forward packets arriving on ifname.
pub fn forwarding(ifname: &str) -> Vec<&'static str> {
    ["ipv4", "ipv6"]
        .into_iter()
        .filter(|fam| read(&format!("/proc/sys/net/{fam}/conf/{ifname}/forwarding")).as_deref() == Some("1"))
        .collect()
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---------------------------------------------------------------- stop on a signal

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// SIGTERM (systemd stop), SIGINT and SIGHUP set a flag the relay loop reads, so it can remove
/// the proxy addresses it added before it exits. poll(2) returns EINTR on the signal.
pub fn catch_stop_signals() {
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: an all-zero sigaction is valid; the handler only stores to an atomic.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}
