// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! goatrope: the roles, the declaration and the machine they change. `src/main.rs` is the command
//! line over them; `fuzz/` drives the parsers of untrusted input through this library.
//!
//! Exit codes: 0 success or match; 2 refused or invalid declaration; 3 check differs; 1 error.

pub mod boundary;
pub mod config;
pub mod engine;
pub mod l2;
pub mod link;
pub mod nl;
pub mod proxy;
pub mod relay;
pub mod relay_filter;
pub mod relay_tcp;
pub mod send;
pub mod sys;
pub mod sysutil;
pub mod tap;
#[cfg(test)]
mod units;

pub const VERSION: &str = include_str!("../VERSION");

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_DIFFERS: i32 = 3;

/// The version of the software this binary belongs to: the VERSION file of the checkout,
/// unpacked release or installed tree it runs from, else the one it was built with. A release
/// is the archive, and its VERSION file is part of what the archive's hash covers.
pub fn version() -> String {
    if let Ok(exe) = std::env::current_exe().and_then(|e| e.canonicalize()) {
        let mut candidates: Vec<std::path::PathBuf> = exe.ancestors().skip(1).take(3).map(|d| d.join("VERSION")).collect();
        candidates.push("/usr/local/lib/goatrope/VERSION".into());
        candidates.push("/usr/local/lib/goatrope/goatrope/VERSION".into());
        for c in candidates {
            if let Ok(v) = std::fs::read_to_string(&c) {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    VERSION.trim().to_string()
}
