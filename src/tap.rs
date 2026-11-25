// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The tap role. Ported so far: the banner that `validate`, `install` and `status` print.

use crate::config::Tap;

pub fn banner(tap: &Tap) -> String {
    if tap.mode == "inline" {
        return "tap: inline, fail-closed. Every frame of the link passes through this machine; \
                the link is down whenever it is off, restarting or hung."
            .to_string();
    }
    format!(
        "tap: listen ({}), receive only. The link does not pass through this machine; \
         while it is off only the recording has a gap.",
        tap.source.as_deref().unwrap_or("")
    )
}
