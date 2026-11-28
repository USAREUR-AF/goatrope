// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The declaration: any text is valid or refused with a message, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Err(e) = goatrope::config::parse(text, "fuzz.toml") {
            assert!(!e.0.is_empty());
        }
    }
});
