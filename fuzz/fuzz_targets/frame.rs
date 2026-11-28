// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Frames from a tapped link, as decode-and-send reads them: Ethernet, IPv4, UDP and fragment
//! reassembly. The input is a run of frames, each preceded by its length (two bytes, big endian),
//! fed to one reassembly buffer, with no match and with one, so fragments meet each other.
#![no_main]

use goatrope::config::Match;
use goatrope::send::{parse, Fragments};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let m = Match { protocol: "udp".into(), src: Some("192.0.2.10".into()), dst: None, src_port: None, dst_port: Some(5000) };
    let mut all = Fragments::new();
    let mut matched = Fragments::new();
    let mut rest = data;
    while rest.len() >= 2 {
        let n = (u16::from_be_bytes([rest[0], rest[1]]) as usize).min(rest.len() - 2);
        let frame = &rest[2..2 + n];
        if let Some(d) = parse(frame, &mut all, None) {
            assert!(d.payload.len() <= 65535);
        }
        let _ = parse(frame, &mut matched, Some(&m));
        rest = &rest[2 + n..];
    }
});
