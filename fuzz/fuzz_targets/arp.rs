// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! ARP packets from the relay's link, as the address proxy reads them: what decodes encodes back
//! to the same 28 bytes.
#![no_main]

use goatrope::proxy::Arp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(a) = Arp::decode(data) {
        assert_eq!(&a.encode()[..], &data[..28]);
    }
});
