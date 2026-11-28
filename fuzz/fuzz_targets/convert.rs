// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Payloads from a tapped link, as the linked converter reads them: Remote ID to Cursor on Target
//! with the packs of the pinned goat-transformers commit, found in GOATROPE_FUZZ_PACKS (its
//! `packs` directory, with `model` beside it). A conversion may fail; it must not panic.
#![no_main]

use std::sync::OnceLock;

use goatrope::config::Convert;
use goatrope::engine::{digest, Linked};
use libfuzzer_sys::fuzz_target;

fn engine() -> &'static Linked {
    static E: OnceLock<Linked> = OnceLock::new();
    E.get_or_init(|| {
        let packs = std::env::var("GOATROPE_FUZZ_PACKS").expect("GOATROPE_FUZZ_PACKS names the packs directory");
        let mut c = Convert { sha256: String::new(), from_format: "remote-id".into(), to_format: "cot-xml".into(), packs };
        c.sha256 = digest(&c).expect("the packs digest");
        Linked::load(&c, &c.sha256).expect("the packs load")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = engine().convert(data);
});
