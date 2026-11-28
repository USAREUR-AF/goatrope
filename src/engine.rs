// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The goat-transformers engine, linked into goatrope (docs/adr/0006-data-path.md).
//!
//! A `[[send]]` with a `convert` converts in its own process with this engine: the packs are
//! loaded once at start, and each message costs one call. There is no other converter. The engine is
//! a pinned crate dependency (Cargo.toml names the commit, Cargo.lock records it), so the code
//! that converts is part of the goatrope binary the deployment already pins. The packs are
//! data: their digest is declared (`packs_sha256`), the files are read once, hashed, and the
//! engine loads those same bytes, so what was checked is what loads: the guarantee goatrope
//! gives a pinned binary (hash and copy in one read, run the copy), kept for the packs.

use std::fs;
use std::path::{Path, PathBuf};

use goat_transformers::Engine;
use sha2::{Digest, Sha256};

use crate::config::Convert;

/// The engine's crate version. `convert.version` must name it.
pub const VERSION: &str = "0.8.0";
/// The goat-transformers commit Cargo.toml pins; a unit test holds it to Cargo.lock.
pub const COMMIT: &str = "37d243021cb404f1f090d36d64d9bb567f60b126";

pub fn describe() -> String {
    format!("goat-transformers {VERSION} (commit {})", &COMMIT[..12])
}

/// The pack names a conversion loads: the part of each format before a colon, once each.
pub fn pack_names(c: &Convert) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for f in [&c.from_format, &c.to_format] {
        let p = f.split(':').next().unwrap_or("").to_string();
        if !names.contains(&p) {
            names.push(p);
        }
    }
    names
}

/// What a conversion loads, read once: each named pack's `pack.def`, and `core` with the model
/// modules the packs use, and the modules those use, from `model/` beside the packs directory, in
/// an order where each module follows the modules it uses (as `adapters/core/src/pipeline.rs` of
/// goat-transformers selects them). The engine loads these bytes, so what was hashed is what loads.
struct Selected {
    /// (path relative to the tree, as if the packs directory were called `packs`; bytes), in path order
    files: Vec<(String, Vec<u8>)>,
    /// module texts in load order
    modules: Vec<String>,
    packs: Vec<goat_transformers::Pack>,
}

fn word(line: &str, key: &str) -> Option<String> {
    let mut t = line.split_whitespace();
    (t.next() == Some(key)).then(|| t.next().map(|s| s.to_string())).flatten()
}

fn select(c: &Convert) -> Result<Selected, String> {
    let packs_dir = Path::new(&c.packs);
    let model = packs_dir.parent().map(|p| p.join("model")).unwrap_or_else(|| PathBuf::from("model"));
    let mut files = Vec::new();
    let mut packs = Vec::new();
    let mut need: Vec<String> = vec!["core".to_string()];
    for n in pack_names(c) {
        if n.is_empty() || n == "." || n == ".." || n.contains('/') {
            return Err(format!("`{n}` is not a pack name"));
        }
        let p = packs_dir.join(&n).join("pack.def");
        let data = fs::read(&p).map_err(|err| format!("no pack {n}: {}: {err}", p.display()))?;
        let text = String::from_utf8(data.clone()).map_err(|_| format!("{}: not UTF-8", p.display()))?;
        let pack = goat_transformers::Pack::parse(&text).map_err(|e| format!("{} (in {})", e, p.display()))?;
        need.extend(pack.uses.iter().filter(|u| !need.contains(u)).cloned().collect::<Vec<_>>());
        packs.push(pack);
        files.push((format!("packs/{n}/pack.def"), data));
    }
    // every module file's name and uses (each file read and let go), then the closure of what the
    // packs need; only those files are read again, and those bytes are what is hashed and loaded
    let mut all: Vec<(String, Vec<String>, PathBuf)> = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(&model)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().and_then(|s| s.to_str()) == Some("def")).collect())
        .unwrap_or_default();
    paths.sort();
    for f in paths {
        let text = fs::read_to_string(&f).map_err(|err| format!("{}: {err}", f.display()))?;
        let name = text.lines().find_map(|l| word(l, "module")).unwrap_or_default();
        let uses = text.lines().filter_map(|l| word(l, "uses")).filter(|u| *u != name).collect();
        all.push((name, uses, f));
    }
    let mut i = 0;
    while i < need.len() {
        if let Some(m) = all.iter().find(|m| m.0 == need[i]) {
            let more: Vec<String> = m.1.iter().filter(|u| !need.contains(u)).cloned().collect();
            need.extend(more);
        }
        i += 1;
    }
    let mut pending: Vec<_> = all.into_iter().filter(|m| need.contains(&m.0)).collect();
    pending.sort_by_key(|m| m.0 != "core");
    let (mut loaded, mut modules) = (Vec::<String>::new(), Vec::new());
    while !pending.is_empty() {
        let names: Vec<String> = pending.iter().map(|m| m.0.clone()).collect();
        let Some(at) = pending.iter().position(|m| m.1.iter().all(|u| loaded.contains(u) || !names.contains(u))) else {
            return Err(format!("the `uses` lines of model modules {} form a cycle", names.join(", ")));
        };
        let (name, _, path) = pending.remove(at);
        let data = fs::read(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        let text = String::from_utf8(data.clone()).map_err(|_| format!("{}: not UTF-8", path.display()))?;
        if text.lines().find_map(|l| word(l, "module")).as_deref() != Some(name.as_str()) {
            return Err(format!("{} changed while it was read", path.display()));
        }
        modules.push(text);
        files.push((format!("model/{}", path.file_name().unwrap().to_string_lossy()), data));
        loaded.push(name);
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Selected { files, modules, packs })
}

/// The packs digest: SHA-256 over, for each file in path order, its relative path, a NUL, its
/// length in decimal, a NUL and its bytes.
pub fn digest_of(files: &[(String, Vec<u8>)]) -> String {
    let mut h = Sha256::new();
    for (path, data) in files {
        h.update(path.as_bytes());
        h.update([0]);
        h.update(data.len().to_string().as_bytes());
        h.update([0]);
        h.update(data);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest of what a conversion loads, as it is on disk now.
pub fn digest(c: &Convert) -> Result<String, String> {
    Ok(digest_of(&select(c)?.files))
}

/// The engine with a conversion's packs loaded from the bytes that were hashed.
pub struct Linked {
    engine: Engine,
    from: String,
    to: String,
    /// the files loaded
    pub files: usize,
    /// how long reading, hashing and loading them took, s
    pub load_s: f64,
    /// this process's resident memory after the load, and its peak until then, KiB (/proc/self/status)
    pub rss_kib: u64,
    pub peak_rss_kib: u64,
}

/// VmRSS and VmHWM of this process, KiB.
pub fn rss() -> (u64, u64) {
    let t = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kib =
        |k: &str| t.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    (kib("VmRSS:"), kib("VmHWM:"))
}

/// The time of each conversion: the last SAMPLES in a ring for p50 and p99, the maximum and the
/// count since start. `status` and the heartbeat report them (docs/adr/0006-data-path.md: a
/// conversion takes a millisecond or less).
pub struct Timings {
    ring: Vec<u64>,
    next: usize,
    pub count: u64,
    pub max_ns: u64,
}

const SAMPLES: usize = 16384;

impl Default for Timings {
    fn default() -> Self {
        Timings { ring: Vec::with_capacity(SAMPLES), next: 0, count: 0, max_ns: 0 }
    }
}

impl Timings {
    pub fn record(&mut self, ns: u64) {
        if self.ring.len() < SAMPLES {
            self.ring.push(ns);
        } else {
            self.ring[self.next] = ns;
        }
        self.next = (self.next + 1) % SAMPLES;
        self.count += 1;
        self.max_ns = self.max_ns.max(ns);
    }

    /// `{"count": n, "p50_us": x, "p99_us": y, "max_us": z}`; p50 and p99 over the last SAMPLES.
    pub fn json(&self) -> String {
        let mut v = self.ring.clone();
        v.sort_unstable();
        let q = |p: f64| if v.is_empty() { 0.0 } else { v[((v.len() - 1) as f64 * p).round() as usize] as f64 / 1000.0 };
        format!(
            "{{\"count\": {}, \"p50_us\": {:.1}, \"p99_us\": {:.1}, \"max_us\": {:.1}}}",
            self.count,
            q(0.5),
            q(0.99),
            self.max_ns as f64 / 1000.0
        )
    }
}

impl Linked {
    pub fn load(c: &Convert, want: &str) -> Result<Linked, String> {
        let t = std::time::Instant::now();
        let sel = select(c)?;
        let have = digest_of(&sel.files);
        if have != want {
            return Err(format!("the packs under {} have digest {have}, not the declared packs_sha256 {want}", c.packs));
        }
        let mut engine = Engine::new();
        for m in &sel.modules {
            engine.load_model(m).map_err(|e| e.to_string())?;
        }
        for p in sel.packs {
            engine.load(p).map_err(|e| e.to_string())?;
        }
        let files = sel.files.len();
        drop(sel.files);
        let load_s = t.elapsed().as_secs_f64();
        let (rss_kib, peak_rss_kib) = rss();
        Ok(Linked { engine, from: c.from_format.clone(), to: c.to_format.clone(), files, load_s, rss_kib, peak_rss_kib })
    }

    /// One payload, given to the engine as hexadecimal text (as `goat-xf convert` reads it); the
    /// output with its trailing newlines removed.
    pub fn convert(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut input = String::with_capacity(payload.len() * 2 + 1);
        for b in payload {
            input.push_str(&format!("{b:02x}"));
        }
        input.push('\n');
        let out = self.engine.convert_text(&self.from, &self.to, &input, None).map_err(|e| e.to_string())?;
        let mut o = out.into_bytes();
        while o.last() == Some(&b'\n') {
            o.pop();
        }
        Ok(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_matches_cargo_lock() {
        let lock = include_str!("../Cargo.lock");
        assert!(lock.contains(&format!("goat-transformers?rev={COMMIT}#{COMMIT}")), "Cargo.lock does not pin {COMMIT}");
        assert!(lock.contains(&format!("name = \"goat-transformers\"\nversion = \"{VERSION}\"")));
    }

    #[test]
    fn timings_report_quantiles_and_max() {
        let mut t = Timings::default();
        for us in 1..=100u64 {
            t.record(us * 1000);
        }
        let v: serde_json::Value = serde_json::from_str(&t.json()).unwrap();
        assert_eq!(v["count"], 100);
        assert_eq!((v["p50_us"].as_f64(), v["p99_us"].as_f64(), v["max_us"].as_f64()), (Some(51.0), Some(99.0), Some(100.0)));
        for _ in 0..SAMPLES {
            t.record(5000);
        }
        let v: serde_json::Value = serde_json::from_str(&t.json()).unwrap();
        assert_eq!((v["p99_us"].as_f64(), v["max_us"].as_f64()), (Some(5.0), Some(100.0)));
    }

    #[test]
    fn digest_is_path_length_and_bytes() {
        let a = digest_of(&[("model/core.def".into(), b"x".to_vec())]);
        let b = digest_of(&[("model/core.def".into(), b"y".to_vec())]);
        let c = digest_of(&[("model/core.dex".into(), b"x".to_vec())]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        // the same as the documented construction
        let mut h = Sha256::new();
        h.update(b"model/core.def\x001\x00x");
        assert_eq!(a, h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}
