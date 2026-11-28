// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! What the link may reach on the relay machine (#39).
//!
//! The relay holds its link address, and its proxy addresses while their tunnels are up, on
//! `link_interface`. The link is not authenticated, so the relay admits from it only what its
//! rules name. An nftables table of its own, `inet goatrope_relay`, on the input hook:
//!
//! - from `link_interface`: replies to flows the machine started (conntrack established or
//!   related), the link-to-remote rules' (protocol, port) pairs at the address each listens on,
//!   and IPv6 neighbor discovery when the link address is IPv6. Everything else is dropped and
//!   counted (`link_dropped`): the machine's own services do not answer the link.
//! - from any other interface but loopback: nothing addressed to the link or proxy addresses
//!   (`elsewhere_dropped`), so another network cannot reach them either.
//!
//! On `link_interface`, `arp_ignore = 1` (answer ARP only for addresses held on it, so the link
//! cannot resolve the machine's other addresses) and `arp_announce = 2` (ARP requests sent on the
//! link carry an address of the link). `goatrope install` writes them to a sysctl file; the relay
//! sets them itself when it runs without it and refuses when it cannot.
//!
//! The relay replaces the table at start, keeps its signature (the rules as the kernel lists
//! them), and compares it every 2 s; a difference stops the relay, whose restart puts it back.
//! The table stays when the relay stops, so a stopped relay still admits nothing new; `uninstall`
//! removes it.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde_json::Value;

use crate::config::{Config, Relay};
use crate::sysutil as su;
use crate::tap::{item, Item};

pub const TABLE: &str = "goatrope_relay";
pub const SYSCTL: &str = "/etc/sysctl.d/91-goatrope-relay.conf";
/// (key, value the relay requires) under net.ipv4.conf.<link_interface>
pub const ARP: [(&str, &str); 2] = [("arp_ignore", "1"), ("arp_announce", "2")];

/// The signature of the table as this relay process installed it.
static BASELINE: Mutex<Option<String>> = Mutex::new(None);

fn host(a: &str) -> &str {
    a.split('/').next().unwrap_or(a)
}

fn fam(a: &str) -> &'static str {
    if a.contains(':') {
        "ip6"
    } else {
        "ip"
    }
}

/// The addresses the relay holds on the link: its own and the proxy addresses.
fn addresses(r: &Relay) -> Vec<String> {
    let mut v = vec![host(&r.link_address).to_string()];
    v.extend(r.proxies.iter().map(|p| p.address.clone()));
    v
}

/// The table, as `nft -f` reads it.
pub fn ruleset(r: &Relay) -> String {
    let li = &r.link_interface;
    let own = host(&r.link_address);
    let mut link = vec!["\t\tct state established,related accept".to_string()];
    if own.contains(':') {
        link.push("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept".into());
    }
    // (address, protocol) -> ports, in declaration order
    let mut pairs: Vec<(String, String, Vec<u16>)> = Vec::new();
    for rule in r.rules.iter().filter(|x| x.link_initiated()) {
        let a = rule.link_address.clone().unwrap_or_else(|| own.to_string());
        match pairs.iter_mut().find(|(pa, pp, _)| *pa == a && *pp == rule.protocol) {
            Some((_, _, ports)) => ports.push(rule.listen_port),
            None => pairs.push((a, rule.protocol.clone(), vec![rule.listen_port])),
        }
    }
    for (a, proto, ports) in &pairs {
        let p: Vec<String> = ports.iter().map(|x| x.to_string()).collect();
        link.push(format!("\t\t{} daddr {a} {proto} dport {{ {} }} accept", fam(a), p.join(", ")));
    }
    link.push("\t\tcounter name \"link_dropped\" drop".into());
    let mut elsewhere = Vec::new();
    for f in ["ip", "ip6"] {
        let held: Vec<String> = addresses(r).into_iter().filter(|a| fam(a) == f).collect();
        if !held.is_empty() {
            elsewhere.push(format!("\t\t{f} daddr {{ {} }} counter name \"elsewhere_dropped\" drop", held.join(", ")));
        }
    }
    format!(
        "table inet {TABLE} {{
\tcounter link_dropped {{
\t}}
\tcounter elsewhere_dropped {{
\t}}
\tchain input {{
\t\ttype filter hook input priority filter - 10; policy accept;
\t\tiifname \"{li}\" jump link
\t\tiifname \"lo\" return
{}
\t}}
\tchain link {{
{}
\t}}
}}
",
        elsewhere.join("\n"),
        link.join("\n")
    )
}

/// The ruleset's own digest: what the declaration asks for.
pub fn declared(r: &Relay) -> String {
    crate::send::sha256_hex(ruleset(r).as_bytes())
}

fn nft_stdin(script: &str) -> Result<(), String> {
    let child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn();
    let mut child = child.map_err(|e| format!("nft: {}", crate::sys::strerror(&e)))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| format!("nft: {}", crate::sys::strerror(&e)))?;
    if !out.status.success() {
        return Err(format!("nft -f: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// The table as the kernel lists it; None when there is none.
fn read() -> Option<Value> {
    let p = su::run(&["nft", "-j", "list", "table", "inet", TABLE]);
    if p.code != 0 {
        return None;
    }
    serde_json::from_str(p.stdout.trim()).ok()
}

/// The rules, chains and counters without handles and packet counts, as one digest.
pub fn signature(v: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    for o in v["nftables"].as_array().into_iter().flatten() {
        if let Some(t) = o.get("table") {
            parts.push(format!("table {}", t["name"]));
        } else if let Some(c) = o.get("counter") {
            parts.push(format!("counter {}", c["name"]));
        } else if let Some(c) = o.get("chain") {
            parts.push(format!("chain {} {} {} {} {}", c["name"], c["type"], c["hook"], c["prio"], c["policy"]));
        } else if let Some(r) = o.get("rule") {
            let mut expr = r["expr"].clone();
            strip_counts(&mut expr);
            parts.push(format!("rule {} {}", r["chain"], expr));
        }
    }
    crate::send::sha256_hex(parts.join("\n").as_bytes())
}

/// Anonymous counters carry packet counts; they are not part of what the rule is.
fn strip_counts(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Object(c)) = m.get_mut("counter") {
                c.remove("packets");
                c.remove("bytes");
            }
            for x in m.values_mut() {
                strip_counts(x);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(strip_counts),
        _ => {}
    }
}

fn counter(v: &Value, name: &str) -> u64 {
    v["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| o.get("counter"))
        .find(|c| c["name"].as_str() == Some(name))
        .and_then(|c| c["packets"].as_u64())
        .unwrap_or(0)
}

/// The two counters: dropped from the link, and dropped from elsewhere.
pub fn drops() -> Option<(u64, u64)> {
    let v = read()?;
    Some((counter(&v, "link_dropped"), counter(&v, "elsewhere_dropped")))
}

fn arp_path(ifname: &str, key: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{ifname}/{key}")
}

/// Every ARP setting on the link interface that is not as required: (key, value now, required).
fn arp_wrong(r: &Relay) -> Vec<(&'static str, String, &'static str)> {
    ARP.iter()
        .filter_map(|(k, want)| {
            let have = crate::sys::read(&arp_path(&r.link_interface, k)).unwrap_or_else(|| "absent".into());
            (have != *want).then_some((*k, have, *want))
        })
        .collect()
}

/// Before the relay starts: nft is there.
pub fn preflight(_r: &Relay) -> Result<(), String> {
    if !su::have("nft") {
        return Err(
            "nft is not installed (sudo apt-get install -y nftables); the relay admits only its rules from the link through it".into()
        );
    }
    Ok(())
}

/// ARP on the link interface as required: set here when it is not and this process may write it
/// (the relay unit may not; install writes the sysctl file), else a refusal.
fn arp(r: &Relay) -> Result<(), String> {
    for (k, _, want) in arp_wrong(r) {
        crate::sys::write(&arp_path(&r.link_interface, k), want);
    }
    let wrong = arp_wrong(r);
    if !wrong.is_empty() {
        let w: Vec<String> =
            wrong.iter().map(|(k, have, want)| format!("net.ipv4.conf.{}.{k} is {have}, not {want}", r.link_interface)).collect();
        return Err(format!(
            "{}: the machine would answer ARP on the link for its other addresses. `goatrope install` writes {SYSCTL}; apply it (sudo sysctl -p {SYSCTL})",
            w.join("; ")
        ));
    }
    Ok(())
}

/// Replace the table with the declared one and remember its signature.
pub fn up(r: &Relay) -> Result<(), String> {
    arp(r)?;
    let script = format!("table inet {TABLE}\ndelete table inet {TABLE}\n{}", ruleset(r));
    nft_stdin(&script)?;
    let sig = read().map(|v| signature(&v)).ok_or_else(|| format!("the table inet {TABLE} is not there after nft -f"))?;
    *BASELINE.lock().unwrap_or_else(|e| e.into_inner()) = Some(sig);
    println!(
        "goatrope relay: from {} it admits only replies and its rules' ports at {}; everything else to this machine is dropped and counted (nft table inet {TABLE})",
        r.link_interface,
        addresses(r).join(", ")
    );
    Ok(())
}

/// The relay's 2 s tick: the table is still the one it installed, and ARP is still as required.
pub fn tick(r: &Relay) -> Result<(), String> {
    let base = BASELINE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let now = read().map(|v| signature(&v));
    if now.is_none() || now != base {
        return Err(format!("the nft table inet {TABLE} was removed or changed"));
    }
    let wrong = arp_wrong(r);
    if !wrong.is_empty() {
        return Err(format!("{}.{} was changed to {}", r.link_interface, wrong[0].0, wrong[0].1));
    }
    Ok(())
}

/// relay.health's "link_filter" object.
pub fn health_json(r: &Relay) -> String {
    let base = BASELINE.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
    let (link, elsewhere) = drops().unwrap_or((0, 0));
    format!(
        "{{\"signature\": \"{base}\", \"declared\": \"{}\", \"link_dropped\": {link}, \"elsewhere_dropped\": {elsewhere}}}",
        declared(r)
    )
}

/// The sysctl file install writes for the relay.
pub fn sysctl_file(r: &Relay, header: &str) -> String {
    let mut s = format!("{header}# the relay's link interface answers ARP only for its own addresses, and asks with one of them\n");
    for (k, v) in ARP {
        s.push_str(&format!("net/ipv4/conf/{}/{k} = {v}\n", r.link_interface));
    }
    s
}

/// For the state file: the ARP settings before install, to restore at uninstall.
pub fn arp_now(r: &Relay) -> Value {
    let mut m = serde_json::Map::new();
    for (k, _) in ARP {
        if let Some(v) = crate::sys::read(&arp_path(&r.link_interface, k)) {
            m.insert(k.to_string(), Value::String(v));
        }
    }
    Value::Object(m)
}

/// Uninstall: remove the table and put the ARP settings back.
pub fn remove(link_interface: Option<&str>, prior: &Value) {
    su::run(&["nft", "delete", "table", "inet", TABLE]);
    if let (Some(li), Some(m)) = (link_interface, prior.as_object()) {
        for (k, v) in m {
            if let Some(v) = v.as_str() {
                crate::sys::write(&arp_path(li, k), v);
            }
        }
    }
}

pub fn check(cfg: &Config, health: Option<&Value>) -> Vec<Item> {
    let mut items = Vec::new();
    let Some(r) = &cfg.relay else { return items };
    let live = read();
    let row = health.map(|h| &h["link_filter"]);
    let (ok, have) = match (&live, row) {
        (None, _) => (false, format!("no nft table inet {TABLE}")),
        (Some(_), None) => (false, "the relay reports no table".to_string()),
        (Some(v), Some(h)) => {
            let sig = signature(v);
            if h["declared"].as_str() != Some(declared(r).as_str()) {
                (false, "the relay runs a table made from another declaration".to_string())
            } else if h["signature"].as_str() != Some(sig.as_str()) {
                (false, "changed since the relay installed it".to_string())
            } else {
                (
                    true,
                    format!(
                        "as declared; {} dropped from the link, {} from elsewhere",
                        counter(v, "link_dropped"),
                        counter(v, "elsewhere_dropped")
                    ),
                )
            }
        }
    };
    item(
        &mut items,
        "relay-link-filter",
        Some(ok),
        format!("nft table inet {TABLE}: from {} only replies and the rules' ports", r.link_interface),
        have,
    );
    for (k, want) in ARP {
        let have = crate::sys::read(&arp_path(&r.link_interface, k)).unwrap_or_else(|| "absent".into());
        item(&mut items, format!("relay-arp:{}:{k}", r.link_interface), Some(have == want), want, have);
    }
    items
}

pub fn status(r: &Relay) {
    match drops() {
        Some((l, e)) => println!(
            "  filter from {}: only replies and the rules' ports reach this machine; {l} dropped from the link, {e} addressed to its link addresses from elsewhere",
            r.link_interface
        ),
        None => println!("  filter nft table inet {TABLE} absent: the link reaches this machine's services"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_admits_only_link_initiated_ports() {
        let text = r#"schema = 1
[relay]
remote_interface = "wg0"
link_interface = "r0"
link_address = "192.0.2.50/24"
allow = [
  { direction = "both", protocol = "udp", remote = "198.51.100.5", listen_port = 7000, target = "192.0.2.2", target_port = 7000 },
  { direction = "link-to-remote", protocol = "udp", remote = "198.51.100.5", listen_port = 7100, remote_port = 7100, sources = ["192.0.2.2"] },
  { direction = "link-to-remote", protocol = "tcp", remote = "198.51.100.5", listen_port = 7300, remote_port = 7300, sources = ["192.0.2.2"] },
  { direction = "link-to-remote", protocol = "udp", remote = "198.51.100.5", listen_port = 7101, remote_port = 7101, sources = ["192.0.2.2"] },
]
"#;
        let c = crate::config::parse(text, "x.toml").unwrap();
        let s = ruleset(c.relay.as_ref().unwrap());
        assert!(s.contains("ip daddr 192.0.2.50 udp dport { 7100, 7101 } accept"));
        assert!(s.contains("ip daddr 192.0.2.50 tcp dport { 7300 } accept"));
        assert!(!s.contains("7000"));
        assert!(s.contains("iifname \"r0\" jump link"));
        assert!(s.contains("ip daddr { 192.0.2.50 } counter name \"elsewhere_dropped\" drop"));
        assert!(s.trim_end().ends_with('}'));
    }

    #[test]
    fn signature_ignores_counts_and_handles() {
        let a: Value = serde_json::from_str(r#"{"nftables":[{"metainfo":{}},{"table":{"name":"t","handle":1}},{"rule":{"chain":"link","handle":5,"expr":[{"counter":{"packets":3,"bytes":9}},{"drop":null}]}}]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"nftables":[{"table":{"name":"t","handle":7}},{"rule":{"chain":"link","handle":9,"expr":[{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}]}"#).unwrap();
        assert_eq!(signature(&a), signature(&b));
        let c: Value =
            serde_json::from_str(r#"{"nftables":[{"table":{"name":"t"}},{"rule":{"chain":"link","expr":[{"accept":null}]}}]}"#).unwrap();
        assert_ne!(signature(&a), signature(&c));
    }
}
