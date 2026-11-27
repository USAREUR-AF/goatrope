// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The remote mirror (ADR 0004 §5): frames arriving on tap ports go, through a tc `mirred`
//! action, to an ERSPAN type II interface goatrope makes, and from there to a collector.
//!
//! systemd-networkd makes the interface at every boot from a .netdev, as it makes the bridge and
//! the erspan listen source; goatrope-ports turns IPv6 off on it, raises it, and puts the tc
//! filters on the tap ports, at boot and at install. Nothing is sent onto the tapped link: the
//! interface's packets leave by the declared underlay, and the mirrored copy is the only thing
//! the action makes.

use serde_json::{json, Value};

use crate::config::{pystr, Mirror, Tap};
use crate::sysutil as su;
use crate::tap::{item, Item};

const NET: &str = "/etc/systemd/network";
/// The tc filter priority of session n is PREF_BASE + n, on each hook of each mirrored port.
pub const PREF_BASE: i64 = 1000;
/// The interface's MTU: a received frame up to this size plus its Ethernet header is sent whole
/// (the kernel truncates longer frames); the outer packet is fragmented on a smaller underlay.
pub const MTU: u32 = 9000;

pub fn dev(m: &Mirror) -> String {
    format!("goatrope-m{}", m.gre_key)
}

pub fn devs(tap: &Tap) -> Vec<String> {
    tap.mirrors.iter().map(dev).collect()
}

fn pref(m: &Mirror) -> String {
    (PREF_BASE + m.gre_key).to_string()
}

/// The tc hooks a mirror uses on its port. An inline bridge port: ingress (frames from its own
/// side) and egress (frames from the other side), so one port mirrors both directions, as the
/// recording of that port does. A listen port only receives.
pub fn hooks(tap: &Tap) -> &'static [&'static str] {
    if tap.mode == "inline" {
        &["ingress", "egress"]
    } else {
        &["ingress"]
    }
}

pub fn render(tap: &Tap, header: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for m in &tap.mirrors {
        let d = dev(m);
        let filter = if m.filter.is_empty() { "every frame".to_string() } else { format!("filter {}", pystr(&m.filter)) };
        out.push((
            format!("{NET}/03-goatrope-{d}.netdev"),
            format!(
                "{header}# mirror: {} ({filter}) to {} as ERSPAN type II session {}; outer packets may be fragmented
[NetDev]
Name={d}
Kind=erspan
MTUBytes={MTU}

[Tunnel]
Local={}
Remote={}
Key={}
SerializeTunneledPackets=yes
ERSPANVersion=1
ERSPANIndex=1
DiscoverPathMTU=no
IgnoreDontFragment=yes
Independent=yes
",
                m.ports.join(", "),
                m.remote,
                m.gre_key,
                m.local,
                m.remote,
                m.gre_key
            ),
        ));
        out.push((
            format!("{NET}/05-goatrope-{d}.network"),
            format!(
                "{header}# mirror interface: no address; goatrope-ports raises it once IPv6 is off, so it sends only the copies
[Match]
Name={d}

[Link]
RequiredForOnline=no
ActivationPolicy=manual
ARP=no

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
IPv6SendRA=no
LLDP=no
EmitLLDP=no
DHCP=no
ConfigureWithoutCarrier=yes
"
            ),
        ));
    }
    out
}

/// The classic BPF program tcpdump compiles from the filter, as tc's `bytecode` takes it; None for
/// every frame (a matchall filter).
pub fn bytecode(filter: &str) -> Result<Option<String>, String> {
    if filter.is_empty() {
        return Ok(None);
    }
    let p = su::run(&["tcpdump", "-y", "EN10MB", "-ddd", "--", filter]);
    let lines: Vec<&str> = p.stdout.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if p.code != 0 || lines.len() < 2 {
        return Err(format!("tcpdump cannot compile the filter {}: {}", pystr(filter), p.stderr.trim()));
    }
    Ok(Some(lines.join(",")))
}

/// The refusals install makes for the mirrors. Nothing has been changed when one is returned.
pub fn preflight(tap: &Tap) -> Result<(), String> {
    for m in &tap.mirrors {
        let d = dev(m);
        if tap.ports.contains(&d) {
            return Err(format!("{d} is a tap port; goatrope makes an interface of that name for mirror session {}", m.gre_key));
        }
        if su::exists(&d) && su::kind(&d).as_deref() != Some("erspan") {
            return Err(format!("{d} exists and is not an erspan interface; goatrope makes it for mirror session {}", m.gre_key));
        }
        if !su::exists(&m.underlay) {
            return Err(format!("the mirror underlay {} does not exist (see: ip -br link)", m.underlay));
        }
        if !su::addresses(&m.underlay).iter().any(|a| a.split('/').next() == Some(m.local.as_str())) {
            return Err(format!("{} does not hold {}, the mirror's source address; configure the address first", m.underlay, m.local));
        }
        let via = m.remote.parse().ok().and_then(crate::link::route_dev);
        if via.as_deref() != Some(m.underlay.as_str()) {
            return Err(format!(
                "the route to the collector {} leaves by {}, not the underlay {}; the mirror is sent only by its underlay",
                m.remote,
                via.unwrap_or_else(|| "no interface".into()),
                m.underlay
            ));
        }
        bytecode(&m.filter)?;
    }
    Ok(())
}

fn tc_filter_args(m: &Mirror, port: &str, hook: &str, bc: &Option<String>) -> Vec<String> {
    let mut a: Vec<String> =
        ["tc", "filter", "add", "dev", port, hook, "pref", &pref(m), "handle", "1"].iter().map(|s| s.to_string()).collect();
    match bc {
        Some(b) => a.extend(["bpf".into(), "bytecode".into(), b.clone()]),
        None => a.push("matchall".into()),
    }
    a.extend(["action", "mirred", "egress", "mirror", "dev"].iter().map(|s| s.to_string()));
    a.push(dev(m));
    a
}

/// The mirror's tc filter on one hook of a port, as `tc filter show` prints it, or None.
fn shown(m: &Mirror, port: &str, hook: &str) -> Option<String> {
    let p = su::run(&["tc", "filter", "show", "dev", port, hook, "pref", &pref(m)]);
    let t = p.stdout.trim();
    if p.code != 0 || t.is_empty() {
        None
    } else {
        Some(t.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

fn filter_matches(m: &Mirror, port: &str, hook: &str, bc: &Option<String>) -> bool {
    let Some(s) = shown(m, port, hook) else { return false };
    let kind_ok = match bc {
        Some(b) => s.contains(" bpf ") && s.contains(&format!("bytecode '{b}'")),
        None => s.contains(" matchall "),
    };
    kind_ok && s.contains(&format!("mirred (Egress Mirror to device {})", dev(m))) && s.matches("action order").count() == 1
}

/// Idempotent, at boot and at install: IPv6 off and the interface up, then the tc filters.
pub fn apply(tap: &Tap, wait_for: impl Fn(&str, f64) -> bool) -> Vec<String> {
    let mut problems = Vec::new();
    for m in &tap.mirrors {
        let d = dev(m);
        if !wait_for(&d, 10.0) {
            problems.push(format!("the mirror interface {d} did not appear (systemd-networkd makes it)"));
            continue;
        }
        su::write(&format!("/proc/sys/net/ipv6/conf/{d}/disable_ipv6"), "1");
        su::run(&["ip", "link", "set", &d, "arp", "off"]);
        su::run(&["ip", "link", "set", &d, "up"]);
        let bc = match bytecode(&m.filter) {
            Ok(b) => b,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        for p in &m.ports {
            if !su::exists(p) {
                continue; // apply_ports reports the missing port
            }
            if !su::run(&["tc", "qdisc", "show", "dev", p]).stdout.contains("clsact") {
                su::run(&["tc", "qdisc", "add", "dev", p, "clsact"]);
            }
            for hook in hooks(tap) {
                if filter_matches(m, p, hook, &bc) {
                    continue;
                }
                su::run(&["tc", "filter", "del", "dev", p, hook, "pref", &pref(m)]);
                let args = tc_filter_args(m, p, hook, &bc);
                let r = su::run(&args.iter().map(String::as_str).collect::<Vec<_>>());
                if r.code != 0 {
                    problems.push(format!("{p}: the mirror filter for session {} could not be added: {}", m.gre_key, r.stderr.trim()));
                }
            }
        }
    }
    problems
}

/// What uninstall, or an install that drops a mirror, has to undo.
pub fn state(tap: &Tap) -> Value {
    json!(tap
        .mirrors
        .iter()
        .map(|m| json!({"dev": dev(m), "pref": pref(m), "ports": m.ports, "hooks": hooks(tap),
                        "underlay": m.underlay, "local": m.local, "remote": m.remote, "filter": m.filter}))
        .collect::<Vec<_>>())
}

/// Remove the filters and interfaces of the mirrors in `recorded` (a state's "mirrors") that are not
/// in `keep` exactly as they are; a changed mirror is removed whole, and made again from its new
/// files. Only goatrope's own filters go (by priority); other tc filters on the port stay.
pub fn undo(recorded: &Value, keep: &Value) {
    let Some(list) = recorded.as_array() else { return };
    let keep = keep.as_array().cloned().unwrap_or_default();
    for r in list {
        let (Some(d), Some(pref)) = (r["dev"].as_str(), r["pref"].as_str()) else { continue };
        if keep.contains(r) {
            continue;
        }
        for p in r["ports"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
            for hook in r["hooks"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                if su::exists(p) {
                    su::run(&["tc", "filter", "del", "dev", p, hook, "pref", pref]);
                }
            }
        }
        if su::exists(d) && su::kind(d).as_deref() == Some("erspan") {
            let _ = crate::nl::delete_link(d);
        }
    }
}

fn link_json(d: &str) -> Value {
    let p = su::run(&["ip", "-d", "-j", "link", "show", "dev", d]);
    serde_json::from_str::<Value>(&p.stdout).ok().and_then(|v| v.get(0).cloned()).unwrap_or(Value::Null)
}

fn describe(l: &Value) -> String {
    let i = &l["linkinfo"]["info_data"];
    format!(
        "{} session {} from {} to {}, {}{}, {}, mtu {}",
        l["linkinfo"]["info_kind"].as_str().unwrap_or("?"),
        // ip shows the key as a dotted quad: 0.0.3.255 is session 1023
        i["okey"]
            .as_str()
            .and_then(|k| k.parse::<std::net::Ipv4Addr>().ok())
            .map(|k| u32::from(k).to_string())
            .unwrap_or_else(|| "none".into()),
        i["local"].as_str().unwrap_or("?"),
        i["remote"].as_str().unwrap_or("?"),
        if i["pmtudisc"].as_bool() == Some(false) { "nopmtudisc" } else { "pmtudisc" },
        if i["ignore_df"].as_bool() == Some(true) { ", ignore-df" } else { "" },
        if i["erspan_ver"].as_i64() == Some(1) { "type II" } else { "not type II" },
        l["mtu"]
    )
}

fn want_link(m: &Mirror) -> String {
    format!("erspan session {} from {} to {}, nopmtudisc, ignore-df, type II, mtu {MTU}", m.gre_key, m.local, m.remote)
}

pub fn check(tap: &Tap, items: &mut Vec<Item>) {
    for m in &tap.mirrors {
        let d = dev(m);
        if !su::exists(&d) {
            item(items, format!("mirror:{d}"), Some(false), want_link(m), "absent");
        } else {
            let l = link_json(&d);
            let have = describe(&l);
            let ok = have == want_link(m) && l["linkinfo"]["info_data"]["ikey"] == l["linkinfo"]["info_data"]["okey"];
            item(items, format!("mirror:{d}"), Some(ok), want_link(m), have);
            let up = su::is_up(&d);
            item(items, format!("mirror-up:{d}"), Some(up), "up", if up { "up" } else { "down" });
            let v6 = su::read(&format!("/proc/sys/net/ipv6/conf/{d}/disable_ipv6"));
            item(
                items,
                format!("mirror-ipv6-disabled:{d}"),
                Some(v6.as_deref() == Some("1")),
                "1",
                v6.map(Value::String).unwrap_or(Value::Null),
            );
            let addrs = su::addresses(&d);
            item(
                items,
                format!("mirror-address:{d}"),
                Some(addrs.is_empty()),
                "none",
                if addrs.is_empty() { "none".into() } else { addrs.join(", ") },
            );
        }
        let held = su::addresses(&m.underlay).iter().any(|a| a.split('/').next() == Some(m.local.as_str()));
        item(
            items,
            format!("mirror-underlay:{d}:{}", m.underlay),
            Some(held),
            format!("holds {}", m.local),
            if held { format!("holds {}", m.local) } else { format!("does not hold {}", m.local) },
        );
        let via = m.remote.parse().ok().and_then(crate::link::route_dev).unwrap_or_else(|| "no route".into());
        item(
            items,
            format!("mirror-route:{d}"),
            Some(via == m.underlay),
            format!("{} by {}", m.remote, m.underlay),
            format!("{} by {via}", m.remote),
        );
        let bc = bytecode(&m.filter);
        let what = match &bc {
            Ok(None) => "matchall".to_string(),
            Ok(Some(_)) => format!("bpf {}", pystr(&m.filter)),
            Err(e) => e.clone(),
        };
        for p in &m.ports {
            for hook in hooks(tap) {
                let ok = bc.as_ref().map(|b| filter_matches(m, p, hook, b)).unwrap_or(false);
                let have = match shown(m, p, hook) {
                    None => "absent".to_string(),
                    Some(_) if ok => format!("{what}, mirred to {d}"),
                    Some(_) => "differs".to_string(),
                };
                item(items, format!("mirror-filter:{p}:{hook}:{d}"), Some(ok), format!("{what}, mirred to {d}"), have);
            }
        }
    }
}

pub fn status(tap: &Tap) {
    for m in &tap.mirrors {
        let d = dev(m);
        let sent = su::read(&format!("/sys/class/net/{d}/statistics/tx_packets")).unwrap_or_else(|| "absent".into());
        let filter = if m.filter.is_empty() { "(every frame)".to_string() } else { m.filter.clone() };
        println!(
            "  mirror {d:<14} session {} {} -> {} on {}, filter {}, sent {sent}",
            m.gre_key,
            m.ports.join(","),
            m.remote,
            m.underlay,
            pystr(&filter)
        );
    }
}
