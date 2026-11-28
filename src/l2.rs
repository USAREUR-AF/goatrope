// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Layer-2 lane (docs/adr/0004 §6): an opt-in bridge of one dedicated port and one GRETAP
//! interface to one peer over WireGuard, filtered by declared EtherTypes and source MACs.
//!
//! The relay makes the lane when it starts and owns it while it runs:
//!
//! - `l2b-<name>`, a bridge: STP off, no address, no IPv6 address (addrgenmode none), no
//!   multicast snooping or querier (it floods multicast to its one other member), no VLAN
//!   filtering, link-local group frames (01:80:C2:00:00:0X) not forwarded. tc drops every frame
//!   on its own ingress and egress, so this machine neither receives from the lane nor sends into it.
//! - `l2g-<name>`, a GRETAP interface from `local` to `peer`, keyed, bound to the remote
//!   interface, MTU 1500, with outer fragmentation allowed (nopmtudisc, ignore-df), so full
//!   frames cross a WireGuard MTU below 1,500.
//! - tc flower on the ingress of both members: from the port only the declared EtherTypes,
//!   from the tunnel only the declared EtherTypes from the declared source MACs (and an ARP
//!   frame only when its sender hardware address is that MAC too); then a matchall drop.
//!   Every filter carries a cookie naming what it passes, so check and the relay can tell it
//!   was not replaced; `tc -s filter show` counts each.
//!
//! The GRETAP interface is up only while the WireGuard peer that owns `peer` has a handshake
//! younger than 180 s (read every 2 s, with the address proxy's `proxy::handshake_age`); it is
//! taken down when the relay stops (on SIGTERM through `proxy::stop_requested`, and ExecStopPost
//! runs `goatrope l2 down`), and when anything about the lane differs from the declaration, after
//! which the relay exits and the unit's restart builds it again.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::config::{Config, Relay, L2};
use crate::nl;
use crate::sysutil as su;
use crate::tap::{item, Item};

pub const BRIDGE_PREFIX: &str = "l2b-";
pub const GRETAP_PREFIX: &str = "l2g-";
const ARP: u16 = 0x0806;
const DROP_PREF: u32 = 60000;

pub fn bridge(l: &L2) -> String {
    format!("{BRIDGE_PREFIX}{}", l.name)
}

pub fn gretap(l: &L2) -> String {
    format!("{GRETAP_PREFIX}{}", l.name)
}

fn lanes(cfg: &Config) -> &[L2] {
    cfg.relay.as_ref().map(|r| r.l2.as_slice()).unwrap_or_default()
}

// ---------------------------------------------------------------- the filters

/// One tc filter goatrope puts on a lane interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Filter {
    dir: &'static str,
    pref: u32,
    /// None: matchall drop of every frame; Some: flower, passing this EtherType
    ethertype: Option<u16>,
    /// flower: the source MAC (and, for ARP, the sender hardware address) it requires
    mac: Option<String>,
    cookie: String,
}

fn cookie(et: u16, mac: Option<&str>) -> String {
    format!("{et:04x}{}", mac.map(|m| m.replace(':', "")).unwrap_or_else(|| "000000000000".into()))
}

fn drop_all(dir: &'static str, pref: u32) -> Filter {
    Filter { dir, pref, ethertype: None, mac: None, cookie: cookie(0, None) }
}

/// The filters for each lane interface: (interface, filters).
fn filters(l: &L2) -> Vec<(String, Vec<Filter>)> {
    let mut port: Vec<Filter> = l
        .ethertypes
        .iter()
        .enumerate()
        .map(|(i, et)| Filter { dir: "ingress", pref: 10 + i as u32, ethertype: Some(*et), mac: None, cookie: cookie(*et, None) })
        .collect();
    port.push(drop_all("ingress", DROP_PREF));
    let mut tunnel = Vec::new();
    for (i, et) in l.ethertypes.iter().enumerate() {
        for (j, mac) in l.macs.iter().enumerate() {
            tunnel.push(Filter {
                dir: "ingress",
                pref: 10 + (i * l.macs.len() + j) as u32,
                ethertype: Some(*et),
                mac: Some(mac.clone()),
                cookie: cookie(*et, Some(mac)),
            });
        }
    }
    tunnel.push(drop_all("ingress", DROP_PREF));
    vec![(l.port.clone(), port), (gretap(l), tunnel), (bridge(l), vec![drop_all("ingress", 1), drop_all("egress", 1)])]
}

/// The `tc -batch` line that adds f to dev.
fn tc_line(dev: &str, f: &Filter) -> String {
    let head = format!("filter add dev {dev} {} pref {} handle {}", f.dir, f.pref, f.pref);
    match (f.ethertype, &f.mac) {
        (None, _) => format!("{head} protocol all matchall action drop cookie {}", f.cookie),
        (Some(et), mac) => {
            let mut keys = String::new();
            if let Some(m) = mac {
                keys.push_str(&format!(" src_mac {m}"));
                if et == ARP {
                    keys.push_str(&format!(" arp_sha {m}"));
                }
            }
            format!("{head} protocol 0x{et:04x} flower{keys} action pass cookie {}", f.cookie)
        }
    }
}

/// The filters on dev as tc shows them, in the same form, with each one's packet count.
fn read_filters(dev: &str) -> Option<Vec<(Filter, u64)>> {
    let mut out = Vec::new();
    for dir in ["ingress", "egress"] {
        let p = su::run(&["tc", "-s", "-j", "filter", "show", "dev", dev, dir]);
        if p.code != 0 {
            return None;
        }
        let v: Value = serde_json::from_str(p.stdout.trim()).unwrap_or(Value::Array(vec![]));
        for f in v.as_array().into_iter().flatten().filter(|f| f.get("options").is_some()) {
            let o = &f["options"];
            let act = &o["actions"][0];
            let pass = act["control_action"]["type"].as_str() == Some("pass");
            let kind = f["kind"].as_str().unwrap_or_default();
            let ck = act["cookie"].as_str().unwrap_or_default().to_string();
            let et = u16::from_str_radix(ck.get(..4).unwrap_or("0000"), 16).unwrap_or(0);
            let mac = o["keys"]["src_mac"].as_str().map(|s| s.to_lowercase());
            let arp_ok = et != ARP || mac.is_none() || o["keys"]["arp_sha"].as_str().map(|s| s.to_lowercase()) == mac;
            let shape_ok = match kind {
                "matchall" => !pass && f["protocol"].as_str() == Some("all"),
                "flower" => pass && arp_ok && o["actions"].as_array().map(|a| a.len()) == Some(1),
                _ => false,
            };
            let pref = f["pref"].as_u64().unwrap_or(0) as u32;
            let filter = Filter {
                dir: if dir == "ingress" { "ingress" } else { "egress" },
                pref: if shape_ok && o["handle"].as_u64() == Some(pref as u64) { pref } else { 0 },
                ethertype: if kind == "flower" { Some(et) } else { None },
                mac,
                cookie: if shape_ok { ck } else { format!("{kind}?") },
            };
            out.push((filter, act["stats"]["packets"].as_u64().unwrap_or(0)));
        }
    }
    Some(out)
}

/// Replace every filter on dev with `want`, in one tc batch.
fn put_filters(dev: &str, want: &[Filter]) -> Result<(), String> {
    let q = su::run(&["tc", "qdisc", "replace", "dev", dev, "clsact"]);
    if q.code != 0 {
        return Err(format!("{dev}: tc qdisc replace clsact: {}", q.stderr.trim()));
    }
    for dir in ["ingress", "egress"] {
        su::run(&["tc", "filter", "del", "dev", dev, dir]);
    }
    let batch: String = want.iter().map(|f| tc_line(dev, f) + "\n").collect();
    let child = Command::new("tc").args(["-batch", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn();
    let mut child = child.map_err(|e| format!("tc: {}", crate::sys::strerror(&e)))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(batch.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| format!("tc: {}", crate::sys::strerror(&e)))?;
    if !out.status.success() {
        return Err(format!("{dev}: tc filter: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn filters_match(dev: &str, want: &[Filter]) -> bool {
    let Some(have) = read_filters(dev) else { return false };
    let mut have: Vec<Filter> = have.into_iter().map(|(f, _)| f).collect();
    let mut want = want.to_vec();
    have.sort();
    want.sort();
    have == want
}

// ---------------------------------------------------------------- reading the lane

fn link_json(ifname: &str) -> Option<Value> {
    let p = su::run(&["ip", "-d", "-j", "link", "show", "dev", ifname]);
    if p.code != 0 {
        return None;
    }
    serde_json::from_str::<Value>(p.stdout.trim()).ok()?.as_array()?.first().cloned()
}

fn info<'a>(l: &'a Value, k: &str) -> &'a Value {
    &l["linkinfo"]["info_data"][k]
}

fn bridge_nf_on() -> Vec<String> {
    ["iptables", "ip6tables", "arptables"]
        .iter()
        .filter(|k| crate::sys::read(&format!("/proc/sys/net/bridge/bridge-nf-call-{k}")).as_deref() == Some("1"))
        .map(|k| format!("net.bridge.bridge-nf-call-{k}"))
        .collect()
}

/// Every property of one lane that the declaration fixes, as check items.
fn inspect(l: &L2, r: &Relay) -> Vec<Item> {
    let mut items = Vec::new();
    let (br, gt) = (bridge(l), gretap(l));
    let id = |what: &str| format!("l2:{}:{what}", l.name);
    let b = link_json(&br);
    let have = match &b {
        None => "absent".to_string(),
        Some(b) => {
            let mut bad = Vec::new();
            if b["linkinfo"]["info_kind"].as_str() != Some("bridge") {
                bad.push("not a bridge".to_string());
            }
            for (k, want) in [("stp_state", 0), ("mcast_snooping", 0), ("mcast_querier", 0), ("vlan_filtering", 0)] {
                if info(b, k).as_u64() != Some(want) {
                    bad.push(format!("{k} {}", info(b, k)));
                }
            }
            if info(b, "group_fwd_mask").as_str().is_some_and(|m| m != "0" && m != "0x0") {
                bad.push(format!("group_fwd_mask {}", info(b, "group_fwd_mask")));
            }
            if b["inet6_addr_gen_mode"].as_str() != Some("none") {
                bad.push(format!("addrgenmode {}", b["inet6_addr_gen_mode"]));
            }
            if !b["flags"].as_array().is_some_and(|f| f.iter().any(|x| x == "UP")) {
                bad.push("down".into());
            }
            let a = nl::addresses(&br);
            if !a.is_empty() {
                bad.push(format!("addresses {}", a.join(", ")));
            }
            if bad.is_empty() {
                "as declared".into()
            } else {
                bad.join("; ")
            }
        }
    };
    let want_b = "a bridge, up, STP off, no address, addrgenmode none, no snooping, querier or VLAN filtering";
    item(&mut items, id("bridge"), Some(have == "as declared"), want_b, have);

    let g = link_json(&gt);
    let have = match &g {
        None => "absent".to_string(),
        Some(g) => {
            let mut bad = Vec::new();
            let key = Ipv4Addr::from(l.key).to_string();
            let s = |k: &str| info(g, k).as_str().unwrap_or_default().to_string();
            if g["linkinfo"]["info_kind"].as_str() != Some("gretap") {
                bad.push("not a gretap interface".to_string());
            }
            for (k, want) in [("local", l.local.as_str()), ("remote", l.peer.as_str()), ("ikey", &key), ("okey", &key)] {
                if s(k) != want {
                    bad.push(format!("{k} {}", s(k)));
                }
            }
            if g["link"].as_str() != Some(r.remote_interface.as_str()) {
                bad.push(format!("bound to {}", g["link"]));
            }
            if info(g, "pmtudisc").as_bool() != Some(false) || info(g, "ignore_df").as_bool() != Some(true) {
                bad.push("outer fragmentation not allowed (want nopmtudisc, ignore-df)".into());
            }
            if g["mtu"].as_u64() != Some(1500) {
                bad.push(format!("mtu {}", g["mtu"]));
            }
            if g["master"].as_str() != Some(br.as_str()) {
                bad.push(format!("master {}", g["master"]));
            }
            if g["inet6_addr_gen_mode"].as_str() != Some("none") {
                bad.push(format!("addrgenmode {}", g["inet6_addr_gen_mode"]));
            }
            let a = nl::addresses(&gt);
            if !a.is_empty() {
                bad.push(format!("addresses {}", a.join(", ")));
            }
            if bad.is_empty() {
                "as declared".into()
            } else {
                bad.join("; ")
            }
        }
    };
    let want_g =
        format!("gretap {} to {} key {} on {}, mtu 1500, nopmtudisc, ignore-df, in {br}", l.local, l.peer, l.key, r.remote_interface);
    item(&mut items, id("gretap"), Some(have == "as declared"), want_g, have);

    let m = su::master(&l.port);
    item(
        &mut items,
        id("port"),
        Some(m.as_deref() == Some(br.as_str())),
        format!("{} in {br}", l.port),
        match m {
            Some(m) => format!("{} in {m}", l.port),
            None if su::exists(&l.port) => format!("{} in no bridge", l.port),
            None => format!("{} absent", l.port),
        },
    );
    for (dev, want) in filters(l) {
        let ok = filters_match(&dev, &want);
        item(
            &mut items,
            id(&format!("filters:{dev}")),
            Some(ok),
            format!("{} goatrope filters", want.len()),
            if ok { format!("{} goatrope filters", want.len()) } else { "missing or changed".into() },
        );
    }
    let nf = bridge_nf_on();
    item(
        &mut items,
        id("bridge-nf-call"),
        Some(nf.is_empty()),
        "0 (bridged frames bypass iptables)",
        if nf.is_empty() { "0".to_string() } else { format!("{} = 1", nf.join(", ")) },
    );
    items
}

/// What a declaration's lanes imply, for `goatrope check`.
pub fn check(cfg: &Config) -> Vec<Item> {
    let Some(r) = &cfg.relay else { return vec![] };
    r.l2.iter().flat_map(|l| inspect(l, r)).collect()
}

// ---------------------------------------------------------------- refusals and building

fn ip(args: &[&str]) -> Result<(), String> {
    let mut cmd = vec!["ip"];
    cmd.extend_from_slice(args);
    let p = su::run(&cmd);
    if p.code != 0 {
        return Err(format!("{}: {}", cmd.join(" "), p.stderr.trim()));
    }
    Ok(())
}

/// Before the relay starts: every lane's port is free, and (on the mesh) the tunnel ends are there.
pub fn preflight(cfg: &Config) -> Result<(), String> {
    let Some(r) = &cfg.relay else { return Ok(()) };
    if r.l2.is_empty() {
        return Ok(());
    }
    for tool in ["ip", "tc"] {
        if !su::have(tool) {
            return Err(format!("{tool} is not installed (iproute2); a layer-2 lane needs it"));
        }
    }
    let nf = bridge_nf_on();
    if !nf.is_empty() {
        return Err(format!(
            "{} = 1: bridged frames would pass through the firewall and its NAT. Set it to 0 (the tap's sysctl file does), or unload br_netfilter",
            nf.join(", ")
        ));
    }
    let dev = if r.transport == "mesh" {
        Some(nl::wg_get(&r.remote_interface).map_err(|e| format!("{}: {e}", r.remote_interface))?)
    } else {
        None
    };
    for l in &r.l2 {
        let w = format!("lane {}", l.name);
        let (br, gt) = (bridge(l), gretap(l));
        let p = &l.port;
        if !su::exists(p) {
            return Err(format!("{w}: no interface {p}"));
        }
        let k = su::kind(p);
        if p == "lo" || matches!(k.as_deref(), Some("bridge" | "bond" | "wireguard" | "tun" | "vlan" | "gretap" | "erspan")) {
            return Err(format!("{w}: {p} is a {} interface; a lane port is an Ethernet port", k.unwrap_or_else(|| "loopback".into())));
        }
        if let Some(m) = su::master(p).filter(|m| *m != br) {
            return Err(format!("{w}: {p} is a member of {m}; a lane port is in no other bridge"));
        }
        let stacked: Vec<String> = su::uppers(p).into_iter().filter(|u| *u != br).collect();
        if !stacked.is_empty() {
            return Err(format!("{w}: {p} carries {}; a lane port carries nothing else", stacked.join(", ")));
        }
        let addrs: Vec<String> = su::addresses(p).into_iter().filter(|a| !a.to_lowercase().starts_with("fe80:")).collect();
        if !addrs.is_empty() {
            return Err(format!("{w}: {p} has address(es) {}; a lane port has none", addrs.join(", ")));
        }
        if crate::sys::read(&format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6")).as_deref() != Some("1") {
            return Err(format!(
                "{w}: IPv6 is on for {p}: the kernel would send neighbor discovery and MLD frames into the lane. Disable it (net.ipv6.conf.{p}.disable_ipv6 = 1)"
            ));
        }
        if crate::link::default_route_devs().contains(p) {
            return Err(format!("{w}: the default route leaves through {p}"));
        }
        if su::master(p).is_none() {
            let q = su::run(&["tc", "qdisc", "show", "dev", p]).stdout;
            let ours = filters(l).into_iter().find(|(d, _)| d == p).is_some_and(|(d, want)| filters_match(&d, &want));
            if (q.contains("clsact") || q.contains("ingress")) && !ours {
                return Err(format!("{w}: {p} already has a clsact or ingress qdisc; something else filters it"));
            }
        }
        for (name, kind) in [(&br, "bridge"), (&gt, "gretap")] {
            if su::exists(name) && su::kind(name).as_deref() != Some(kind) {
                return Err(format!("{w}: {name} exists and is not a {kind} interface; goatrope names the lane's {kind} so"));
            }
        }
        if let Some(dev) = &dev {
            if !nl::addresses(&r.remote_interface).iter().any(|a| a.split('/').next() == Some(l.local.as_str())) {
                return Err(format!("{w}: {} does not hold {}, this end of the lane", r.remote_interface, l.local));
            }
            let peer: IpAddr = l.peer.parse().map_err(|_| format!("{w}: bad peer {}", l.peer))?;
            let owner = dev
                .peers
                .iter()
                .filter_map(|p| {
                    p.allowed_ips
                        .iter()
                        .filter(|(n, c)| crate::proxy::prefix_holds(*n, *c, peer))
                        .map(|(_, c)| (*c, p))
                        .max_by_key(|(c, _)| *c)
                })
                .max_by_key(|(c, _)| *c)
                .map(|(_, p)| p);
            let Some(owner) = owner else {
                return Err(format!(
                    "{w}: no WireGuard peer on {} is allowed {}; the lane's far end must be a peer of the mesh",
                    r.remote_interface, l.peer
                ));
            };
            if owner.keepalive == 0 {
                println!(
                    "goatrope relay: lane {}: the peer for {} has no persistent keepalive here; if neither end sends one, an idle tunnel stops handshaking and the lane stays down",
                    l.name, l.peer
                );
            }
        }
    }
    Ok(())
}

/// Build every lane that is not as declared, the GRETAP interface down. Idempotent: what already
/// matches is left alone. Filters go on before any member joins the bridge, and the bridge comes
/// up last, so no frame crosses unfiltered.
pub fn up(cfg: &Config) -> Result<(), String> {
    let Some(r) = &cfg.relay else { return Ok(()) };
    for l in &r.l2 {
        if let Err(e) = build(l, r) {
            // a refusal leaves no half-made lane: every lane of this declaration goes
            for l in &r.l2 {
                teardown(l);
            }
            return Err(format!("lane {}: {e}", l.name));
        }
    }
    Ok(())
}

/// Remove one lane's interfaces and the port's filters (ours by name, and by cookie on the port).
fn teardown(l: &L2) {
    let (br, gt) = (bridge(l), gretap(l));
    if su::exists(&gt) && su::kind(&gt).as_deref() == Some("gretap") {
        let _ = nl::delete_link(&gt);
    }
    if su::exists(&br) && su::kind(&br).as_deref() == Some("bridge") {
        let _ = nl::delete_link(&br);
    }
    let port = filters(l).into_iter().find(|(d, _)| *d == l.port);
    if let Some((dev, want)) = port {
        if su::exists(&dev) && filters_match(&dev, &want) {
            su::run(&["tc", "qdisc", "del", "dev", &dev, "clsact"]);
        }
    }
}

fn build(l: &L2, r: &Relay) -> Result<(), String> {
    let (br, gt) = (bridge(l), gretap(l));
    if !su::exists(&br) {
        ip(&["link", "add", &br, "type", "bridge", "stp_state", "0", "forward_delay", "0", "mcast_snooping", "0", "mcast_querier", "0"])?;
    }
    // STP off first: the kernel refuses a forward delay under 2 s while STP is on.
    ip(&["link", "set", &br, "type", "bridge", "stp_state", "0"])?;
    ip(&[
        "link",
        "set",
        &br,
        "type",
        "bridge",
        "forward_delay",
        "0",
        "mcast_snooping",
        "0",
        "mcast_querier",
        "0",
        "vlan_filtering",
        "0",
        "group_fwd_mask",
        "0",
    ])?;
    ip(&["link", "set", &br, "addrgenmode", "none"])?;
    let key = l.key.to_string();
    let built = link_json(&gt).is_some_and(|g| {
        info(&g, "local").as_str() == Some(l.local.as_str())
            && info(&g, "remote").as_str() == Some(l.peer.as_str())
            && info(&g, "ikey").as_str() == Some(Ipv4Addr::from(l.key).to_string().as_str())
            && g["link"].as_str() == Some(r.remote_interface.as_str())
            && info(&g, "pmtudisc").as_bool() == Some(false)
            && info(&g, "ignore_df").as_bool() == Some(true)
    });
    if !built {
        if su::exists(&gt) {
            nl::delete_link(&gt).map_err(|e| format!("{gt}: {e}"))?;
        }
        ip(&[
            "link",
            "add",
            &gt,
            "type",
            "gretap",
            "local",
            &l.local,
            "remote",
            &l.peer,
            "key",
            &key,
            "nopmtudisc",
            "ignore-df",
            "dev",
            &r.remote_interface,
        ])?;
    }
    // Two requests: made on a WireGuard MTU of 1280 (NetBird's), the GRETAP starts below IPv6's
    // minimum MTU and has no IPv6 state, so addrgenmode is refused until the MTU is 1500.
    ip(&["link", "set", &gt, "mtu", "1500"])?;
    ip(&["link", "set", &gt, "addrgenmode", "none"])?;
    for (dev, want) in filters(l) {
        if !filters_match(&dev, &want) {
            put_filters(&dev, &want)?;
        }
    }
    ip(&["link", "set", &gt, "master", &br])?;
    ip(&["link", "set", &l.port, "master", &br])?;
    ip(&["link", "set", &br, "up"])?;
    ip(&["link", "set", &l.port, "up"])?;
    println!(
        "goatrope relay: lane {}: {} and {gt} ({} to {} key {}) in {br}; {} EtherType(s), {} source MAC(s) from the tunnel; the rest dropped",
        l.name,
        l.port,
        l.local,
        l.peer,
        l.key,
        l.ethertypes.len(),
        l.macs.len()
    );
    Ok(())
}

/// Take every lane down: each GRETAP interface goatrope made (`l2g-*`). The bridge and port stay;
/// with the tunnel side down, nothing crosses.
pub fn close_all() -> usize {
    let mut n = 0;
    let Ok(rd) = std::fs::read_dir(crate::link::SYS_NET) else { return 0 };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with(GRETAP_PREFIX) && su::kind(&name).as_deref() == Some("gretap") && nl::set_down(&name).is_ok() {
            n += 1;
        }
    }
    n
}

/// The relay's 2 s tick: the lane still matches the declaration (else every lane is closed and the
/// relay stops), and each GRETAP interface follows its peer's handshake.
pub fn tick(r: &Relay) -> Result<(), String> {
    for l in &r.l2 {
        let bad: Vec<String> =
            inspect(l, r).into_iter().filter(|i| i.ok == Some(false)).map(|i| format!("{}: {}", i.id, crate::tap::show(&i.have))).collect();
        if !bad.is_empty() {
            close_all();
            return Err(format!("lane {} no longer matches the declaration: {}", l.name, bad.join("; ")));
        }
    }
    for l in &r.l2 {
        let gt = gretap(l);
        let age = handshake_age(r, l).ok();
        let fresh = age.is_some_and(|a| a < crate::proxy::HANDSHAKE_FRESH_S);
        let is_up = nl::is_up(&gt).unwrap_or(false);
        if fresh && !is_up {
            nl::set_up(&gt).map_err(|e| format!("{gt}: {e}"))?;
            println!("goatrope relay: lane {} up: the peer for {} handshook {} s ago", l.name, l.peer, age.unwrap_or_default());
        } else if !fresh && is_up {
            nl::set_down(&gt).map_err(|e| format!("{gt}: {e}"))?;
            println!(
                "goatrope relay: lane {} down: the peer for {} has no handshake in the last {} s",
                l.name,
                l.peer,
                crate::proxy::HANDSHAKE_FRESH_S
            );
        }
    }
    Ok(())
}

/// The handshake age, in seconds, of the WireGuard peer that owns the lane's `peer` (the address
/// proxy's reading, ADR 0004 §4); Err says why there is none.
fn handshake_age(r: &Relay, l: &L2) -> Result<i64, String> {
    let peer: IpAddr = l.peer.parse().map_err(|_| format!("bad peer {}", l.peer))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    crate::proxy::handshake_age(&r.remote_interface, peer, now)
}

/// The lane interfaces that exist, for the relay's IP forwarding check.
pub fn interfaces(r: &Relay) -> Vec<String> {
    r.l2.iter().flat_map(|l| [l.port.clone(), bridge(l), gretap(l)]).filter(|i| su::exists(i)).collect()
}

// ---------------------------------------------------------------- install time

/// The unit's extra lines: whenever the relay stops (a crash included), its lanes are closed.
pub fn unit_lines(cfg: &Config) -> String {
    if lanes(cfg).is_empty() {
        return String::new();
    }
    format!("# however the relay stops, its layer-2 lanes are closed\nExecStopPost={} l2 down\n", crate::tap::BIN)
}

/// What uninstall needs to remove each lane, kept in the state file.
pub fn state(cfg: &Config) -> Value {
    Value::Array(lanes(cfg).iter().map(|l| json!({"bridge": bridge(l), "gretap": gretap(l), "port": l.port})).collect())
}

/// Remove the lanes in `recorded` (a state file's list), except those named in `keep`.
pub fn remove(recorded: &Value, keep: &[String]) {
    for l in recorded.as_array().into_iter().flatten() {
        let s = |k: &str| l[k].as_str().unwrap_or_default().to_string();
        let (br, gt, port) = (s("bridge"), s("gretap"), s("port"));
        if keep.contains(&br) || !br.starts_with(BRIDGE_PREFIX) || !gt.starts_with(GRETAP_PREFIX) {
            continue;
        }
        if su::exists(&gt) && su::kind(&gt).as_deref() == Some("gretap") {
            let _ = nl::delete_link(&gt);
        }
        let ours = su::master(&port).as_deref() == Some(br.as_str());
        if su::exists(&br) && su::kind(&br).as_deref() == Some("bridge") {
            let _ = nl::delete_link(&br);
        }
        if ours && su::exists(&port) {
            su::run(&["tc", "qdisc", "del", "dev", &port, "clsact"]);
        }
    }
}

pub fn bridges(cfg: &Config) -> Vec<String> {
    lanes(cfg).iter().map(bridge).collect()
}

pub fn banner(r: &Relay) -> Vec<String> {
    r.l2.iter()
        .map(|l| {
            format!(
                "layer-2 lane {} (accepted by name): {} bridged to {} over {}; only {} from across the tunnel, only {} from the port; everything else dropped and counted.",
                l.name,
                l.port,
                l.peer,
                r.remote_interface,
                macs_and_types(l),
                types(l)
            )
        })
        .collect()
}

fn types(l: &L2) -> String {
    l.ethertypes.iter().map(|e| format!("0x{e:04x}")).collect::<Vec<_>>().join(", ")
}

fn macs_and_types(l: &L2) -> String {
    format!("{} from {}", types(l), l.macs.join(", "))
}

pub fn status(cfg: &Config) {
    let Some(r) = &cfg.relay else { return };
    for l in &r.l2 {
        let gt = gretap(l);
        let state = match nl::is_up(&gt) {
            Some(true) => "up",
            Some(false) => "down",
            None => "absent",
        };
        let hs = match handshake_age(r, l) {
            Ok(a) => format!("handshake {a} s ago"),
            Err(e) => e,
        };
        println!("  lane   {} {state} ({hs}): {} <-> {gt} to {}", l.name, l.port, l.peer);
        for (dev, label) in [(l.port.clone(), "from the port"), (gt, "from the tunnel")] {
            let f = read_filters(&dev).unwrap_or_default();
            let passed: u64 = f.iter().filter(|(x, _)| x.ethertype.is_some()).map(|(_, n)| n).sum();
            let dropped: u64 = f.iter().filter(|(x, _)| x.ethertype.is_none()).map(|(_, n)| n).sum();
            println!("         {label}: {passed} frames passed, {dropped} dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane() -> L2 {
        L2 {
            name: "lane0".into(),
            port: "lp0".into(),
            peer: "203.0.113.2".into(),
            local: "203.0.113.1".into(),
            key: 4242,
            ethertypes: vec![0x0806, 0x88b5],
            macs: vec!["02:00:00:00:b0:01".into(), "02:00:00:00:b0:02".into()],
        }
    }

    #[test]
    fn filters_per_member() {
        let f = filters(&lane());
        let (port, tunnel, br) = (&f[0].1, &f[1].1, &f[2].1);
        assert_eq!(port.len(), 3);
        assert_eq!(tunnel.len(), 5); // 2 EtherTypes x 2 MACs, then the drop
        assert_eq!(br.len(), 2);
        assert_eq!(tunnel.last().unwrap().pref, DROP_PREF);
        assert_eq!(
            tc_line("l2g-lane0", &tunnel[0]),
            "filter add dev l2g-lane0 ingress pref 10 handle 10 protocol 0x0806 flower src_mac 02:00:00:00:b0:01 arp_sha 02:00:00:00:b0:01 action pass cookie 080602000000b001"
        );
        assert_eq!(
            tc_line("lp0", &port[1]),
            "filter add dev lp0 ingress pref 11 handle 11 protocol 0x88b5 flower action pass cookie 88b5000000000000"
        );
        assert_eq!(
            tc_line("lp0", &port[2]),
            "filter add dev lp0 ingress pref 60000 handle 60000 protocol all matchall action drop cookie 0000000000000000"
        );
    }
}
