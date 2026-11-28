// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The tap role: render, install, check, show and remove.
//!
//! One rendering function produces every file the tap needs from the declaration.
//! install writes exactly those files; check compares them, and the running state,
//! with the declaration; uninstall removes exactly the files install recorded and
//! restores the interface settings it saved before changing them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::config::{self, pystr, Config, Tap};
use crate::link::SYS_NET;
use crate::send;
use crate::sysutil as su;

pub const BRIDGE: &str = "goatrope0";
pub const STATE_DIR: &str = "/var/lib/goatrope";
pub const STATE: &str = "/var/lib/goatrope/state.json";
pub const LIB: &str = "/usr/local/lib/goatrope";
pub const BIN: &str = "/usr/local/sbin/goatrope";
pub const ETC: &str = "/etc/goatrope";
const NET: &str = "/etc/systemd/network";
const UNITS: &str = "/etc/systemd/system";
const WATCHDOG_DROPIN: &str = "/etc/systemd/system.conf.d/90-goatrope-watchdog.conf";
const SYSCTL: &str = "/etc/sysctl.d/90-goatrope.conf";
const NM: &str = "/etc/NetworkManager/conf.d/90-goatrope.conf";
const WATCHDOG_SEC: u64 = 15;
const LLDP_MASK: u32 = 1 << 14; // 01:80:C2:00:00:0E

/// install will not proceed; nothing has been changed. Exit code 2.
#[derive(Debug)]
pub struct Refusal(pub String);

type R<T> = Result<T, Refusal>;

fn refuse<T>(m: impl Into<String>) -> R<T> {
    Err(Refusal(m.into()))
}

fn header(cfg: &str) -> String {
    format!("# Written by goatrope {} from {cfg}. goatrope uninstall removes it; do not edit.\n", crate::version())
}

fn decl() -> String {
    format!("{ETC}/goatrope.toml")
}

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

fn tap_of(cfg: &Config) -> &Tap {
    cfg.tap.as_ref().expect("a [tap] is declared")
}

// ---------------------------------------------------------------- rendering

fn network_port(cfg: &Config, port: &str) -> String {
    let tap = tap_of(cfg);
    let inline = tap.mode == "inline";
    let mut lines: Vec<String> = vec![
        header(&decl()).trim_end_matches('\n').to_string(),
        format!("# {}: no address of its own", if inline { "inline bridge port" } else { "listen port" }),
        "[Match]".into(),
        format!("Name={port}"),
        "".into(),
        "[Link]".into(),
        "RequiredForOnline=no".into(),
        // Listen: goatrope-ports.service raises the link only after the egress drop is in place.
        format!("ActivationPolicy={}", if inline { "always-up" } else { "manual" }),
    ];
    if !inline {
        lines.push("ARP=no".into());
    }
    lines.push("".into());
    lines.push("[Network]".into());
    if inline {
        lines.push(format!("Bridge={BRIDGE}"));
    }
    for l in [
        "LinkLocalAddressing=no",
        "IPv6AcceptRA=no",
        "IPv6SendRA=no",
        "LLDP=no",
        "EmitLLDP=no",
        "DHCP=no",
        "ConfigureWithoutCarrier=yes",
        "",
    ] {
        lines.push(l.into());
    }
    lines.join("\n")
}

fn bridge_files() -> Vec<(String, String)> {
    let h = header(&decl());
    let netdev = format!(
        "{h}# inline: a bridge of exactly the two tap ports; STP off, LLDP forwarded
[NetDev]
Name={BRIDGE}
Kind=bridge

[Bridge]
STP=no
ForwardDelaySec=0
MulticastSnooping=no
MulticastQuerier=no
VLANFiltering=no
GroupForwardMask={LLDP_MASK}
"
    );
    let network = format!(
        "{h}# inline: the bridge has no address, so this machine sends nothing on the link
[Match]
Name={BRIDGE}

[Link]
RequiredForOnline=no
ActivationPolicy=always-up

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
IPv6SendRA=no
LLDP=no
EmitLLDP=no
DHCP=no
ConfigureWithoutCarrier=yes
"
    );
    vec![(format!("{NET}/04-goatrope-{BRIDGE}.netdev"), netdev), (format!("{NET}/04-goatrope-{BRIDGE}.network"), network)]
}

/// The decapsulating interface, made by systemd-networkd at every boot, as it makes the bridge.
/// Independent: it is bound to no underlay's .network file, which belongs to the system, not goatrope.
fn erspan_netdev(port: &str, e: &config::Erspan) -> String {
    let index = if e.version == 1 { "ERSPANIndex=1\n" } else { "" };
    format!(
        "{}# listen, erspan: decapsulates mirror session {} sent from {} to {}; it never transmits
[NetDev]
Name={port}
Kind=erspan

[Tunnel]
Local={}
Remote={}
Key={}
SerializeTunneledPackets=yes
ERSPANVersion={}
{index}Independent=yes
",
        header(&decl()),
        e.gre_key,
        e.remote,
        e.local,
        e.local,
        e.remote,
        e.gre_key,
        e.version
    )
}

fn tap_names(tap: &Tap) -> Vec<String> {
    let mut names = tap.ports.clone();
    if tap.mode == "inline" {
        names.push(BRIDGE.into());
    }
    names
}

fn sysctl_file(cfg: &Config) -> String {
    let tap = tap_of(cfg);
    let mut lines = vec![header(&decl()).trim_end_matches('\n').to_string(), "# no IPv6 on tap interfaces".into()];
    for n in tap_names(tap) {
        lines.push(format!("net/ipv6/conf/{n}/disable_ipv6 = 1"));
    }
    if tap.mode == "inline" {
        lines.push("# bridged frames do not pass through iptables (the '-' ignores a missing key)".into());
        lines.push("-net.bridge.bridge-nf-call-iptables = 0".into());
        lines.push("-net.bridge.bridge-nf-call-ip6tables = 0".into());
        lines.push("-net.bridge.bridge-nf-call-arptables = 0".into());
    }
    lines.join("\n") + "\n"
}

fn ports_unit() -> String {
    format!(
        "{}[Unit]
Description=goatrope: prepare the tap ports (IPv6, offloads, EEE, speed; listen: egress drop, then link up)
After=systemd-networkd.service
Wants=systemd-networkd.service

[Service]
# exec, not oneshot: boot does not wait while a port that is late (a USB adapter) is awaited.
Type=exec
RemainAfterExit=yes
ExecStart={BIN} apply-ports --config {ETC}/goatrope.toml

[Install]
WantedBy=multi-user.target
",
        header(&decl())
    )
}

pub fn recorder_argv(cfg: &Config, port: &str) -> Vec<String> {
    let r = &tap_of(cfg).record;
    let mut argv: Vec<String> = [
        "/usr/bin/tcpdump",
        "-n",
        "-i",
        port,
        "-s",
        "0",
        "-B",
        "8192",
        "-C",
        &r.file_mb.to_string(),
        "-W",
        &r.files.to_string(),
        "-Z",
        "tcpdump",
        "-w",
        &format!("{}/{port}.pcap", r.directory),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if !r.filter.is_empty() {
        argv.push("--".into()); // after "--": a filter is never read as a tcpdump option
        argv.push(r.filter.clone());
    }
    argv
}

fn record_unit(cfg: &Config) -> String {
    let r = &tap_of(cfg).record;
    let mut argv = recorder_argv(cfg, "%i");
    if !r.filter.is_empty() {
        // the declaration refuses quotes, backslashes and control characters; escape systemd's specifiers
        let last = argv.len() - 1;
        argv[last] = format!("'{}'", r.filter.replace('%', "%%").replace('$', "$$"));
    }
    format!(
        "{}[Unit]
Description=goatrope: bounded recording ring on %i ({} files of {} MB)
After=goatrope-ports.service
Wants=goatrope-ports.service

[Service]
ExecStart={}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
",
        header(&decl()),
        r.files,
        r.file_mb,
        argv.join(" ")
    )
}

fn watchdog() -> String {
    format!(
        "{}# hardware watchdog: a hung machine restarts\n[Manager]\nRuntimeWatchdogSec={WATCHDOG_SEC}s\nRebootWatchdogSec=2min\n",
        header("the tap role")
    )
}

fn nm_file(cfg: &Config) -> String {
    // "+=" adds to what other files set; "=" would replace it, and NetworkManager would take every
    // device those files keep from it (on Ubuntu: every wired port, the management port among them).
    let names: Vec<String> = tap_names(tap_of(cfg)).iter().map(|n| format!("interface-name:{n}")).collect();
    format!("{}[keyfile]\nunmanaged-devices+={}\n", header(&decl()), names.join(";"))
}

pub fn render(cfg: &Config, nm_present: bool) -> BTreeMap<String, String> {
    let tap = tap_of(cfg);
    let mut files = BTreeMap::new();
    for p in &tap.ports {
        files.insert(format!("{NET}/05-goatrope-{p}.network"), network_port(cfg, p));
    }
    if tap.mode == "inline" {
        files.extend(bridge_files());
    }
    if let Some(e) = &tap.erspan {
        files.insert(format!("{NET}/03-goatrope-{}.netdev", tap.ports[0]), erspan_netdev(&tap.ports[0], e));
    }
    files.insert(SYSCTL.into(), sysctl_file(cfg));
    files.insert(format!("{UNITS}/goatrope-ports.service"), ports_unit());
    files.insert(format!("{UNITS}/goatrope-record@.service"), record_unit(cfg));
    files.insert(WATCHDOG_DROPIN.into(), watchdog());
    if nm_present {
        files.insert(NM.into(), nm_file(cfg));
    }
    files
}

pub fn units(cfg: &Config) -> Vec<String> {
    let mut u = vec!["goatrope-ports.service".to_string()];
    u.extend(tap_of(cfg).record.ports.iter().map(|p| format!("goatrope-record@{p}.service")));
    u
}

/// Every file install writes for this declaration: the tap's (when it has a [tap]), the relay's
/// unit and decode-and-send's; and the mode of each file not written 0644.
fn all_files(cfg: &Config, nm_present: bool) -> (BTreeMap<String, String>, std::collections::HashMap<String, u32>) {
    let mut files = if cfg.tap.is_some() { render(cfg, nm_present) } else { BTreeMap::new() };
    files.extend(crate::relay::render(cfg));
    let (sfiles, modes) = send::render(cfg);
    files.extend(sfiles);
    (files, modes)
}

fn all_units(cfg: &Config) -> Vec<String> {
    let mut u = if cfg.tap.is_some() { units(cfg) } else { vec![] };
    u.extend(crate::relay::units(cfg));
    u.extend(send::units(cfg));
    u
}

// ---------------------------------------------------------------- refusals

fn os_release() -> BTreeMap<String, String> {
    let path = std::env::var("GOATROPE_OS_RELEASE").unwrap_or_else(|_| "/etc/os-release".into());
    let mut out = BTreeMap::new();
    for line in fs::read_to_string(path).unwrap_or_default().lines() {
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn machine() -> String {
    // SAFETY: utsname is plain data; uname fills it.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is a valid utsname.
    unsafe { libc::uname(&mut u) };
    // SAFETY: uname writes a NUL-terminated machine field.
    unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) }.to_string_lossy().into_owned()
}

fn dir_size(d: &str) -> f64 {
    fs::read_dir(d).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len() as f64).sum()).unwrap_or(0.0)
}

/// The machine goatrope runs on, for every role.
fn platform() -> R<()> {
    let osr = os_release();
    if osr.get("ID").map(String::as_str) != Some("ubuntu")
        || !matches!(osr.get("VERSION_ID").map(String::as_str), Some("24.04") | Some("26.04"))
    {
        let pretty = osr.get("PRETTY_NAME").cloned().unwrap_or_else(|| "an unknown system".into());
        return refuse(format!("this is {pretty}; goatrope supports Ubuntu 24.04 and 26.04"));
    }
    let m = machine();
    if m != "aarch64" && m != "x86_64" {
        return refuse(format!("architecture {m} is not supported (arm64 and amd64 are)"));
    }
    Ok(())
}

pub fn preflight(cfg: &Config) -> R<()> {
    let tap = tap_of(cfg);
    platform()?;
    for tool in ["tcpdump", "ethtool", "tc", "ip", "ss", "networkctl", "systemctl"] {
        if !su::have(tool) {
            return refuse(format!("{tool} is not installed: sudo apt-get install -y tcpdump ethtool iproute2 systemd"));
        }
    }
    if !su::exists(&tap.management) {
        return refuse(format!("the management interface {} does not exist (see: ip -br link)", tap.management));
    }
    if let Some(e) = &tap.erspan {
        let p = &tap.ports[0];
        if su::exists(p) && su::kind(p).as_deref() != Some("erspan") {
            return refuse(format!("{p} exists and is not an erspan interface; name the interface goatrope makes for the mirror"));
        }
        if !su::exists(&e.underlay) {
            return refuse(format!("the underlay {} does not exist (see: ip -br link)", e.underlay));
        }
        if !su::addresses(&e.underlay).iter().any(|a| a.split('/').next() == Some(e.local.as_str())) {
            return refuse(format!("{} does not hold {}, where the mirror is sent; configure the address first", e.underlay, e.local));
        }
    }
    for p in &tap.ports {
        if tap.erspan.is_some() && !su::exists(p) {
            continue; // goatrope makes it
        }
        if !su::exists(p) {
            return refuse(format!("no interface {p} (see: ip -br link)"));
        }
        let k = su::kind(p);
        if p == "lo"
            || matches!(k.as_deref(), Some("bridge") | Some("bond") | Some("wireguard") | Some("tun") | Some("vlan"))
            || (k.as_deref() == Some("erspan") && tap.erspan.is_none())
        {
            return refuse(format!("{p} is a {} interface, not an Ethernet port", k.unwrap_or_else(|| "loopback".into())));
        }
        if Path::new(&format!("{SYS_NET}/{p}/wireless")).exists() {
            return refuse(format!("{p} is wireless; a tap port is wired"));
        }
        if let Some(m) = su::master(p) {
            if m != BRIDGE {
                return refuse(format!("{p} is already a member of {m}; remove it from there first"));
            }
        }
        let stacked: Vec<String> = su::uppers(p).into_iter().filter(|u| u != BRIDGE).collect();
        if !stacked.is_empty() {
            return refuse(format!(
                "{p} carries {} (a VLAN or other device on top of it); remove it first, or what uses it loses the link",
                stacked.join(", ")
            ));
        }
    }
    let mut taken: BTreeSet<String> = tap.ports.iter().cloned().collect();
    if su::exists(BRIDGE) {
        taken.insert(BRIDGE.into());
    }
    for p in &taken {
        let addrs: Vec<String> = su::addresses(p).into_iter().filter(|a| !a.to_lowercase().starts_with("fe80:")).collect();
        if !addrs.is_empty() {
            return refuse(format!(
                "{p} has address(es) {}: it is in use. A tap port has no address; move what uses it to the management interface first",
                addrs.join(", ")
            ));
        }
    }
    for dev in crate::link::default_route_devs() {
        if taken.contains(&dev) {
            return refuse(format!("the default route leaves through {dev}; it cannot become a tap port"));
        }
    }
    if let Some((peer, devs)) = su::session() {
        let hit: Vec<&String> = devs.iter().filter(|d| taken.contains(*d)).collect();
        if !hit.is_empty() {
            return refuse(format!(
                "{} carries this session (from {peer}); manage the machine over {} first",
                hit.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                tap.management
            ));
        }
    }
    for (peer, devs) in su::established() {
        let hit: Vec<&String> = devs.iter().filter(|d| taken.contains(*d)).collect();
        if !hit.is_empty() {
            return refuse(format!(
                "{} carries an established connection to {peer}; it cannot become a tap port",
                hit.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let r = &tap.record;
    // one ring per recorded port, plus what file destinations may hold (twice max_mb each)
    let file_dests: Vec<i64> =
        cfg.sends.iter().flat_map(|s| s.to.iter()).filter(|d| d.scheme == "file").map(|d| d.max_mb.unwrap_or(0)).collect();
    let mut need = (r.ports.len() as f64) * (r.files as f64) * (r.file_mb as f64) * 1e6;
    need += file_dests.iter().map(|m| 2.0 * *m as f64 * 1e6).sum::<f64>();
    let mut probe = r.directory.clone();
    while !Path::new(&probe).exists() {
        probe = Path::new(&probe).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
    }
    let (free, total) = su::statvfs(&probe).unwrap_or((0.0, 0.0));
    let used = if Path::new(&r.directory).is_dir() { dir_size(&r.directory) } else { 0.0 };
    // leave 10% of what is available, and at least 5% of the filesystem, for the system
    let room = (0.9 * (free + used)).min(free + used - 0.05 * total);
    if need > room {
        return refuse(format!(
            "the recording ({} ring(s) of {} x {} MB{} = {:.1} GB) does not fit in the {:.1} GB goatrope may use at {probe}; declare fewer or smaller files",
            r.ports.len(),
            r.files,
            r.file_mb,
            if file_dests.is_empty() { "" } else { " plus file destinations" },
            need / 1e9,
            room.max(0.0) / 1e9
        ));
    }
    if let (Some(relay), "listen") = (&cfg.relay, tap.mode.as_str()) {
        for n in [&relay.link_interface, &relay.remote_interface] {
            if tap.ports.contains(n) {
                return refuse(format!("{n} is a listen port and also a relay interface"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- port preparation (boot and install)

fn wait_for(ifname: &str, seconds: f64) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(seconds);
    while Instant::now() < end {
        if su::exists(ifname) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    su::exists(ifname)
}

/// Idempotent. Returns the problems found; an empty list is success.
pub fn apply_ports(cfg: &Config, wait: f64) -> Vec<String> {
    let tap = tap_of(cfg);
    let mut problems = Vec::new();
    for p in &tap.ports {
        if !wait_for(p, wait) {
            problems.push(format!("{p} did not appear within {wait:.0} s"));
            continue;
        }
        su::write(&format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6"), "1");
        for (short, _) in su::OFFLOADS {
            su::run(&["ethtool", "-K", p, short, "off"]);
        }
        su::run(&["ethtool", "--set-eee", p, "eee", "off"]);
        if let Some(speed) = tap.speed_mbps {
            let s = speed.to_string();
            let r = su::run(&["ethtool", "-s", p, "speed", &s, "duplex", "full", "autoneg", "off"]);
            if r.code != 0 {
                problems.push(format!("{p}: could not force {speed} Mb/s full duplex: {}", r.stderr.trim()));
            }
        }
        if tap.mode == "listen" {
            if !su::egress_drop(p) {
                su::run(&["tc", "qdisc", "replace", "dev", p, "clsact"]);
                // whatever holds pref 1 goes: goatrope's drop is the first filter
                su::run(&["tc", "filter", "del", "dev", p, "egress", "pref", "1"]);
                su::run(&["tc", "filter", "add", "dev", p, "egress", "pref", "1", "handle", "1", "matchall", "action", "drop"]);
            }
            if !su::egress_drop(p) {
                problems.push(format!("{p}: the egress drop could not be installed; the link stays down"));
                su::run(&["ip", "link", "set", p, "down"]);
                continue;
            }
            su::run(&["ip", "link", "set", p, "arp", "off"]);
            su::run(&["ip", "link", "set", p, "up"]);
        }
    }
    if tap.mode == "inline" && wait_for(BRIDGE, 10.0) {
        su::write(&format!("/proc/sys/net/ipv6/conf/{BRIDGE}/disable_ipv6"), "1");
        // networkd sets these when it creates the bridge, not on an existing one; assert them every time.
        // STP off first: the kernel refuses a forward delay under 2 s while STP is on.
        su::run(&["ip", "link", "set", BRIDGE, "type", "bridge", "stp_state", "0"]);
        let mask = format!("{LLDP_MASK:#x}");
        su::run(&["ip", "link", "set", BRIDGE, "type", "bridge", "forward_delay", "0", "group_fwd_mask", &mask, "mcast_snooping", "0"]);
    }
    problems
}

// ---------------------------------------------------------------- state

fn opt_str(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

fn snapshot_port(p: &str) -> Value {
    let feats: Map<String, Value> =
        su::features(p).into_iter().filter(|(_, (_, fixed))| !fixed).map(|(k, (v, _))| (k, Value::String(v))).collect();
    let ls = su::link_settings(p);
    let qd = su::run(&["tc", "qdisc", "show", "dev", p]).stdout;
    json!({
        "features": feats,
        "eee": su::eee(p),
        "link": {"speed": ls.speed, "duplex": ls.duplex, "autoneg": ls.autoneg},
        "up": su::is_up(p),
        "noarp": su::is_noarp(p),
        "disable_ipv6": opt_str(su::read(&format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6"))),
        "addr_gen_mode": opt_str(su::read(&format!("/proc/sys/net/ipv6/conf/{p}/addr_gen_mode"))),
        "clsact": qd.contains("clsact"),
    })
}

/// None when goatrope is not installed. An unreadable state file is never taken for "not installed".
pub fn load_state() -> R<Option<Value>> {
    if !Path::new(STATE).exists() {
        return Ok(None);
    }
    for path in [STATE.to_string(), format!("{STATE}.bak")] {
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(&text) {
                if v.get("ports").is_some() {
                    if path != STATE {
                        eprintln!("goatrope: {STATE} is unreadable; using the previous copy {path}");
                    }
                    return Ok(Some(v));
                }
            }
        }
    }
    refuse(format!(
        "{STATE} is unreadable or empty (a power cut during install?) and has no readable previous copy; goatrope will not guess what to restore. Inspect it, restore the ports by hand, then remove it"
    ))
}

fn save_state(state: &Value) -> std::io::Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    let text = serde_json::to_string_pretty(state).unwrap_or_default() + "\n";
    if let Ok(old) = fs::read_to_string(STATE) {
        if serde_json::from_str::<Value>(&old).is_ok() {
            let _ = fs::copy(STATE, format!("{STATE}.bak")); // the previous good copy
        }
    }
    su::write_file(STATE, &text, 0o600)
}

#[cfg(test)]
pub fn save_state_for_test(state: &Value) {
    save_state(state).unwrap();
}

fn makedirs(d: &str, state: &mut Value) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cur = Path::new(d).to_path_buf();
    while !cur.as_os_str().is_empty() && !cur.is_dir() {
        missing.push(cur.clone());
        match cur.parent() {
            Some(p) => cur = p.to_path_buf(),
            None => break,
        }
    }
    for m in missing.iter().rev() {
        fs::create_dir(m)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(m, fs::Permissions::from_mode(0o755))?;
        let ms = Value::String(m.to_string_lossy().to_string());
        let list = state["created_dirs"].as_array_mut().unwrap();
        if !list.contains(&ms) {
            list.push(ms);
        }
    }
    Ok(())
}

fn remove(path: &str) {
    let _ = fs::remove_file(path);
}

fn networkd_links() -> Vec<String> {
    fn walk(d: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = fs::symlink_metadata(&p) else { continue };
            if md.file_type().is_symlink() {
                if let Ok(t) = fs::read_link(&p) {
                    if t.file_name().map(|n| n.to_string_lossy().starts_with("systemd-network")).unwrap_or(false) {
                        out.push(p.to_string_lossy().to_string());
                    }
                }
            } else if md.is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("/etc/systemd/system"), &mut out);
    out.sort();
    out
}

fn nm_wait_unmanaged(cfg: &Config) {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        let st = su::nm_states();
        if tap_of(cfg).ports.iter().all(|p| st.get(p).map(String::as_str).unwrap_or("unmanaged") == "unmanaged") {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Wait until networkd has built the declared shape, or give up quietly.
fn settle(cfg: &Config) {
    let tap = tap_of(cfg);
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        if tap.mode == "listen" {
            if tap.ports.iter().all(|p| su::is_up(p)) {
                return;
            }
        } else if su::exists(BRIDGE) && tap.ports.iter().all(|p| su::master(p).as_deref() == Some(BRIDGE)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn ids_of(name: &str) -> Option<(u32, u32)> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: c is NUL-terminated; getpwnam returns a pointer into static storage or null.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: pw is non-null and points to a passwd record.
    let uid = unsafe { (*pw).pw_uid };
    // SAFETY: as above, for the group database.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    // SAFETY: gr is checked for null before it is read.
    let gid = if gr.is_null() { unsafe { (*pw).pw_gid } } else { unsafe { (*gr).gr_gid } };
    Some((uid, gid))
}

/// The binary that is running, copied to BIN; its VERSION to LIB. A Python tree left by an
/// earlier release goes with it.
fn install_software() -> std::io::Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    if exe != Path::new(BIN) {
        let tmp = format!("{BIN}.goatrope-new");
        fs::copy(&exe, &tmp)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::File::open(&tmp)?.sync_all()?;
        fs::rename(&tmp, BIN)?;
        su::fsync_dir(Path::new("/usr/local/sbin"));
    }
    if Path::new(LIB).join("goatrope").is_dir() {
        let _ = fs::remove_dir_all(Path::new(LIB).join("goatrope"));
    }
    fs::create_dir_all(LIB)?;
    su::write_file(&format!("{LIB}/VERSION"), &format!("{}\n", crate::version()), 0o644)
}

fn refuse_all(cfg: &Config) -> R<()> {
    if cfg.tap.is_none() {
        // a relay alone: the relay checks its own interfaces when it starts, and a refusal leaves its unit failed
        return platform();
    }
    preflight(cfg)?;
    let bad = send::refuse_tap_routes(cfg);
    if !bad.is_empty() {
        return refuse(format!("{}: decode-and-send never transmits on the tapped link", bad.join("; ")));
    }
    Ok(())
}

fn io(e: std::io::Error) -> Refusal {
    Refusal(format!("cannot write: {}", crate::sys::strerror(&e)))
}

/// Bring the machine to this software and this declaration, once. Refuses as install does. A machine
/// already there is left alone. Returns unchanged, changed or (dry run) would-change.
pub fn deploy(cfg: &Config, dry_run: bool) -> R<&'static str> {
    refuse_all(cfg)?;
    let state = load_state()?;
    let declared = fs::read_to_string(&cfg.path).unwrap_or_default();
    let mine = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok()).and_then(|e| send::sha256_file(&e.to_string_lossy()));
    let there = state.is_some()
        && Path::new(BIN).exists()
        && mine.is_some()
        && send::sha256_file(BIN) == mine
        && su::read(&format!("{LIB}/VERSION")).as_deref() == Some(crate::version().as_str())
        && su::read(&decl()).unwrap_or_default() == declared.trim()
        && check(cfg).iter().all(|i| i.ok != Some(false));
    if there {
        return Ok("unchanged");
    }
    if dry_run {
        return Ok("would-change");
    }
    install(cfg)?;
    Ok("changed")
}

pub fn install(cfg: &Config) -> R<()> {
    let prior = load_state()?;
    refuse_all(cfg)?;
    if cfg.tap.is_none() && prior.as_ref().is_some_and(|p| p.get("mode").is_some_and(|m| m.is_string())) {
        return refuse(
            "the installed declaration has a [tap] and this one has none; run goatrope uninstall first, so the tap ports are restored",
        );
    }
    let nm_present = Path::new("/etc/NetworkManager").is_dir();
    let (files, modes) = all_files(cfg, nm_present);

    let mut state = prior.unwrap_or_else(|| {
        json!({
            "ports": {},
            "networkd": {"enabled": su::unit_enabled("systemd-networkd.service"),
                         "active": su::unit_active("systemd-networkd.service"),
                         "links": networkd_links()},
            "created_dirs": [],
            "var_lib_private_existed": Path::new("/var/lib/private").is_dir(),
        })
    });
    if !state["created_dirs"].is_array() {
        state["created_dirs"] = json!([]);
    }
    let tap_cfg = cfg.tap.as_ref();
    if let Some(tap) = tap_cfg.filter(|t| t.erspan.is_some()) {
        let p = tap.ports[0].clone();
        let mut made: Vec<Value> = state["created_links"].as_array().cloned().unwrap_or_default();
        if !su::exists(&p) && !made.contains(&json!(p)) {
            made.push(json!(p));
        }
        state["created_links"] = Value::Array(made);
    }
    for p in tap_cfg.map(|t| t.ports.as_slice()).unwrap_or_default() {
        // first sight of a port: remember how it was (a link goatrope makes is removed instead)
        let made = state["created_links"].as_array().map(|a| a.contains(&json!(p))).unwrap_or(false);
        if state["ports"].get(p).is_none() && !made {
            state["ports"][p] = snapshot_port(p);
        }
    }
    state["version"] = json!(crate::version());
    if let Some(tap) = tap_cfg {
        state["mode"] = json!(tap.mode);
        state["record_directory"] = json!(tap.record.directory);
    }
    // a lane the previous declaration had and this one does not is removed
    crate::l2::remove(&state["relay"]["l2"], &crate::l2::bridges(cfg));
    // uninstall removes a boundary interface the relay made, and the layer-2 lanes
    state["relay"] = match &cfg.relay {
        Some(r) => json!({"transport": r.transport, "remote_interface": r.remote_interface, "l2": crate::l2::state(cfg)}),
        None => Value::Null,
    };
    let stale: Vec<String> = state["files"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).filter(|f| !files.contains_key(*f)).map(String::from).collect())
        .unwrap_or_default();

    let mut dirs: Vec<String> = vec![STATE_DIR.into(), ETC.into()];
    dirs.extend(tap_cfg.map(|t| t.record.directory.clone()));
    let mut parents: Vec<String> = files.keys().filter_map(|f| Path::new(f).parent().map(|p| p.to_string_lossy().to_string())).collect();
    parents.sort();
    parents.dedup();
    dirs.extend(parents);
    for d in &dirs {
        makedirs(d, &mut state).map_err(io)?; // every directory install creates is in the state before anything is written
    }
    if let (Some(tap), Some((uid, gid))) = (tap_cfg, ids_of("tcpdump")) {
        let c = std::ffi::CString::new(tap.record.directory.as_str()).unwrap();
        // SAFETY: c is a NUL-terminated path.
        unsafe { libc::chown(c.as_ptr(), uid, gid) };
    }
    if let Some(tap) = tap_cfg {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tap.record.directory, fs::Permissions::from_mode(0o750));
    }
    state["files"] = json!(files.keys().collect::<Vec<_>>());
    save_state(&state).map_err(io)?; // before any change, so uninstall can always undo

    install_software().map_err(io)?;
    let same = fs::canonicalize(&cfg.path).ok() == fs::canonicalize(decl()).ok();
    if !same {
        let text = fs::read_to_string(&cfg.path).unwrap_or_default();
        if let Some(prev) = su::read(&decl()) {
            if prev != text.trim() {
                su::write_file(&format!("{ETC}/goatrope.toml.prev"), &format!("{prev}\n"), 0o644).map_err(io)?;
                println!("  the previous declaration is kept as {ETC}/goatrope.toml.prev");
            }
        }
        su::write_file(&decl(), &text, 0o644).map_err(io)?;
    }
    for f in &stale {
        remove(f);
    }
    for (path, content) in &files {
        su::write_file(path, content, *modes.get(path).unwrap_or(&0o644)).map_err(io)?;
    }
    let want_units = all_units(cfg);
    if let Some(old) = state["units"].as_array() {
        for u in old.iter().filter_map(|v| v.as_str()) {
            if !want_units.iter().any(|w| w == u) {
                su::systemctl(&["disable", "--now", u]);
            }
        }
    }
    state["units"] = json!(want_units);
    save_state(&state).map_err(io)?;

    su::systemctl(&["daemon-reload"]);
    if let Some(tap) = tap_cfg {
        install_tap(cfg, tap, nm_present);
    }
    if cfg.relay.is_some() {
        su::systemctl(&["enable", crate::relay::UNIT]);
        su::systemctl(&["restart", crate::relay::UNIT]);
        crate::relay::settle(cfg, 5.0);
    }
    Ok(())
}

/// The tap's part of install, after its files are written: the ports, the bridge, the recorders.
fn install_tap(cfg: &Config, tap: &Tap, nm_present: bool) {
    su::run(&["sysctl", "-q", "-p", SYSCTL]);
    if nm_present && su::nm_active() {
        su::run(&["nmcli", "general", "reload", "conf"]); // NetworkManager lets go of the tap ports now, not at reboot
        nm_wait_unmanaged(cfg);
    }
    su::systemctl(&["enable", "--now", "systemd-networkd.service"]);
    su::run(&["networkctl", "reload"]);
    for p in &tap.ports {
        if tap.erspan.is_some() {
            wait_for(p, 10.0);
        }
    }
    if tap.mode == "listen" && su::exists(BRIDGE) {
        su::run(&["ip", "link", "del", BRIDGE]); // left from an earlier inline declaration
    }
    for p in &tap.ports {
        su::run(&["networkctl", "reconfigure", p]);
    }
    for p in apply_ports(cfg, 10.0) {
        println!("  warning: {p}");
    }
    su::systemctl(&["enable", "goatrope-ports.service"]);
    su::systemctl(&["restart", "goatrope-ports.service"]);
    for p in &tap.record.ports {
        let u = format!("goatrope-record@{p}.service");
        su::systemctl(&["enable", &u]);
        su::systemctl(&["restart", &u]);
    }
    send::start(cfg);
    su::systemctl(&["daemon-reexec"]); // applies the watchdog setting
    settle(cfg);
}

// ---------------------------------------------------------------- uninstall

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

pub fn uninstall(purge: bool) -> R<()> {
    let Some(state) = load_state()? else {
        if purge {
            purge_leftovers();
        } else {
            println!("goatrope is not installed (no state file); nothing to remove");
        }
        return Ok(());
    };
    if let Some(units) = state["units"].as_array() {
        for u in units.iter().rev().filter_map(|v| v.as_str()) {
            su::systemctl(&["disable", "--now", u]);
        }
    }
    if let Some(files) = state["files"].as_array() {
        for f in files.iter().filter_map(|v| v.as_str()) {
            remove(f);
        }
    }
    su::systemctl(&["daemon-reload"]);
    if s(&state["relay"], "transport") == Some("boundary") {
        if let Some(ifname) = s(&state["relay"], "remote_interface") {
            let _ = crate::boundary::down(ifname); // the relay's own interface; a mesh interface is never touched
        }
    }
    crate::l2::remove(&state["relay"]["l2"], &[]);
    remove(crate::relay::HEALTH);
    if su::nm_active() {
        su::run(&["nmcli", "general", "reload", "conf"]);
    }
    su::run(&["networkctl", "reload"]);
    if su::exists(BRIDGE) {
        su::run(&["ip", "link", "del", BRIDGE]);
    }
    // links goatrope made (the erspan interface): networkd does not remove a netdev whose file is gone
    if let Some(made) = state["created_links"].as_array() {
        for l in made.iter().filter_map(|v| v.as_str()) {
            if su::exists(l) && su::kind(l).as_deref() == Some("erspan") {
                let _ = crate::nl::delete_link(l);
            }
        }
    }
    if let Some(ports) = state["ports"].as_object() {
        for (p, prior) in ports {
            if !su::exists(p) {
                continue;
            }
            let up = prior["up"].as_bool().unwrap_or(false);
            if !up {
                su::run(&["ip", "link", "set", p, "down"]); // down before the egress drop goes
            }
            if prior["clsact"].as_bool().unwrap_or(false) {
                su::run(&["tc", "filter", "del", "dev", p, "egress", "pref", "1", "handle", "1", "matchall"]);
            } else {
                su::run(&["tc", "qdisc", "del", "dev", p, "clsact"]);
            }
            if let Some(feats) = prior["features"].as_object() {
                for (short, val) in feats {
                    if let Some(v) = val.as_str() {
                        su::run(&["ethtool", "-K", p, short, v]);
                    }
                }
            }
            if s(prior, "eee") == Some("enabled") {
                su::run(&["ethtool", "--set-eee", p, "eee", "on"]);
            }
            if s(&prior["link"], "autoneg") == Some("on") && su::link_settings(p).autoneg.as_deref() == Some("off") {
                su::run(&["ethtool", "-s", p, "autoneg", "on"]);
            }
            let arp = if prior["noarp"].as_bool().unwrap_or(false) { "off" } else { "on" };
            su::run(&["ip", "link", "set", p, "arp", arp]);
            if let Some(v) = s(prior, "addr_gen_mode") {
                su::write(&format!("/proc/sys/net/ipv6/conf/{p}/addr_gen_mode"), v);
            }
            if let Some(v) = s(prior, "disable_ipv6") {
                su::write(&format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6"), v);
            }
            su::run(&["ip", "link", "set", p, if up { "up" } else { "down" }]);
            su::run(&["networkctl", "reconfigure", p]);
        }
    }
    let nd = &state["networkd"];
    if let Some(links) = nd["links"].as_array() {
        // netplan enables networkd under /run only, so `disable` alone cannot say what to undo
        let before: BTreeSet<&str> = links.iter().filter_map(|v| v.as_str()).collect();
        for link in networkd_links() {
            if before.contains(link.as_str()) {
                continue;
            }
            remove(&link);
            if let Some(d) = Path::new(&link).parent() {
                if d != Path::new("/etc/systemd/system") && fs::read_dir(d).map(|mut r| r.next().is_none()).unwrap_or(false) {
                    let _ = fs::remove_dir(d); // as systemctl disable does
                }
            }
        }
    } else if matches!(s(nd, "enabled"), Some("disabled") | Some("masked")) {
        su::systemctl(&["disable", "systemd-networkd.service"]);
    }
    if s(nd, "active") != Some("active") {
        su::systemctl(&["stop", "systemd-networkd.service", "systemd-networkd.socket"]);
    }
    su::systemctl(&["daemon-reexec"]);
    if Path::new(LIB).is_dir() {
        let _ = fs::remove_dir_all(LIB);
    }
    remove(BIN);
    // verified component copies, and the state systemd kept for the decoders' dynamic users
    let _ = fs::remove_dir_all(format!("{STATE_DIR}/components"));
    for (dir, is_link) in [("/var/lib/private", false), ("/var/lib", true)] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for e in rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("goatrope-decode-")) {
            if is_link {
                let _ = fs::remove_file(e.path()); // systemd's link to the private directory
            } else {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    if Path::new("/var/lib/private").is_dir()
        && fs::read_dir("/var/lib/private").map(|mut r| r.next().is_none()).unwrap_or(false)
        && state["var_lib_private_existed"].as_bool() == Some(false)
    {
        let _ = fs::remove_dir("/var/lib/private");
    }
    let mut kept: Vec<String> = Vec::new();
    let rec = s(&state, "record_directory").map(String::from);
    for f in [decl(), format!("{ETC}/goatrope.toml.prev")] {
        if Path::new(&f).exists() {
            if purge {
                remove(&f);
            } else {
                kept.push(f);
            }
        }
    }
    for d in [rec.clone(), Some(format!("{STATE_DIR}/send"))].into_iter().flatten() {
        if !d.starts_with(&format!("{STATE_DIR}/")) || !Path::new(&d).is_dir() {
            continue;
        }
        if purge {
            let _ = fs::remove_dir_all(&d);
        } else if fs::read_dir(&d).map(|mut r| r.next().is_some()).unwrap_or(false) {
            kept.push(d);
        }
    }
    remove(STATE);
    remove(&format!("{STATE}.bak"));
    // Directories install created, deepest first, when empty.
    let mut created: Vec<String> =
        state["created_dirs"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).map(String::from).collect()).unwrap_or_default();
    created.sort_by_key(|d| std::cmp::Reverse(d.len()));
    for d in created {
        if !Path::new(&d).is_dir() {
            continue;
        }
        if fs::read_dir(&d).map(|mut r| r.next().is_none()).unwrap_or(false) {
            let _ = fs::remove_dir(&d);
        } else if !kept.contains(&d) && !kept.iter().any(|k| k.starts_with(&format!("{d}/"))) {
            kept.push(d);
        }
    }
    println!("goatrope removed: units, network files, sysctl, watchdog drop-in, software; interface settings restored");
    if !kept.is_empty() {
        println!("kept (goatrope uninstall --purge removes them): {}", kept.join(", "));
    }
    Ok(())
}

/// After a plain uninstall: the declaration and the recordings are all that remain.
fn purge_leftovers() {
    let mut removed = Vec::new();
    let rec = config::load(&decl()).ok().and_then(|c| c.tap.map(|t| t.record.directory));
    for d in [rec, Some(format!("{STATE_DIR}/record")), Some(format!("{STATE_DIR}/send"))].into_iter().flatten() {
        if d.starts_with(&format!("{STATE_DIR}/")) && Path::new(&d).is_dir() && !removed.contains(&d) {
            let _ = fs::remove_dir_all(&d);
            removed.push(d);
        }
    }
    for f in [decl(), format!("{ETC}/goatrope.toml.prev"), format!("{STATE_DIR}/relay.health")] {
        if Path::new(&f).exists() {
            remove(&f);
            removed.push(f);
        }
    }
    for d in [ETC, STATE_DIR] {
        if Path::new(d).is_dir() && fs::read_dir(d).map(|mut r| r.next().is_none()).unwrap_or(false) {
            let _ = fs::remove_dir(d);
            removed.push(d.to_string());
        }
    }
    println!("purged: {}", if removed.is_empty() { "nothing was left".to_string() } else { removed.join(", ") });
}

// ---------------------------------------------------------------- check

#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub ok: Option<bool>,
    pub want: Value,
    pub have: Value,
}

pub fn item(items: &mut Vec<Item>, id: impl Into<String>, ok: Option<bool>, want: impl Into<Value>, have: impl Into<Value>) {
    items.push(Item { id: id.into(), ok, want: want.into(), have: have.into() });
}

/// A value as Python's f-string shows it.
pub fn show(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Array(a) => {
            format!("[{}]", a.iter().map(|x| if let Value::String(s) = x { pystr(s) } else { show(x) }).collect::<Vec<_>>().join(", "))
        }
        other => other.to_string(),
    }
}

fn read_or(path: &str, d: &str) -> String {
    su::read(path).unwrap_or_else(|| d.to_string())
}

/// Every property the declaration implies, compared with the machine. ok is true, false or None (info).
pub fn check(cfg: &Config) -> Vec<Item> {
    let mut items = Vec::new();
    let state = load_state().ok().flatten();
    item(&mut items, "installed", Some(state.is_some()), "goatrope state present", if state.is_some() { "present" } else { "absent" });
    let inst = su::read(&format!("{LIB}/VERSION"));
    let v = crate::version();
    item(&mut items, "software", Some(inst.as_deref() == Some(v.as_str())), v.clone(), inst.unwrap_or_else(|| "absent".into()));
    let nm_present = Path::new("/etc/NetworkManager").is_dir();
    let expected = all_files(cfg, nm_present).0;
    for (path, content) in &expected {
        let have = su::read(path);
        let same = have.as_deref() == Some(content.trim());
        item(
            &mut items,
            format!("file:{path}"),
            Some(same),
            "as declared",
            if have.is_none() {
                "absent"
            } else if same {
                "as declared"
            } else {
                "differs"
            },
        );
    }
    for unit in &all_units(cfg) {
        let a = su::unit_active(unit);
        item(&mut items, format!("unit:{unit}"), Some(a == "active"), "active", a);
        let e = su::unit_enabled(unit);
        item(&mut items, format!("enabled:{unit}"), Some(e == "enabled"), "enabled", e);
    }
    if let Some(tap) = &cfg.tap {
        items.extend(check_tap(cfg, tap));
    }
    items.extend(crate::relay::check(cfg));
    items.extend(crate::l2::check(cfg));
    let src = su::run(&["findmnt", "-no", "SOURCE", "/"]).stdout.trim().to_string();
    let crypt = su::run(&["lsblk", "-no", "TYPE", "-s", &src]).stdout.contains("crypt");
    item(
        &mut items,
        "root-encryption",
        None,
        "encrypted root (deferred; not a check yet)",
        if crypt { "dm-crypt" } else { "not encrypted (or not detected)" },
    );
    items.extend(send::check(cfg));
    items
}

/// What a [tap] implies: networkd, the ports, the bridge, the rings, the watchdog.
fn check_tap(cfg: &Config, tap: &Tap) -> Vec<Item> {
    let mut items = Vec::new();
    let a = su::unit_active("systemd-networkd.service");
    item(&mut items, "unit:systemd-networkd.service", Some(a == "active"), "active", a);

    let mg = &tap.management;
    item(
        &mut items,
        format!("management:{mg}"),
        Some(su::exists(mg) && !tap.ports.contains(mg)),
        "exists, not a tap port",
        if su::exists(mg) { "exists" } else { "absent" },
    );
    let mut taken: BTreeSet<String> = tap.ports.iter().cloned().collect();
    taken.insert(BRIDGE.into());
    let bad: Vec<String> = crate::link::default_route_devs().into_iter().filter(|d| taken.contains(d)).collect();
    item(
        &mut items,
        "default-route",
        Some(bad.is_empty()),
        "not through a tap port",
        if bad.is_empty() { "not through a tap port".to_string() } else { bad.join(", ") },
    );

    for p in &tap.ports {
        if !su::exists(p) {
            item(&mut items, format!("port:{p}"), Some(false), "exists", "absent");
            continue;
        }
        let addrs = su::addresses(p);
        item(
            &mut items,
            format!("address:{p}"),
            Some(addrs.is_empty()),
            "none",
            if addrs.is_empty() { "none".into() } else { addrs.join(", ") },
        );
        let v6 = su::read(&format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6"));
        item(&mut items, format!("ipv6-disabled:{p}"), Some(v6.as_deref() == Some("1")), "1", opt_str(v6));
        let nf = su::run(&["networkctl", "status", p, "--no-pager"]).stdout;
        let nfile = nf
            .lines()
            .find(|l| l.trim().starts_with("Network File:"))
            .and_then(|l| l.split_once(':').map(|x| x.1.trim().to_string()))
            .unwrap_or_else(|| "none".into());
        let want_file = format!("{NET}/05-goatrope-{p}.network");
        item(&mut items, format!("network-file:{p}"), Some(nfile == want_file), want_file, nfile);
        for (short, (val, fixed)) in su::features(p) {
            let have = format!("{val}{}", if fixed && val == "on" { " (fixed by the driver)" } else { "" });
            item(&mut items, format!("offload:{p}:{short}"), Some(val == "off" || fixed), "off", have);
        }
        let e = su::eee(p);
        item(&mut items, format!("eee:{p}"), Some(e != "enabled"), "off", e);
        if let Some(speed) = tap.speed_mbps {
            let ls = su::link_settings(p);
            let ok = ls.autoneg.as_deref() == Some("off") && (ls.speed.is_none() || ls.speed == Some(speed));
            let sp = ls.speed.map(|x| x.to_string()).unwrap_or_else(|| "None".into());
            item(
                &mut items,
                format!("speed:{p}"),
                Some(ok),
                format!("{speed} Mb/s full, autonegotiation off"),
                format!(
                    "{sp} Mb/s {}, autonegotiation {}",
                    ls.duplex.unwrap_or_else(|| "None".into()),
                    ls.autoneg.unwrap_or_else(|| "None".into())
                ),
            );
        }
        let up = su::is_up(p);
        item(&mut items, format!("up:{p}"), Some(up), "up", if up { "up" } else { "down" });
        let m = su::master(p);
        if tap.mode == "listen" {
            item(&mut items, format!("no-bridge:{p}"), Some(m.is_none()), "in no bridge", m.unwrap_or_else(|| "in no bridge".into()));
            let drop = su::egress_drop_state(p);
            item(
                &mut items,
                format!("egress-drop:{p}"),
                Some(drop.is_ok()),
                "every outgoing frame dropped (the first egress filter is a matchall drop)",
                match drop {
                    Ok(()) => "present".to_string(),
                    Err(e) => e,
                },
            );
            let na = su::is_noarp(p);
            item(&mut items, format!("noarp:{p}"), Some(na), "ARP off", if na { "ARP off" } else { "ARP on" });
        } else {
            item(&mut items, format!("bridge-member:{p}"), Some(m.as_deref() == Some(BRIDGE)), BRIDGE, m.unwrap_or_else(|| "none".into()));
        }
    }

    if let Some(e) = &tap.erspan {
        let p = &tap.ports[0];
        let k = su::kind(p);
        item(
            &mut items,
            format!("erspan:{p}"),
            Some(k.as_deref() == Some("erspan")),
            "an erspan interface",
            k.unwrap_or_else(|| "absent".into()),
        );
        let held = su::addresses(&e.underlay).iter().any(|a| a.split('/').next() == Some(e.local.as_str()));
        item(
            &mut items,
            format!("erspan-underlay:{}", e.underlay),
            Some(held),
            format!("holds {}", e.local),
            if held { format!("holds {}", e.local) } else { format!("does not hold {}", e.local) },
        );
    }
    if su::nm_active() {
        let st = su::nm_states();
        for p in &tap.ports {
            let state = st.get(p).cloned();
            item(
                &mut items,
                format!("networkmanager-unmanaged:{p}"),
                Some(state.as_deref().unwrap_or("unmanaged") == "unmanaged"),
                "unmanaged",
                state.unwrap_or_else(|| "absent".into()),
            );
        }
    }
    for p in &tap.ports {
        let stacked: Vec<String> = su::uppers(p).into_iter().filter(|u| u != BRIDGE).collect();
        item(
            &mut items,
            format!("nothing-stacked:{p}"),
            Some(stacked.is_empty()),
            "no VLAN or other device on top",
            if stacked.is_empty() { "none".into() } else { stacked.join(", ") },
        );
    }

    if tap.mode == "inline" {
        let b = format!("{SYS_NET}/{BRIDGE}/bridge");
        if !su::exists(BRIDGE) {
            item(&mut items, format!("bridge:{BRIDGE}"), Some(false), "exists", "absent");
        } else {
            let mut members: Vec<String> = fs::read_dir(format!("{SYS_NET}/{BRIDGE}/brif"))
                .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
                .unwrap_or_default();
            members.sort();
            let mut want = tap.ports.clone();
            want.sort();
            item(&mut items, "bridge-members", Some(members == want), json!(want), json!(members));
            let stp = su::read(&format!("{b}/stp_state"));
            item(&mut items, "bridge-stp", Some(stp.as_deref() == Some("0")), "0 (off)", opt_str(stp));
            let fd = su::read(&format!("{b}/forward_delay"));
            item(&mut items, "bridge-forward-delay", Some(fd.as_deref() == Some("0")), "0", opt_str(fd));
            for p in &members {
                let st = su::read(&format!("{SYS_NET}/{BRIDGE}/brif/{p}/state"));
                item(&mut items, format!("bridge-port-forwarding:{p}"), Some(st.as_deref() == Some("3")), "3 (forwarding)", opt_str(st));
            }
            let mask_s = read_or(&format!("{b}/group_fwd_mask"), "0");
            let mask =
                if let Some(h) = mask_s.strip_prefix("0x") { u32::from_str_radix(h, 16).unwrap_or(0) } else { mask_s.parse().unwrap_or(0) };
            item(
                &mut items,
                "bridge-lldp-forwarded",
                Some(mask & LLDP_MASK != 0),
                format!("bit 14 set ({LLDP_MASK:#x})"),
                format!("{mask:#x}"),
            );
            let addrs = su::addresses(BRIDGE);
            item(
                &mut items,
                "bridge-address",
                Some(addrs.is_empty()),
                "none",
                if addrs.is_empty() { "none".into() } else { addrs.join(", ") },
            );
            let v6 = su::read(&format!("/proc/sys/net/ipv6/conf/{BRIDGE}/disable_ipv6"));
            item(&mut items, "bridge-ipv6-disabled", Some(v6.as_deref() == Some("1")), "1", opt_str(v6));
            let up = su::is_up(BRIDGE);
            item(&mut items, "bridge-up", Some(up), "up", if up { "up" } else { "down" });
        }
        for key in ["iptables", "ip6tables", "arptables"] {
            if let Some(v) = su::read(&format!("/proc/sys/net/bridge/bridge-nf-call-{key}")) {
                item(&mut items, format!("bridge-nf-call-{key}"), Some(v == "0"), "0", v);
            }
        }
    }

    let r = &tap.record;
    for p in &r.ports {
        item(&mut items, format!("record-port:{p}"), Some(tap.ports.contains(p) && p != BRIDGE), "a tap port, not the bridge", p.clone());
    }
    if Path::new(&r.directory).is_dir() {
        let names: Vec<String> = fs::read_dir(&r.directory)
            .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
            .unwrap_or_default();
        for p in &r.ports {
            let count = names.iter().filter(|f| f.starts_with(&format!("{p}.pcap"))).count() as i64;
            item(
                &mut items,
                format!("ring:{p}"),
                Some(count <= r.files),
                format!("at most {} files of {} MB", r.files, r.file_mb),
                format!("{count} files"),
            );
        }
    } else {
        item(&mut items, "ring-directory", Some(false), r.directory.clone(), "absent");
    }

    let rt = su::systemctl(&["show", "-p", "RuntimeWatchdogUSec", "--value"]).stdout.trim().to_string();
    let ok = rt == format!("{WATCHDOG_SEC}s") || rt == (WATCHDOG_SEC * 1_000_000).to_string();
    item(&mut items, "watchdog-runtime", Some(ok), format!("{WATCHDOG_SEC}s"), if rt.is_empty() { "unknown".into() } else { rt });
    match std::env::var("GOATROPE_TEST_WATCHDOG_DEVICE").ok().filter(|s| !s.is_empty()) {
        Some(dev) => {
            item(
                &mut items,
                "watchdog-device",
                Some(Path::new(&dev).exists()),
                "a watchdog device",
                format!("test stand-in {dev}, the hardware was not checked"),
            );
        }
        None => {
            let mut devs: Vec<String> = fs::read_dir("/dev")
                .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.starts_with("watchdog")).collect())
                .unwrap_or_default();
            devs.sort();
            item(
                &mut items,
                "watchdog-device",
                Some(!devs.is_empty()),
                "a watchdog device",
                if devs.is_empty() { "none".into() } else { devs.join(", ") },
            );
        }
    }
    if let (Some(relay), "listen") = (&cfg.relay, tap.mode.as_str()) {
        let clash: Vec<&String> = [&relay.link_interface, &relay.remote_interface].into_iter().filter(|n| tap.ports.contains(n)).collect();
        item(
            &mut items,
            "relay-not-on-listen-port",
            Some(clash.is_empty()),
            "no relay interface is a listen port",
            if clash.is_empty() { "none".into() } else { clash.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") },
        );
    }
    items
}

// ---------------------------------------------------------------- JSON as Python's json.dumps(indent=2) writes it

pub fn json_pretty(v: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent + 1);
    let end = "  ".repeat(indent);
    match v {
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Array(a) => {
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                out.push_str(&pad);
                json_pretty(x, indent + 1, out);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&end);
            out.push(']');
        }
        Value::String(s) => out.push_str(&send::json_str(s)),
        other => out.push_str(&other.to_string()),
    }
}

/// An object whose keys keep the order given, as a Python dict does.
pub fn json_object(fields: &[(&str, String)], indent: usize) -> String {
    let pad = "  ".repeat(indent + 1);
    let end = "  ".repeat(indent);
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("{pad}{}: {v}", send::json_str(k))).collect();
    format!("{{\n{}\n{end}}}", body.join(",\n"))
}

pub fn check_json(cfg: &Config, items: &[Item], bad: bool) -> String {
    let rendered: Vec<String> = items
        .iter()
        .map(|i| {
            let ok = match i.ok {
                Some(true) => "true".to_string(),
                Some(false) => "false".to_string(),
                None => "null".to_string(),
            };
            let mut w = String::new();
            json_pretty(&i.want, 3, &mut w);
            let mut h = String::new();
            json_pretty(&i.have, 3, &mut h);
            json_object(&[("id", send::json_str(&i.id)), ("ok", ok), ("want", w), ("have", h)], 2)
        })
        .collect();
    let items_s = if rendered.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{}\n  ]", rendered.iter().map(|r| format!("    {r}")).collect::<Vec<_>>().join(",\n"))
    };
    json_object(
        &[
            ("goatrope", send::json_str(&crate::version())),
            ("config", send::json_str(&cfg.path)),
            ("mode", send::json_str(cfg.tap.as_ref().map(|t| t.mode.as_str()).unwrap_or("relay"))),
            ("result", send::json_str(if bad { "differs" } else { "match" })),
            ("items", items_s),
        ],
        0,
    )
}

// ---------------------------------------------------------------- status

pub fn status(cfg: &Config) -> i32 {
    println!("goatrope {}  config {}", crate::version(), cfg.path);
    if let Some(tap) = &cfg.tap {
        status_tap(tap);
    }
    if let Some(r) = &cfg.relay {
        println!("{}", crate::relay::banner(r));
        crate::relay::status(cfg);
        crate::l2::status(cfg);
    }
    send::status(cfg);
    let items = check(cfg);
    let bad = items.iter().filter(|i| i.ok == Some(false)).count();
    if bad == 0 {
        println!("  check  match");
    } else {
        println!("  check  differs in {bad} of {} items (goatrope check)", items.len());
    }
    0
}

fn status_tap(tap: &Tap) {
    println!("{}", banner(tap));
    for p in &tap.ports {
        if !su::exists(p) {
            println!("  port {p:<16} absent");
            continue;
        }
        let carrier = read_or(&format!("{SYS_NET}/{p}/carrier"), "?");
        let speed = read_or(&format!("{SYS_NET}/{p}/speed"), "?");
        let drop =
            if tap.mode == "listen" { format!("  egress-drop={}", if su::egress_drop(p) { "yes" } else { "NO" }) } else { String::new() };
        println!("  port {p:<16} carrier={carrier} speed={speed} Mb/s  addresses={}{drop}", su::addresses(p).len());
    }
    if let Some(e) = &tap.erspan {
        println!(
            "  erspan {:<14} session {} (type {}) from {} to {} on {}",
            tap.ports[0],
            e.gre_key,
            if e.version == 1 { "II" } else { "III" },
            e.remote,
            e.local,
            e.underlay
        );
    }
    if tap.mode == "inline" {
        if su::exists(BRIDGE) {
            let mut members: Vec<String> = fs::read_dir(format!("{SYS_NET}/{BRIDGE}/brif"))
                .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
                .unwrap_or_default();
            members.sort();
            println!(
                "  bridge {BRIDGE} {}  members={}  stp={}",
                read_or(&format!("{SYS_NET}/{BRIDGE}/operstate"), "None"),
                members.join(" "),
                read_or(&format!("{SYS_NET}/{BRIDGE}/bridge/stp_state"), "None")
            );
        } else {
            println!("  bridge {BRIDGE} absent");
        }
    }
    let r = &tap.record;
    for p in &r.ports {
        let mut files: Vec<std::path::PathBuf> = if Path::new(&r.directory).is_dir() {
            fs::read_dir(&r.directory)
                .map(|rd| {
                    rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{p}.pcap"))).map(|e| e.path()).collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        files.sort();
        let size: u64 = files.iter().filter_map(|f| fs::metadata(f).ok()).map(|m| m.len()).sum();
        let filter = if r.filter.is_empty() { "(every frame)".to_string() } else { r.filter.clone() };
        println!(
            "  record {p:<14} {:<9} {} of {} files, {:.1} MB, filter {}",
            su::unit_active(&format!("goatrope-record@{p}.service")),
            files.len(),
            r.files,
            size as f64 / 1e6,
            pystr(&filter)
        );
    }
}
