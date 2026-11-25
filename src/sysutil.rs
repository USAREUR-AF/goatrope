// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Reading and changing the machine: files, sysfs, ethtool, tc, systemd, NetworkManager.
//! Links, addresses and routes are read through netlink (link.rs).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::link::{self, SYS_NET};

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command and collect its output; a missing program is exit 127, as a shell reports it.
pub fn run(cmd: &[&str]) -> Out {
    run_timeout(cmd, Duration::from_secs(30))
}

pub fn run_timeout(cmd: &[&str], timeout: Duration) -> Out {
    let child = Command::new(cmd[0]).args(&cmd[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return Out { code: 127, stdout: String::new(), stderr: format!("{}: not found", cmd[0]) },
    };
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut so, &mut s);
        s
    });
    let he = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut se, &mut s);
        s
    });
    let end = Instant::now() + timeout;
    let code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().unwrap_or(1),
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break 124;
            }
        }
    };
    Out { code, stdout: ho.join().unwrap_or_default(), stderr: he.join().unwrap_or_default() }
}

pub fn have(tool: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into())
        .split(':')
        .any(|d| fs::metadata(Path::new(d).join(tool)).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false))
}

/// A file's text, stripped, or None when it cannot be read.
pub fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Replace path atomically and durably: a power cut leaves the old file or the new one, never half.
pub fn write_file(path: &str, content: &str, mode: u32) -> std::io::Result<()> {
    let p = Path::new(path);
    let d = p.parent().unwrap_or(Path::new("/"));
    let tmp = d.join(format!(".{}.goatrope-new", p.file_name().unwrap_or_default().to_string_lossy()));
    let res = (|| {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp); // a full disk: the old file stays, and no half-written one is left beside it
        return Err(e);
    }
    fs::rename(&tmp, p)?;
    fsync_dir(d);
    Ok(())
}

pub fn fsync_dir(d: &Path) {
    if let Ok(f) = fs::File::open(d) {
        let _ = f.sync_all();
    }
}

/// Write a value to a sysfs or procfs file; false when it cannot be written.
pub fn write(path: &str, value: &str) -> bool {
    fs::write(path, value).is_ok()
}

pub fn exists(ifname: &str) -> bool {
    Path::new(&format!("{SYS_NET}/{ifname}")).exists()
}

/// Devices stacked on ifname (VLAN, macvlan, ipvlan, a bridge or bond it belongs to).
pub fn uppers(ifname: &str) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(format!("{SYS_NET}/{ifname}"))
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_string_lossy().strip_prefix("upper_").map(String::from)).collect())
        .unwrap_or_default();
    out.sort();
    out
}

pub fn master(ifname: &str) -> Option<String> {
    let p = format!("{SYS_NET}/{ifname}/master");
    fs::read_link(&p).ok().and_then(|t| t.file_name().map(|n| n.to_string_lossy().to_string()))
}

const IFF_UP: u32 = 0x1;
const IFF_NOARP: u32 = 0x80;

fn ifflags(ifname: &str) -> u32 {
    read(&format!("{SYS_NET}/{ifname}/flags")).and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0)
}

pub fn is_up(ifname: &str) -> bool {
    exists(ifname) && ifflags(ifname) & IFF_UP != 0
}

pub fn is_noarp(ifname: &str) -> bool {
    ifflags(ifname) & IFF_NOARP != 0
}

pub fn kind(ifname: &str) -> Option<String> {
    link::kind(ifname)
}

pub fn addresses(ifname: &str) -> Vec<String> {
    link::addresses(ifname)
}

/// "[fe80::1%tp0]:22" or "192.0.2.1:22" or "fe80::1%tp0" -> (address, scope interface or None).
pub fn split_scope(hostport: &str) -> (String, Option<String>) {
    let mut h = hostport.to_string();
    if h.starts_with('[') && h.contains(']') {
        let i = h.find(']').unwrap();
        let mut inside = h[1..i].to_string();
        let rest = &h[i + 1..];
        if let Some(r) = rest.strip_prefix('%') {
            // ss prints the scope after the bracket: [fe80::1]%tp0:22
            inside.push('%');
            inside.push_str(r.rsplit_once(':').map(|x| x.0).unwrap_or(r));
        }
        h = inside;
    } else if h.matches(':').count() == 1 {
        h = h.rsplit_once(':').unwrap().0.to_string();
    }
    match h.split_once('%') {
        Some((a, s)) if !s.is_empty() => (a.to_string(), Some(s.to_string())),
        Some((a, _)) => (a.to_string(), None),
        None => (h, None),
    }
}

/// (peer, devices beneath it) for every established TCP connection, an SSH session among them.
pub fn established() -> Vec<(String, BTreeSet<String>)> {
    let p = run(&["ss", "-Htn", "state", "established"]);
    let mut out = Vec::new();
    for line in p.stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let (local, peer) = (cols[cols.len() - 2], cols[cols.len() - 1]);
        let (_, lscope) = split_scope(local);
        let (paddr, pscope) = split_scope(peer);
        let mut devs = link::peer_devices(&paddr, pscope.as_deref().or(lscope.as_deref()));
        devs.remove("lo");
        if let Some(l) = &lscope {
            devs.extend(link::lowers(l));
        }
        if !devs.is_empty() {
            out.push((paddr, devs));
        }
    }
    out
}

/// The operator's SSH session: (peer, devices beneath it).
pub fn session() -> Option<(String, BTreeSet<String>)> {
    let s = std::env::var("SSH_CONNECTION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("GOATROPE_SSH_CONNECTION").ok().filter(|s| !s.is_empty()))?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    let (paddr, pscope) = split_scope(parts.first().copied().unwrap_or(""));
    let lscope = if parts.len() > 2 { split_scope(parts[2]).1 } else { None };
    let devs = link::peer_devices(&paddr, pscope.as_deref().or(lscope.as_deref()));
    Some((paddr, devs))
}

pub fn nm_active() -> bool {
    unit_active("NetworkManager.service") == "active" && have("nmcli")
}

/// {device: state} as NetworkManager sees them.
pub fn nm_states() -> BTreeMap<String, String> {
    let p = run(&["nmcli", "-t", "-f", "DEVICE,STATE", "device"]);
    let mut out = BTreeMap::new();
    for line in p.stdout.lines() {
        if let Some((dev, state)) = line.rsplit_once(':') {
            if !dev.is_empty() {
                out.insert(dev.replace("\\:", ":"), state.to_string());
            }
        }
    }
    out
}

/// Which IP families forward packets arriving on ifname.
#[allow(dead_code)] // the relay uses it once it is ported (ADR 0003 step 3)
pub fn forwarding(ifname: &str) -> Vec<String> {
    ["ipv4", "ipv6"]
        .iter()
        .filter(|f| read(&format!("/proc/sys/net/{f}/conf/{ifname}/forwarding")).as_deref() == Some("1"))
        .map(|f| f.to_string())
        .collect()
}

pub const OFFLOADS: [(&str, &str); 4] = [
    ("gro", "generic-receive-offload"),
    ("lro", "large-receive-offload"),
    ("tso", "tcp-segmentation-offload"),
    ("gso", "generic-segmentation-offload"),
];

/// {short: (on|off, fixed)} for the offloads goatrope turns off.
pub fn features(ifname: &str) -> BTreeMap<String, (String, bool)> {
    let p = run(&["ethtool", "-k", ifname]);
    let mut found: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for line in p.stdout.lines() {
        let t = line.trim_start();
        let Some((name, rest)) = t.split_once(':') else { continue };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            continue;
        }
        let rest = rest.trim_start();
        let val = if rest.starts_with("on") {
            "on"
        } else if rest.starts_with("off") {
            "off"
        } else {
            continue;
        };
        let after = &rest[val.len()..];
        if !after.is_empty() && !after.starts_with(char::is_whitespace) {
            continue;
        }
        let fixed = after.trim_start().starts_with("[fixed]");
        found.insert(name.to_string(), (val.to_string(), fixed));
    }
    OFFLOADS.iter().filter_map(|(k, v)| found.get(*v).map(|x| (k.to_string(), x.clone()))).collect()
}

/// enabled, disabled or unsupported.
pub fn eee(ifname: &str) -> String {
    let p = run(&["ethtool", "--show-eee", ifname]);
    if p.code != 0 {
        return "unsupported".into();
    }
    let text = p.stdout.to_lowercase();
    if text.contains("not supported") {
        return "unsupported".into();
    }
    let Some(i) = text.find("eee status:") else { return "unsupported".into() };
    let word: String = text[i + 11..].trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if word.is_empty() {
        return "unsupported".into();
    }
    if word == "disabled" || word == "not" { "disabled" } else { "enabled" }.into()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LinkSettings {
    pub speed: Option<i64>,
    pub duplex: Option<String>,
    pub autoneg: Option<String>,
}

pub fn link_settings(ifname: &str) -> LinkSettings {
    let p = run(&["ethtool", ifname]);
    let mut out = LinkSettings::default();
    for line in p.stdout.lines() {
        let line = line.trim();
        if let Some(r) = line.strip_prefix("Speed:") {
            let digits: String = r.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
            out.speed = digits.parse().ok();
        } else if let Some(r) = line.strip_prefix("Duplex:") {
            out.duplex = Some(r.trim().to_lowercase());
        } else if let Some(r) = line.strip_prefix("Auto-negotiation:") {
            out.autoneg = Some(r.trim().to_lowercase());
        }
    }
    out
}

pub fn egress_drop(ifname: &str) -> bool {
    let p = run(&["tc", "filter", "show", "dev", ifname, "egress"]);
    p.stdout.contains("matchall") && p.stdout.contains("gact action drop")
}

pub fn systemctl(args: &[&str]) -> Out {
    let mut cmd = vec!["systemctl"];
    cmd.extend_from_slice(args);
    run_timeout(&cmd, Duration::from_secs(120))
}

fn or_unknown(s: String) -> String {
    let s = s.trim().to_string();
    if s.is_empty() {
        "unknown".into()
    } else {
        s
    }
}

pub fn unit_active(unit: &str) -> String {
    or_unknown(systemctl(&["is-active", unit]).stdout)
}

pub fn unit_enabled(unit: &str) -> String {
    or_unknown(systemctl(&["is-enabled", unit]).stdout)
}

/// (bytes available to an ordinary user, total bytes) of the filesystem holding path.
pub fn statvfs(path: &str) -> Option<(f64, f64)> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: zeroed statvfs is a valid buffer for the call to fill.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated; st is a valid statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let fr = st.f_frsize as f64;
    Some((st.f_bavail as f64 * fr, st.f_blocks as f64 * fr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        assert_eq!(split_scope("192.0.2.1:22"), ("192.0.2.1".into(), None));
        assert_eq!(split_scope("[fe80::1%tp0]:22"), ("fe80::1".into(), Some("tp0".into())));
        assert_eq!(split_scope("[fe80::1]%tp0:22"), ("fe80::1".into(), Some("tp0".into())));
        assert_eq!(split_scope("[2001:db8::1]:22"), ("2001:db8::1".into(), None));
    }
}
