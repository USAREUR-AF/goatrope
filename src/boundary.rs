// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The relay's boundary transport (docs/adr/0002, Transport).
//!
//! For a site that must be treated as outside the deployment, the relay reaches the
//! remote side through a WireGuard interface of its own with exactly one peer: the
//! declared boundary point. The peer's key, endpoint and single tunnel address are
//! fixed by the declaration, and the interface is checked against it before the relay
//! starts and every two seconds while it runs.
//!
//! The interface may be made by goatrope (`goatrope boundary up`, or the relay when it
//! is absent) or by other tooling; either way it must match the declaration exactly.
//! goatrope never prints a private key's value or hands it to another program: the
//! public key is derived in process and compared with the one the interface uses.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

use crate::config::Boundary;
use crate::nl;

pub struct BoundaryRefusal(pub String);

fn host_len(addr: &str) -> u8 {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => 128,
        _ => 32,
    }
}

// ---------------------------------------------------------------- keys

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A 32-byte key as WireGuard writes it: standard base64, 44 characters.
pub fn b64_key(k: &[u8; 32]) -> String {
    let mut out = String::with_capacity(44);
    for chunk in k.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A key in WireGuard's base64 form (44 characters ending in '='), as `wg` accepts it.
pub fn key_from_b64(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' {
        return None;
    }
    let val = |c: u8| B64.iter().position(|x| *x == c).map(|p| p as u32);
    let mut out = [0u8; 32];
    let mut o = 0;
    for chunk in b.chunks(4) {
        let pad = chunk.iter().filter(|c| **c == b'=').count();
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if *c == b'=' { 0 } else { val(*c)? };
            n |= v << (18 - 6 * i);
        }
        for i in 0..(3 - pad) {
            out[o] = (n >> (16 - 8 * i)) as u8;
            o += 1;
        }
    }
    (o == 32).then_some(out)
}

/// The public key for a private key: X25519 of the clamped scalar with the base point.
pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// The key in a key file. `wg` reads 44 characters and allows only whitespace after them.
fn read_key(path: &str) -> Option<[u8; 32]> {
    let text = std::fs::read_to_string(path).ok()?;
    key_from_b64(text.trim_end())
}

fn pubkey(private_key_file: &str) -> Option<String> {
    let mut k = read_key(private_key_file)?;
    let p = public_from_private(&k);
    k.fill(0);
    Some(b64_key(&p))
}

fn file_problem(path: &str, what: &str) -> Option<String> {
    let Ok(st) = std::fs::metadata(path) else {
        return Some(format!(
            "{what} {path} does not exist (make it with `goatrope boundary key`)"
        ));
    };
    if !st.file_type().is_file() {
        return Some(format!("{what} {path} is not a regular file"));
    }
    if st.uid() != 0 || st.mode() & 0o077 != 0 {
        return Some(format!(
            "{what} {path} must be owned by root and readable by root only (mode 600)"
        ));
    }
    None
}

fn file_problems(b: &Boundary) -> Vec<String> {
    let mut out: Vec<String> = file_problem(&b.private_key_file, "private key file")
        .into_iter()
        .collect();
    if !b.preshared_key_file.is_empty() {
        out.extend(file_problem(&b.preshared_key_file, "preshared key file"));
    }
    out
}

// ---------------------------------------------------------------- how `wg show <if> dump` prints a value

/// "ip:port" or "[ip6]:port"; "(none)" when the peer has no endpoint.
pub fn fmt_endpoint(e: Option<SocketAddr>) -> String {
    match e {
        None => "(none)".to_string(),
        Some(SocketAddr::V4(a)) => format!("{}:{}", a.ip(), a.port()),
        Some(SocketAddr::V6(a)) => {
            let scope = if a.scope_id() != 0 {
                format!(
                    "%{}",
                    crate::link::ifname_of(a.scope_id())
                        .unwrap_or_else(|| a.scope_id().to_string())
                )
            } else {
                String::new()
            };
            format!("[{}{scope}]:{}", a.ip(), a.port())
        }
    }
}

/// "addr/len,addr/len"; "(none)" when there is none.
pub fn fmt_allowed(ips: &[(IpAddr, u8)]) -> String {
    if ips.is_empty() {
        return "(none)".to_string();
    }
    ips.iter()
        .map(|(a, l)| format!("{a}/{l}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The keepalive interval; 0 is "off".
pub fn fmt_keepalive(k: u16) -> String {
    if k == 0 {
        "off".to_string()
    } else {
        k.to_string()
    }
}

// ---------------------------------------------------------------- check, up, down, key, sheet

/// Every way the interface differs from the declaration; empty when it matches.
pub fn check(b: &Boundary, ifname: &str) -> Vec<String> {
    let mut problems = file_problems(b);
    if !problems.is_empty() {
        return problems;
    }
    if !crate::sys::exists(ifname) {
        return vec![format!("no interface {ifname}")];
    }
    if nl::kind(ifname).as_deref() != Some("wireguard") {
        return vec![format!("{ifname} is not a WireGuard interface")];
    }
    let dev = match nl::wg_get(ifname) {
        Ok(d) => d,
        Err(e) => {
            return vec![format!(
                "wg show {ifname} failed: {}",
                crate::sys::strerror(&e)
            )]
        }
    };
    if dev.listen_port != b.listen_port {
        problems.push(format!(
            "{ifname} listens on {}, not the declared {}",
            dev.listen_port, b.listen_port
        ));
    }
    match pubkey(&b.private_key_file) {
        None => problems.push(format!(
            "cannot derive a public key from {}",
            b.private_key_file
        )),
        Some(want) if dev.public_key.map(|k| b64_key(&k)).as_ref() != Some(&want) => problems.push(
            format!("{ifname} does not use the key in {}", b.private_key_file),
        ),
        Some(_) => {}
    }
    if dev.peers.len() != 1 {
        problems.push(format!(
            "{ifname} has {} peers; a boundary interface has exactly one, the boundary point",
            dev.peers.len()
        ));
    }
    if let Some(p) = dev.peers.first() {
        let pubk = b64_key(&p.public_key);
        if pubk != b.peer_public_key {
            problems.push(format!(
                "{ifname}'s peer is not the declared boundary point (key {}...)",
                &pubk[..8]
            ));
        }
        if !b.preshared_key_file.is_empty() {
            let same = match (p.preshared_key, read_key(&b.preshared_key_file)) {
                (Some(have), Some(mut want)) => {
                    let eq = have == want;
                    want.fill(0);
                    eq
                }
                _ => false,
            };
            if !same {
                problems.push(format!(
                    "{ifname}'s peer does not use the preshared key in {}",
                    b.preshared_key_file
                ));
            }
        } else if p.preshared_key.is_some() {
            problems.push(format!(
                "{ifname}'s peer has a preshared key the declaration does not name"
            ));
        }
        let endpoint = fmt_endpoint(p.endpoint);
        if endpoint != b.peer_endpoint {
            problems.push(format!(
                "{ifname}'s peer endpoint is {endpoint}, not the declared {}",
                b.peer_endpoint
            ));
        }
        let allowed = fmt_allowed(&p.allowed_ips);
        let want_allowed = format!("{}/{}", b.peer_address, host_len(&b.peer_address));
        if allowed != want_allowed {
            problems.push(format!(
                "{ifname}'s peer may send from {allowed}; a boundary interface allows only {want_allowed}"
            ));
        }
        let ka = fmt_keepalive(p.keepalive);
        let want_ka = fmt_keepalive(b.keepalive_s);
        if ka != want_ka {
            problems.push(format!(
                "{ifname}'s peer keepalive is {ka}, not the declared {want_ka}"
            ));
        }
    }
    if !nl::addresses(ifname).contains(&b.address) {
        problems.push(format!("{ifname} does not hold {}", b.address));
    }
    problems
}

fn err(step: &str, e: &std::io::Error) -> BoundaryRefusal {
    BoundaryRefusal(format!("{step} failed: {}", crate::sys::strerror(e)))
}

/// The four steps that make the interface: `ip link add`, `wg set`, `ip address add`, `ip link set up`.
fn make(b: &Boundary, ifname: &str, made: &mut bool) -> Result<(), BoundaryRefusal> {
    nl::add_wireguard(ifname).map_err(|e| err("ip link add", &e))?;
    *made = true;
    let wg_step = format!("wg set {ifname}");
    let bad_key = || {
        BoundaryRefusal(format!(
            "{wg_step} failed: Key is not the correct length or format"
        ))
    };
    let private_key = read_key(&b.private_key_file).ok_or_else(bad_key)?;
    let preshared_key = if b.preshared_key_file.is_empty() {
        None
    } else {
        Some(read_key(&b.preshared_key_file).ok_or_else(bad_key)?)
    };
    let peer_ip: IpAddr = b.peer_address.parse().map_err(|_| bad_key())?;
    let set = nl::WgSet {
        private_key,
        listen_port: b.listen_port,
        peer_public_key: key_from_b64(&b.peer_public_key).ok_or_else(bad_key)?,
        endpoint: b.peer_endpoint.parse().map_err(|_| {
            BoundaryRefusal(format!(
                "{wg_step} failed: bad endpoint {}",
                b.peer_endpoint
            ))
        })?,
        allowed: (peer_ip, host_len(&b.peer_address)),
        preshared_key,
        keepalive: b.keepalive_s,
    };
    nl::wg_set(ifname, &set).map_err(|e| err(&wg_step, &e))?;
    drop(set);
    // goatrope's own interface: it never routes, and carries no IPv6 unless declared
    crate::sys::write(&format!("/proc/sys/net/ipv4/conf/{ifname}/forwarding"), "0");
    crate::sys::write(&format!("/proc/sys/net/ipv6/conf/{ifname}/forwarding"), "0");
    if !b.address.contains(':') {
        crate::sys::write(
            &format!("/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6"),
            "1",
        );
    }
    let (ip, prefix) = b.address.split_once('/').unwrap_or((&b.address, ""));
    let ip: IpAddr = ip.parse().map_err(|_| {
        BoundaryRefusal(format!("ip address add failed: bad address {}", b.address))
    })?;
    let prefix: u8 = prefix.parse().unwrap_or(host_len(&b.address));
    nl::add_address(ifname, ip, prefix).map_err(|e| err("ip address add", &e))?;
    nl::set_up(ifname).map_err(|e| err("ip link set", &e))?;
    Ok(())
}

/// Make the interface when it is absent; then require it to match. Returns true when it was made here.
pub fn up(b: &Boundary, ifname: &str) -> Result<bool, BoundaryRefusal> {
    let mut made = false;
    if !crate::sys::exists(ifname) {
        let bad = file_problems(b);
        if !bad.is_empty() {
            return Err(BoundaryRefusal(bad.join("; ")));
        }
        if let Err(e) = make(b, ifname, &mut made) {
            if made {
                // the interface exists from the first step: take it away again
                let _ = nl::delete_link(ifname);
            }
            return Err(e);
        }
    }
    let problems = check(b, ifname);
    if !problems.is_empty() {
        if made {
            let _ = nl::delete_link(ifname);
        }
        return Err(BoundaryRefusal(format!(
            "{ifname} does not match the declaration: {}",
            problems.join("; ")
        )));
    }
    Ok(made)
}

pub enum DownError {
    Refusal(BoundaryRefusal),
    Failed(String),
}

pub fn down(ifname: &str) -> Result<bool, DownError> {
    if !crate::sys::exists(ifname) {
        return Ok(false);
    }
    if nl::kind(ifname).as_deref() != Some("wireguard") {
        return Err(DownError::Refusal(BoundaryRefusal(format!(
            "{ifname} is not a WireGuard interface; goatrope removes only its boundary interface"
        ))));
    }
    nl::delete_link(ifname).map_err(|e| {
        DownError::Failed(format!(
            "ip link del {ifname} failed: {}",
            crate::sys::strerror(&e)
        ))
    })?;
    Ok(true)
}

/// Write a new private key, mode 600, refusing to replace one. Returns the public key.
pub fn make_key(path: &str) -> Result<Result<String, BoundaryRefusal>, String> {
    if std::path::Path::new(path).exists() {
        return Ok(Err(BoundaryRefusal(format!(
            "{path} already exists; goatrope never replaces a key (remove it yourself to rotate)"
        ))));
    }
    let mut k = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut k) {
        return Ok(Err(BoundaryRefusal(format!("wg genkey failed: {e}"))));
    }
    // clamped, as `wg genkey` writes it
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    let mut line = b64_key(&k);
    line.push('\n');
    let public = b64_key(&public_from_private(&k));
    k.fill(0);
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty());
    let dir = dir.unwrap_or(std::path::Path::new("."));
    if !dir.exists() {
        if let Some(up) = dir.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(up)
                .map_err(|e| crate::sys::oserror(&e, &up.to_string_lossy()))?;
        }
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(dir) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(crate::sys::oserror(&e, &dir.to_string_lossy()));
            }
        }
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| {
            f.write_all(line.as_bytes())?;
            f.sync_all()
        });
    // overwrite the copy of the key this process holds
    // SAFETY: zero bytes are valid UTF-8, so the string stays valid.
    unsafe { line.as_bytes_mut().fill(0) };
    written.map_err(|e| crate::sys::oserror(&e, path))?;
    Ok(Ok(public))
}

/// What the boundary point's operator needs; no private value.
pub fn sheet(b: &Boundary, ifname: &str) -> String {
    let public = pubkey(&b.private_key_file)
        .unwrap_or_else(|| "(no key yet: goatrope boundary key)".to_string());
    let mine = b.address.split('/').next().unwrap_or_default();
    let psk = if b.preshared_key_file.is_empty() {
        "none"
    } else {
        "yes, exchanged out of band"
    };
    format!(
        "public key      {public}\n\
         listen port     {} (UDP, on this machine's address facing the boundary point)\n\
         tunnel address  {mine} (the boundary point allows only {mine}/{} from this peer)\n\
         boundary point  {}, tunnel address {}, interface {ifname} here\n\
         preshared key   {psk}",
        b.listen_port,
        host_len(mine),
        b.peer_endpoint,
        b.peer_address
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_public_keys() {
        // RFC 7748 section 6.1: Alice's and Bob's private and public keys
        let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(public_from_private(&alice), alice_pub);
        assert_eq!(public_from_private(&bob), bob_pub);
    }

    #[test]
    fn base64_round_trip_and_known_value() {
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let s = b64_key(&alice_pub);
        assert_eq!(s, "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
        assert_eq!(key_from_b64(&s), Some(alice_pub));
        assert_eq!(
            b64_key(&[0u8; 32]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(key_from_b64("short="), None);
        assert_eq!(
            key_from_b64("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoA"),
            None
        );
        assert_eq!(
            key_from_b64("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066Spjqqb!mo="),
            None
        );
    }

    #[test]
    fn wg_show_formats() {
        assert_eq!(fmt_endpoint(None), "(none)");
        assert_eq!(
            fmt_endpoint(Some("203.0.113.7:51900".parse().unwrap())),
            "203.0.113.7:51900"
        );
        assert_eq!(
            fmt_endpoint(Some("[2001:db8::7]:51900".parse().unwrap())),
            "[2001:db8::7]:51900"
        );
        assert_eq!(fmt_allowed(&[]), "(none)");
        assert_eq!(
            fmt_allowed(&[("10.200.0.1".parse().unwrap(), 32)]),
            "10.200.0.1/32"
        );
        assert_eq!(
            fmt_allowed(&[
                ("10.200.0.0".parse().unwrap(), 30),
                ("2001:db8::1".parse().unwrap(), 128)
            ]),
            "10.200.0.0/30,2001:db8::1/128"
        );
        assert_eq!(fmt_keepalive(0), "off");
        assert_eq!(fmt_keepalive(25), "25");
        assert_eq!(host_len("10.200.0.1"), 32);
        assert_eq!(host_len("2001:db8::1"), 128);
    }
}
