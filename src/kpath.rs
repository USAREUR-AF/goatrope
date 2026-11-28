// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The relay's kernel path for UDP (docs/adr/0006-data-path.md), opt-in: a tc program on the
//! WireGuard interface's ingress forwards the datagrams of `remote-to-link` and `both` rules to
//! the link without waking the relay.
//!
//! The program is written here as BPF instructions, so there is no object file, no compiler and
//! no loader library. A datagram it forwards is one the relay's socket would have forwarded for
//! the rule, and well formed: IPv4 with no options and a valid header checksum, not a fragment,
//! not a GSO or GRO aggregate, UDP whose length is the IP payload's, the packet's length the IP
//! total length, no longer than the link's MTU, from the rule's `remote`, to one of the WireGuard
//! interface's own IPv4 addresses, at the rule's `listen_port`. It is rewritten to what the
//! relay's own link socket sends (the relay's link address and that socket's port, to the rule's
//! target; TTL 64, TOS 0; checksums updated) and sent out of the link interface with
//! `bpf_redirect_neigh`. Everything else goes on to the relay's sockets (`TC_ACT_OK`), where the
//! rules apply as before.
//!
//! Two array maps: `rules` (per rule: the last remote address and port, datagrams redirected,
//! datagrams the program could not redirect), read by the relay for replies and relay.health;
//! `conf` (the link MTU and up to 8 local addresses), written by the relay every 2 s, so an
//! address added to or removed from the WireGuard interface is followed without reloading.
//!
//! The kernel path bypasses netfilter: tc ingress runs before PREROUTING and INPUT, and the
//! redirect skips OUTPUT and POSTROUTING. `netfilter_applies` finds rules that would have seen the
//! datagrams; the relay refuses the kernel path then unless the declaration accepts the bypass by
//! name.
//!
//! The filter is found and removed by its program name at `PRIO` on any interface, with no
//! declaration needed (`goatrope relay-kernel-off`, the unit's ExecStopPost; `uninstall`); the
//! relay removes any it finds before it starts. `STATE` records what was attached, for `check`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::config::Relay;
use crate::nl;

/// The tc priority of the relay's filter on the WireGuard interface's ingress.
pub const PRIO: u16 = 3000;
/// The program's name; the filter is found by it.
pub const NAME: &str = "goatrope_relay";
/// What was attached: interface, program id, rules, mode.
pub const STATE: &str = "/var/lib/goatrope/relay-kernel.json";
/// Local addresses the program matches at most.
pub const MAX_LOCALS: usize = 8;

// ---------------------------------------------------------------- BPF instructions

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R5: u8 = 5;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;

const W: u8 = 0x00; // size bits
const H: u8 = 0x08;
const B: u8 = 0x10;

// helper ids (include/uapi/linux/bpf.h)
const MAP_LOOKUP_ELEM: i32 = 1;
const SKB_STORE_BYTES: i32 = 9;
const L3_CSUM_REPLACE: i32 = 10;
const L4_CSUM_REPLACE: i32 = 11;
const SKB_CHANGE_HEAD: i32 = 43;
const REDIRECT_NEIGH: i32 = 152;

const F_PSEUDO_HDR: i32 = 0x10;
const F_MARK_MANGLED_0: i32 = 0x20;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_REDIRECT: i32 = 7;

// __sk_buff
const SKB_LEN: i16 = 0;
const SKB_DATA: i16 = 76;
const SKB_DATA_END: i16 = 80;
const SKB_GSO_SEGS: i16 = 164;

fn raw(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    op as u64 | (((dst as u64) | ((src as u64) << 4)) << 8) | ((off as u16 as u64) << 16) | ((imm as u32 as u64) << 32)
}

/// A program under construction: instructions, labels and the jumps still to resolve.
#[derive(Default)]
struct Asm {
    ins: Vec<u64>,
    labels: HashMap<String, usize>,
    jumps: Vec<(usize, String)>,
}

impl Asm {
    fn push(&mut self, i: u64) {
        self.ins.push(i);
    }
    fn label(&mut self, l: &str) {
        self.labels.insert(l.to_string(), self.ins.len());
    }
    fn jump(&mut self, op: u8, dst: u8, src: u8, imm: i32, l: &str) {
        self.jumps.push((self.ins.len(), l.to_string()));
        self.push(raw(op, dst, src, 0, imm));
    }
    fn mov_imm(&mut self, d: u8, imm: i32) {
        self.push(raw(0xb7, d, 0, 0, imm));
    }
    fn mov(&mut self, d: u8, s: u8) {
        self.push(raw(0xbf, d, s, 0, 0));
    }
    fn add_imm(&mut self, d: u8, imm: i32) {
        self.push(raw(0x07, d, 0, 0, imm));
    }
    fn add(&mut self, d: u8, s: u8) {
        self.push(raw(0x0f, d, s, 0, 0));
    }
    fn and_imm(&mut self, d: u8, imm: i32) {
        self.push(raw(0x57, d, 0, 0, imm));
    }
    fn rsh_imm(&mut self, d: u8, imm: i32) {
        self.push(raw(0x77, d, 0, 0, imm));
    }
    /// d = (u16) d in network byte order, as a host integer
    fn be16(&mut self, d: u8) {
        self.push(raw(0xdc, d, 0, 0, 16));
    }
    fn ldx(&mut self, size: u8, d: u8, s: u8, off: i16) {
        self.push(raw(0x61 | size, d, s, off, 0));
    }
    fn stx(&mut self, size: u8, d: u8, s: u8, off: i16) {
        self.push(raw(0x63 | size, d, s, off, 0));
    }
    fn st(&mut self, size: u8, d: u8, off: i16, imm: i32) {
        self.push(raw(0x62 | size, d, 0, off, imm));
    }
    fn xadd64(&mut self, d: u8, s: u8, off: i16) {
        self.push(raw(0xdb, d, s, off, 0));
    }
    /// if (u32)d != imm goto l
    fn jne32(&mut self, d: u8, imm: i32, l: &str) {
        self.jump(0x56, d, 0, imm, l);
    }
    /// if (u32)d == imm goto l
    fn jeq32(&mut self, d: u8, imm: i32, l: &str) {
        self.jump(0x16, d, 0, imm, l);
    }
    /// if (u32)d > imm goto l (unsigned)
    fn jgt32(&mut self, d: u8, imm: i32, l: &str) {
        self.jump(0x26, d, 0, imm, l);
    }
    /// if (u32)d < imm goto l (unsigned)
    fn jlt32(&mut self, d: u8, imm: i32, l: &str) {
        self.jump(0xa6, d, 0, imm, l);
    }
    /// if (u32)d != (u32)s goto l
    fn jne32_reg(&mut self, d: u8, s: u8, l: &str) {
        self.jump(0x5e, d, s, 0, l);
    }
    /// if (u32)d == (u32)s goto l
    fn jeq32_reg(&mut self, d: u8, s: u8, l: &str) {
        self.jump(0x1e, d, s, 0, l);
    }
    /// if d > s goto l (unsigned, 64 bits)
    fn jgt(&mut self, d: u8, s: u8, l: &str) {
        self.jump(0x2d, d, s, 0, l);
    }
    /// if d == imm goto l (64 bits)
    fn jeq(&mut self, d: u8, imm: i32, l: &str) {
        self.jump(0x15, d, 0, imm, l);
    }
    fn ja(&mut self, l: &str) {
        self.jump(0x05, 0, 0, 0, l);
    }
    fn call(&mut self, id: i32) {
        self.push(raw(0x85, 0, 0, 0, id));
    }
    fn exit(&mut self) {
        self.push(raw(0x95, 0, 0, 0, 0));
    }
    fn ld_map(&mut self, d: u8, fd: i32) {
        self.push(raw(0x18, d, 1, 0, fd)); // BPF_PSEUDO_MAP_FD
        self.push(0);
    }
    fn finish(mut self) -> Result<Vec<u64>, String> {
        for (at, l) in std::mem::take(&mut self.jumps) {
            let to = *self.labels.get(&l).ok_or_else(|| format!("bpf: no label {l}"))?;
            let off = to as i64 - at as i64 - 1;
            let off = i16::try_from(off).map_err(|_| format!("bpf: jump to {l} out of range"))?;
            self.ins[at] = (self.ins[at] & !(0xffff << 16)) | ((off as u16 as u64) << 16);
        }
        Ok(self.ins)
    }
}

/// An address or port as the program loads it from the packet: network-order bytes read as a
/// native integer.
fn ip_word(a: Ipv4Addr) -> i32 {
    u32::from_ne_bytes(a.octets()) as i32
}
fn port_word(p: u16) -> i32 {
    u16::from_ne_bytes(p.to_be_bytes()) as i32
}
fn bytes_word(b: [u8; 2]) -> i32 {
    u16::from_ne_bytes(b) as i32
}

/// One rule as the program forwards it.
#[derive(Debug, Clone, PartialEq)]
pub struct KRule {
    pub remote: Ipv4Addr,
    pub listen_port: u16,
    pub link: Ipv4Addr,
    pub link_port: u16,
    pub target: Ipv4Addr,
    pub target_port: u16,
}

// stack slots
const S_SADDR: i16 = -4;
const S_DADDR: i16 = -8;
const S_SPORT: i16 = -10;
const S_DPORT: i16 = -12;
const S_WORD0: i16 = -14;
const S_WORD8: i16 = -16;
const S_TOTLEN: i16 = -18;
const S_KEY: i16 = -24;
const S_TMP: i16 = -28;
const S_ETH: i16 = -44;

/// The program. `rules_fd` and `conf_fd` are the two maps.
/// `redirect_flags` is 0; a test passes flags `bpf_redirect_neigh` refuses, to see a failure counted.
fn program(rules: &[KRule], link_ifindex: u32, rules_fd: i32, conf_fd: i32, redirect_flags: i32) -> Result<Vec<u64>, String> {
    let mut a = Asm::default();
    a.mov(R6, R1);
    a.ldx(W, R5, R6, SKB_GSO_SEGS);
    a.jgt32(R5, 1, "pass"); // a GSO or GRO aggregate: the socket path
    a.ldx(W, R2, R6, SKB_DATA);
    a.ldx(W, R3, R6, SKB_DATA_END);
    a.mov(R4, R2);
    a.add_imm(R4, 28); // an IPv4 header without options and a UDP header
    a.jgt(R4, R3, "pass");
    a.ldx(B, R5, R2, 0);
    a.jne32(R5, 0x45, "pass"); // IPv4, no options
    a.ldx(B, R5, R2, 9);
    a.jne32(R5, 17, "pass"); // UDP
    a.ldx(H, R5, R2, 6);
    a.and_imm(R5, bytes_word([0x3f, 0xff])); // more-fragments and fragment offset
    a.jne32(R5, 0, "pass"); // a fragment: the socket path reassembles it
                            // lengths: the packet is the IP total length, and UDP's length is the IP payload's
    a.ldx(H, R5, R2, 2);
    a.be16(R5);
    a.ldx(W, R4, R6, SKB_LEN);
    a.jne32_reg(R4, R5, "pass");
    a.stx(H, R10, R5, S_TOTLEN);
    a.ldx(H, R4, R2, 24);
    a.be16(R4);
    a.jlt32(R4, 8, "pass");
    a.mov(R0, R5);
    a.add_imm(R0, -20);
    a.jne32_reg(R0, R4, "pass");
    // the IP header checksum: the ones' complement sum of its ten halfwords is 0xffff
    a.mov_imm(R0, 0);
    for k in 0..10 {
        a.ldx(H, R4, R2, 2 * k);
        a.add(R0, R4);
    }
    for _ in 0..2 {
        a.mov(R4, R0);
        a.rsh_imm(R4, 16);
        a.and_imm(R0, 0xffff);
        a.add(R0, R4);
    }
    a.jne32(R0, 0xffff, "pass");
    a.ldx(W, R7, R2, 12); // saddr
    a.ldx(W, R8, R2, 16); // daddr
    a.ldx(H, R9, R2, 22); // dport
    a.stx(W, R10, R7, S_SADDR);
    a.stx(W, R10, R8, S_DADDR);
    a.ldx(H, R5, R2, 20);
    a.stx(H, R10, R5, S_SPORT);
    a.stx(H, R10, R9, S_DPORT);
    a.ldx(H, R5, R2, 0);
    a.stx(H, R10, R5, S_WORD0); // version, IHL, TOS
    a.ldx(H, R5, R2, 8);
    a.stx(H, R10, R5, S_WORD8); // TTL, protocol
                                // conf: the link MTU, and the WireGuard interface's own addresses
    a.st(W, R10, S_KEY, 0);
    a.ld_map(R1, conf_fd);
    a.mov(R2, R10);
    a.add_imm(R2, S_KEY as i32);
    a.call(MAP_LOOKUP_ELEM);
    a.jeq(R0, 0, "pass");
    a.ldx(W, R4, R0, 0);
    a.ldx(H, R5, R10, S_TOTLEN);
    a.jgt(R5, R4, "pass"); // longer than the link's MTU: the socket path
    for k in 0..MAX_LOCALS as i16 {
        a.ldx(W, R4, R0, 4 + 4 * k);
        a.jeq32(R4, 0, "pass"); // the addresses are packed from the start
        a.jeq32_reg(R8, R4, "local");
    }
    a.ja("pass");
    a.label("local");
    for (i, r) in rules.iter().enumerate() {
        let next = format!("next{i}");
        a.jne32(R7, ip_word(r.remote), &next);
        a.jne32(R9, port_word(r.listen_port), &next);
        a.ja(&format!("rule{i}"));
        a.label(&next);
    }
    a.label("pass");
    a.mov_imm(R0, TC_ACT_OK);
    a.exit();
    let word0 = bytes_word([0x45, 0x00]);
    let word8 = bytes_word([64, 17]);
    for (i, r) in rules.iter().enumerate() {
        a.label(&format!("rule{i}"));
        // replace one checksum's share of a field: the old value from a register or a stack slot
        let csum = |a: &mut Asm, helper: i32, at: i32, from_stack: Option<i16>, from_reg: u8, to: i32, flags: i32| {
            a.mov(R1, R6);
            a.mov_imm(R2, at);
            match from_stack {
                Some(off) => a.ldx(H, R3, R10, off),
                None => a.mov(R3, from_reg),
            }
            a.mov_imm(R4, to);
            a.mov_imm(R5, flags);
            a.call(helper);
        };
        let l4 = F_MARK_MANGLED_0; // a UDP checksum of 0 (none) stays 0
        csum(&mut a, L4_CSUM_REPLACE, 26, None, R7, ip_word(r.link), l4 | F_PSEUDO_HDR | 4);
        csum(&mut a, L4_CSUM_REPLACE, 26, None, R8, ip_word(r.target), l4 | F_PSEUDO_HDR | 4);
        csum(&mut a, L4_CSUM_REPLACE, 26, Some(S_SPORT), 0, port_word(r.link_port), l4 | 2);
        csum(&mut a, L4_CSUM_REPLACE, 26, None, R9, port_word(r.target_port), l4 | 2);
        csum(&mut a, L3_CSUM_REPLACE, 10, None, R7, ip_word(r.link), 4);
        csum(&mut a, L3_CSUM_REPLACE, 10, None, R8, ip_word(r.target), 4);
        csum(&mut a, L3_CSUM_REPLACE, 10, Some(S_WORD0), 0, word0, 2);
        csum(&mut a, L3_CSUM_REPLACE, 10, Some(S_WORD8), 0, word8, 2);
        let store = |a: &mut Asm, at: i32, size: u8, val: i32, len: i32| {
            a.st(size, R10, S_TMP, val);
            a.mov(R1, R6);
            a.mov_imm(R2, at);
            a.mov(R3, R10);
            a.add_imm(R3, S_TMP as i32);
            a.mov_imm(R4, len);
            a.mov_imm(R5, 0);
            a.call(SKB_STORE_BYTES);
        };
        store(&mut a, 12, W, ip_word(r.link), 4);
        store(&mut a, 16, W, ip_word(r.target), 4);
        store(&mut a, 20, H, port_word(r.link_port), 2);
        store(&mut a, 22, H, port_word(r.target_port), 2);
        store(&mut a, 0, H, word0, 2);
        store(&mut a, 8, H, word8, 2);
        // bpf_redirect_neigh replaces an Ethernet header; a WireGuard packet has none, so push one
        a.mov_imm(R8, TC_ACT_SHOT);
        a.mov(R1, R6);
        a.mov_imm(R2, 14);
        a.mov_imm(R3, 0);
        a.call(SKB_CHANGE_HEAD);
        a.jne32(R0, 0, &format!("count{i}"));
        a.st(W, R10, S_ETH, i32::from_ne_bytes([2, 0, 0, 0]));
        a.st(W, R10, S_ETH + 4, i32::from_ne_bytes([0, 1, 2, 0]));
        a.st(W, R10, S_ETH + 8, i32::from_ne_bytes([0, 0, 0, 2]));
        a.st(H, R10, S_ETH + 12, bytes_word([0x08, 0x00]));
        a.mov(R1, R6);
        a.mov_imm(R2, 0);
        a.mov(R3, R10);
        a.add_imm(R3, S_ETH as i32);
        a.mov_imm(R4, 14);
        a.mov_imm(R5, 0);
        a.call(SKB_STORE_BYTES);
        a.mov_imm(R1, link_ifindex as i32);
        a.mov_imm(R2, 0);
        a.mov_imm(R3, 0);
        a.mov_imm(R4, redirect_flags);
        a.call(REDIRECT_NEIGH);
        a.mov(R8, R0);
        // count it, and learn the remote, after the redirect
        a.label(&format!("count{i}"));
        a.st(W, R10, S_KEY, i as i32);
        a.ld_map(R1, rules_fd);
        a.mov(R2, R10);
        a.add_imm(R2, S_KEY as i32);
        a.call(MAP_LOOKUP_ELEM);
        a.jeq(R0, 0, &format!("done{i}"));
        a.mov_imm(R5, 1);
        a.jne32(R8, TC_ACT_REDIRECT, &format!("failed{i}"));
        a.stx(W, R0, R7, 0);
        a.ldx(H, R4, R10, S_SPORT);
        a.stx(H, R0, R4, 4);
        a.xadd64(R0, R5, 8);
        a.ja(&format!("done{i}"));
        a.label(&format!("failed{i}"));
        a.xadd64(R0, R5, 16);
        a.label(&format!("done{i}"));
        a.mov(R0, R8);
        a.exit();
    }
    a.finish()
}

// ---------------------------------------------------------------- the bpf(2) system call

const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
/// a `rules` slot: remote address (4), remote port (2, network order), unused (2), redirected (8), failed (8)
const RULE_VALUE: u32 = 24;
/// the `conf` slot: link MTU (4), then MAX_LOCALS addresses (4 each), packed from the start
const CONF_VALUE: u32 = 4 + 4 * MAX_LOCALS as u32;

fn bpf(cmd: libc::c_long, attr: &mut [u8; 128]) -> io::Result<i32> {
    // SAFETY: attr is a zeroed union bpf_attr of the size given; the kernel reads only the fields of cmd.
    let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len() as libc::c_uint) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as i32)
    }
}

fn put32(a: &mut [u8; 128], at: usize, v: u32) {
    a[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}
fn put64(a: &mut [u8; 128], at: usize, v: u64) {
    a[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}

fn owned(fd: i32) -> OwnedFd {
    // SAFETY: fd was just returned by bpf(2) and nothing else owns it.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn map_create(value: u32, entries: u32) -> io::Result<OwnedFd> {
    let mut a = [0u8; 128];
    put32(&mut a, 0, BPF_MAP_TYPE_ARRAY);
    put32(&mut a, 4, 4);
    put32(&mut a, 8, value);
    put32(&mut a, 12, entries.max(1));
    bpf(BPF_MAP_CREATE, &mut a).map(owned)
}

fn prog_load(ins: &[u64]) -> Result<OwnedFd, String> {
    let license = b"Apache-2.0\0";
    let load = |log: &mut Vec<u8>| {
        let mut a = [0u8; 128];
        put32(&mut a, 0, BPF_PROG_TYPE_SCHED_CLS);
        put32(&mut a, 4, ins.len() as u32);
        put64(&mut a, 8, ins.as_ptr() as u64);
        put64(&mut a, 16, license.as_ptr() as u64);
        if !log.is_empty() {
            put32(&mut a, 24, 1);
            put32(&mut a, 28, log.len() as u32);
            put64(&mut a, 32, log.as_mut_ptr() as u64);
        }
        a[48..48 + NAME.len()].copy_from_slice(NAME.as_bytes());
        bpf(BPF_PROG_LOAD, &mut a)
    };
    match load(&mut Vec::new()) {
        Ok(fd) => Ok(owned(fd)),
        Err(e) => {
            // again with the verifier's log, for the reason
            let mut log = vec![0u8; 1 << 20];
            let _ = load(&mut log);
            let text = String::from_utf8_lossy(&log[..log.iter().position(|&b| b == 0).unwrap_or(0)]).to_string();
            let tail: Vec<&str> = text.lines().rev().take(3).collect();
            Err(format!(
                "the kernel refused the program: {e}{}",
                if tail.is_empty() { String::new() } else { format!(" ({})", tail.join(" / ")) }
            ))
        }
    }
}

fn prog_id(prog: &OwnedFd) -> Option<u32> {
    let mut info = [0u8; 256];
    let mut a = [0u8; 128];
    put32(&mut a, 0, prog.as_raw_fd() as u32);
    put32(&mut a, 4, info.len() as u32);
    put64(&mut a, 8, info.as_mut_ptr() as u64);
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut a).ok()?;
    Some(u32::from_ne_bytes(info[4..8].try_into().unwrap()))
}

fn map_lookup<const N: usize>(map: &OwnedFd, key: u32) -> Option<[u8; N]> {
    let mut value = [0u8; N];
    let mut a = [0u8; 128];
    put32(&mut a, 0, map.as_raw_fd() as u32);
    put64(&mut a, 8, &key as *const u32 as u64);
    put64(&mut a, 16, value.as_mut_ptr() as u64);
    bpf(BPF_MAP_LOOKUP_ELEM, &mut a).ok().map(|_| value)
}

fn map_update(map: &OwnedFd, key: u32, value: &[u8]) -> io::Result<()> {
    let mut a = [0u8; 128];
    put32(&mut a, 0, map.as_raw_fd() as u32);
    put64(&mut a, 8, &key as *const u32 as u64);
    put64(&mut a, 16, value.as_ptr() as u64);
    bpf(BPF_MAP_UPDATE_ELEM, &mut a).map(|_| ())
}

// ---------------------------------------------------------------- capabilities

const CAP_BPF: u32 = 39;

/// Drop CAP_BPF from this process (effective, permitted, inheritable, ambient) once the program
/// is attached: what is left of the kernel path (reading and writing its maps, removing its
/// filter) needs no CAP_BPF.
pub fn drop_cap_bpf() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut h = Header { version: 0x2008_0522, pid: 0 };
    let mut d = [Data::default(); 2];
    // SAFETY: header and two data structs, as capget(2) version 3 takes them.
    if unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut Header, d.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let bit = !(1u32 << (CAP_BPF - 32));
    d[1].effective &= bit;
    d[1].permitted &= bit;
    d[1].inheritable &= bit;
    // SAFETY: as above.
    if unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut Header, d.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain prctl(2) call.
    unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_LOWER as libc::c_ulong, CAP_BPF as libc::c_ulong, 0, 0) };
    Ok(())
}

// ---------------------------------------------------------------- netfilter

/// The hooks whose rules a kernel-path datagram skips: those that see it arriving on the
/// WireGuard interface, and those that see it leaving on the link interface.
const IN_HOOKS: [&str; 3] = ["prerouting", "input", "ingress"];
const OUT_HOOKS: [&str; 3] = ["output", "postrouting", "egress"];

/// Whether netfilter has a rule or a base-chain policy that would see the kernel path's
/// datagrams: Ok(None) none, Ok(Some(why)) one, Err when the ruleset cannot be read. A rule counts
/// unless it matches an interface name (`iifname`, `oifname`) that is another interface.
pub fn netfilter_applies(remote_if: &str, link_if: &str) -> Result<Option<String>, String> {
    let legacy: Vec<String> = ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|l| !l.trim().is_empty())
        .collect();
    if !legacy.is_empty() {
        return Ok(Some(format!("iptables (legacy) tables are loaded: {}", legacy.join(", "))));
    }
    let p = crate::sysutil::run(&["nft", "-j", "list", "ruleset"]);
    if p.code == 127 || (p.code != 0 && p.stderr.contains("No such file")) {
        // nf_tables loaded as a module or built into the kernel: its rules exist and cannot be read
        let present = std::path::Path::new("/sys/module/nf_tables").exists()
            || std::path::Path::new("/proc/net/netfilter/nf_tables").exists()
            || std::fs::read_to_string("/proc/modules").unwrap_or_default().lines().any(|l| l.starts_with("nf_tables "));
        return if present {
            Err("nf_tables is in the kernel and the nft command is not installed, so its rules cannot be read".into())
        } else {
            Ok(None)
        };
    }
    if p.code != 0 {
        return Err(format!("nft -j list ruleset: {}", p.stderr.trim()));
    }
    let v: serde_json::Value = serde_json::from_str(&p.stdout).map_err(|e| format!("nft -j list ruleset: {e}"))?;
    let items = v["nftables"].as_array().cloned().unwrap_or_default();
    // base chains at the hooks: (family, table, chain) -> (inbound, its device for netdev)
    let mut base: HashMap<(String, String, String), (bool, Option<String>)> = HashMap::new();
    for it in &items {
        let Some(c) = it.get("chain") else { continue };
        let Some(hook) = c["hook"].as_str() else { continue };
        let inbound = IN_HOOKS.contains(&hook);
        if !inbound && !OUT_HOOKS.contains(&hook) {
            continue;
        }
        let family = c["family"].as_str().unwrap_or("").to_string();
        if !["ip", "ip6", "inet", "netdev"].contains(&family.as_str()) {
            continue;
        }
        let dev = c["dev"].as_str().map(str::to_string);
        let ours = if inbound { remote_if } else { link_if };
        if family == "netdev" && dev.as_deref().is_some_and(|d| d != ours) {
            continue;
        }
        let key = (family.clone(), c["table"].as_str().unwrap_or("").to_string(), c["name"].as_str().unwrap_or("").to_string());
        if c["policy"].as_str() == Some("drop") {
            return Ok(Some(format!("{} {} chain {} (hook {hook}) has policy drop", key.0, key.1, key.2)));
        }
        base.insert(key, (inbound, dev));
    }
    for it in &items {
        let Some(r) = it.get("rule") else { continue };
        let key = (
            r["family"].as_str().unwrap_or("").to_string(),
            r["table"].as_str().unwrap_or("").to_string(),
            r["chain"].as_str().unwrap_or("").to_string(),
        );
        let Some((inbound, _)) = base.get(&key) else { continue };
        let ours = if *inbound { remote_if } else { link_if };
        let meta = if *inbound { ["iifname", "iif"] } else { ["oifname", "oif"] };
        let other = r["expr"].as_array().is_some_and(|ex| {
            ex.iter().any(|e| {
                let m = &e["match"];
                m["op"].as_str() == Some("==")
                    && m["left"]["meta"]["key"].as_str().is_some_and(|k| meta.contains(&k))
                    && m["right"].as_str().is_some_and(|name| names_another(name, ours))
            })
        });
        if !other {
            return Ok(Some(format!(
                "{} {} chain {} has a rule that can see {}'s datagrams{}",
                key.0,
                key.1,
                key.2,
                if *inbound { format!("{remote_if} input") } else { format!("{link_if} output") },
                r["handle"].as_u64().map(|h| format!(" (handle {h})")).unwrap_or_default()
            )));
        }
    }
    Ok(None)
}

/// Whether an `iifname`/`oifname` value names an interface other than `ours`: only a literal name
/// that differs. A wildcard (`wg*`, nft's trailing `*`) whose prefix `ours` starts with names it;
/// any other wildcard or pattern is counted as possibly ours.
fn names_another(name: &str, ours: &str) -> bool {
    if let Some(prefix) = name.strip_suffix('*') {
        if prefix.contains(['*', '?', '[', '\\']) {
            return false;
        }
        return !ours.starts_with(prefix);
    }
    !name.contains(['*', '?', '[', '\\']) && name != ours
}

// ---------------------------------------------------------------- finding and removing the filter

/// The relay's filters (by name, at PRIO) on every interface, and any other filter at PRIO.
pub fn filters() -> Result<Vec<(String, nl::IngressFilter)>, String> {
    let mut out = Vec::new();
    let names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map_err(|e| format!("/sys/class/net: {e}"))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    for dev in names {
        // an interface with no ingress hook gives none; any other error is not "no filter"
        let fs = nl::tc_ingress_filters(&dev).map_err(|e| format!("{dev}: reading its tc filters: {e}"))?;
        for f in fs {
            if f.prio == PRIO || f.name.as_deref() == Some(NAME) {
                out.push((dev.clone(), f));
            }
        }
    }
    Ok(out)
}

/// Remove every filter of the relay's program, on any interface, and the state file. An error
/// names a filter that could not be removed.
pub fn detach_all() -> Result<usize, String> {
    let mut n = 0;
    for (dev, f) in filters()? {
        if f.name.as_deref() != Some(NAME) {
            continue; // someone else's filter at the same priority: not ours to remove
        }
        nl::tc_filter_del_exact(&dev, &f)
            .map_err(|e| format!("{dev}: the kernel path's filter (pref {}) could not be removed: {e}", f.prio))?;
        n += 1;
    }
    let _ = std::fs::remove_file(STATE);
    Ok(n)
}

// ---------------------------------------------------------------- the attached path

/// The rules the kernel path can carry, from the declaration alone: UDP, `remote-to-link` or
/// `both`, IPv4 remote and target, no proxy address. (remote, listen port, target, target port)
pub fn eligible(r: &Relay) -> Vec<(Ipv4Addr, u16, Ipv4Addr, u16)> {
    r.rules
        .iter()
        .filter(|x| x.protocol == "udp" && !x.link_initiated() && x.link_address.is_none())
        .filter_map(|x| Some((x.remote.parse().ok()?, x.listen_port, x.target.parse().ok()?, x.target_port)))
        .collect()
}

fn rules_json(rules: &[(Ipv4Addr, u16, Ipv4Addr, u16)]) -> serde_json::Value {
    serde_json::Value::Array(rules.iter().map(|(a, p, t, q)| serde_json::json!([a.to_string(), p, t.to_string(), q])).collect())
}

/// The program attached to the WireGuard interface; dropping it detaches it.
pub struct KernelPath {
    dev: String,
    link_dev: String,
    rules_map: OwnedFd,
    conf_map: OwnedFd,
    _prog: OwnedFd,
    conf: Vec<u8>,
    pub rules: usize,
    /// local addresses beyond MAX_LOCALS, which the program does not match
    pub unmatched_locals: usize,
}

impl KernelPath {
    /// Build, load and attach the program for these rules (map slot = position in `rules`), and
    /// record it in STATE.
    pub fn start(dev: &str, link_dev: &str, rules: &[KRule], bypasses_netfilter: bool) -> Result<KernelPath, String> {
        Self::start_with(dev, link_dev, rules, bypasses_netfilter, 0)
    }

    fn start_with(dev: &str, link_dev: &str, rules: &[KRule], bypasses_netfilter: bool, redirect_flags: i32) -> Result<KernelPath, String> {
        if rules.is_empty() {
            return Err("no rule it can carry (it carries IPv4 UDP remote-to-link and both rules without a proxy address)".into());
        }
        let link_ifindex = nl::ifindex(link_dev).map_err(|e| format!("{link_dev}: {e}"))?;
        let rules_map = map_create(RULE_VALUE, rules.len() as u32).map_err(|e| format!("cannot create the map: {e}"))?;
        let conf_map = map_create(CONF_VALUE, 1).map_err(|e| format!("cannot create the map: {e}"))?;
        let ins = program(rules, link_ifindex, rules_map.as_raw_fd(), conf_map.as_raw_fd(), redirect_flags)?;
        let prog = prog_load(&ins)?;
        let mut k = KernelPath {
            dev: dev.to_string(),
            link_dev: link_dev.to_string(),
            rules_map,
            conf_map,
            _prog: prog,
            conf: Vec::new(),
            rules: rules.len(),
            unmatched_locals: 0,
        };
        k.refresh().map_err(|e| format!("cannot write the map: {e}"))?;
        nl::tc_clsact(dev).map_err(|e| format!("{dev}: clsact: {e}"))?;
        nl::tc_bpf_ingress(dev, PRIO, k._prog.as_raw_fd(), NAME).map_err(|e| format!("{dev}: attaching the filter: {e}"))?;
        let state = serde_json::json!({
            "dev": dev,
            "prio": PRIO,
            "prog_id": prog_id(&k._prog),
            "bypasses_netfilter": bypasses_netfilter,
            "rules": rules_json(&rules.iter().map(|r| (r.remote, r.listen_port, r.target, r.target_port)).collect::<Vec<_>>()),
        });
        let _ = std::fs::write(STATE, state.to_string());
        Ok(k)
    }

    /// Write the link MTU and the WireGuard interface's IPv4 addresses to `conf` when they changed.
    pub fn refresh(&mut self) -> io::Result<()> {
        let mtu: u32 =
            crate::sysutil::read(&format!("/sys/class/net/{}/mtu", self.link_dev)).and_then(|m| m.trim().parse().ok()).unwrap_or(0);
        let locals: Vec<Ipv4Addr> =
            nl::addresses(&self.dev).iter().filter_map(|a| a.split('/').next().and_then(|x| x.parse::<Ipv4Addr>().ok())).collect();
        self.unmatched_locals = locals.len().saturating_sub(MAX_LOCALS);
        let mut v = vec![0u8; CONF_VALUE as usize];
        v[0..4].copy_from_slice(&mtu.to_ne_bytes());
        for (k, a) in locals.iter().take(MAX_LOCALS).enumerate() {
            v[4 + 4 * k..8 + 4 * k].copy_from_slice(&a.octets());
        }
        if v != self.conf {
            map_update(&self.conf_map, 0, &v)?;
            self.conf = v;
        }
        Ok(())
    }

    /// The rule's last remote (as the program saw it), datagrams redirected, datagrams it could not redirect.
    pub fn slot(&self, i: u32) -> Option<(Option<SocketAddr>, u64, u64)> {
        let v: [u8; RULE_VALUE as usize] = map_lookup(&self.rules_map, i)?;
        let ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
        let port = u16::from_be_bytes([v[4], v[5]]);
        let packets = u64::from_ne_bytes(v[8..16].try_into().unwrap());
        let failed = u64::from_ne_bytes(v[16..24].try_into().unwrap());
        Some(((port != 0).then_some(SocketAddr::new(IpAddr::V4(ip), port)), packets, failed))
    }
}

impl Drop for KernelPath {
    fn drop(&mut self) {
        if let Err(e) = detach_all() {
            eprintln!("goatrope relay: {e}");
        }
    }
}

// ---------------------------------------------------------------- check

/// What `check` compares: the filter the declaration would have attached (the relay running with
/// the kernel path declared) against the filters at PRIO on this machine and STATE.
pub fn check_item(r: Option<&Relay>, relay_active: bool, why: Option<&str>) -> (bool, String, String) {
    let found = match filters() {
        Ok(f) => f,
        Err(e) => return (false, "the filters can be read".into(), e),
    };
    let shown: Vec<String> = found
        .iter()
        .map(|(d, f)| {
            format!(
                "{d}: {} {}{}",
                f.kind,
                f.name.clone().unwrap_or_else(|| "(unnamed)".into()),
                f.prog_id.map(|i| format!(" id {i}")).unwrap_or_default()
            )
        })
        .collect();
    let mut have = if shown.is_empty() { "no filter at pref 3000".to_string() } else { shown.join("; ") };
    if let Some(w) = why.filter(|_| found.is_empty()) {
        have.push_str(&format!(" (the relay says: {w})"));
    }
    let declared = r.filter(|r| r.kernel_path);
    let Some(r) = declared.filter(|_| relay_active) else {
        let want = if declared.is_some() { "the relay is not running: no filter" } else { "kernel path off: no filter" };
        return (found.is_empty(), want.to_string(), have);
    };
    let mode = if r.kernel_path_bypasses_netfilter { ", bypassing netfilter (accepted)" } else { "" };
    let want = format!("one filter on {} named {NAME}, for {} rule(s){mode}", r.remote_interface, eligible(r).len());
    let state: Option<serde_json::Value> = crate::sysutil::read(STATE).and_then(|t| serde_json::from_str(&t).ok());
    let ok = match (&found[..], &state) {
        ([(d, f)], Some(s)) => {
            d == &r.remote_interface
                && f.name.as_deref() == Some(NAME)
                && f.prog_id.is_some()
                && s["prog_id"].as_u64() == f.prog_id.map(u64::from)
                && s["dev"].as_str() == Some(r.remote_interface.as_str())
                && s["rules"] == rules_json(&eligible(r))
                && s["bypasses_netfilter"].as_bool() == Some(r.kernel_path_bypasses_netfilter)
        }
        _ => false,
    };
    (ok, want, have)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_the_kernel_headers() {
        assert_eq!(raw(0xbf, R6, R1, 0, 0), 0x16bf); // r6 = r1
        assert_eq!(raw(0x61, R2, R6, SKB_DATA, 0), 0x004c_6261); // r2 = *(u32 *)(r6 + 76)
        assert_eq!(raw(0x95, 0, 0, 0, 0), 0x95); // exit
        assert_eq!(raw(0xdc, R5, 0, 0, 16), 0x0000_0010_0000_05dc); // r5 = be16 r5
        assert_eq!(port_word(7002), u16::from_ne_bytes([0x1b, 0x5a]) as i32);
        assert_eq!(ip_word(Ipv4Addr::new(192, 0, 2, 50)), u32::from_ne_bytes([192, 0, 2, 50]) as i32);
    }

    #[test]
    fn interface_names_another_only_when_literal_and_different() {
        assert!(names_another("eth9", "wg0"));
        assert!(!names_another("wg0", "wg0"));
        assert!(!names_another("wg*", "wg0"));
        assert!(names_another("eth*", "wg0"));
        assert!(!names_another("*", "wg0"));
        assert!(!names_another("w?0", "wg0"));
    }

    #[test]
    fn jumps_resolve_inside_the_program() {
        let r = KRule {
            remote: Ipv4Addr::new(10, 99, 0, 2),
            listen_port: 7002,
            link: Ipv4Addr::new(192, 0, 2, 50),
            link_port: 40000,
            target: Ipv4Addr::new(192, 0, 2, 2),
            target_port: 7002,
        };
        let p = program(&[r.clone(), r], 9, 3, 4, 0).unwrap();
        assert!(p.len() > 100 && p.len() < 4096);
        for (i, ins) in p.iter().enumerate() {
            let op = (*ins & 0xff) as u8;
            if op & 0x07 == 0x05 || op & 0x07 == 0x06 {
                if op == 0x85 || op == 0x95 {
                    continue; // call, exit
                }
                let off = ((*ins >> 16) & 0xffff) as u16 as i16 as i64;
                let to = i as i64 + 1 + off;
                assert!(to >= 0 && (to as usize) < p.len(), "jump at {i} to {to}");
            }
        }
    }

    /// A TUN device stands for the WireGuard interface (both carry IP packets with no Ethernet
    /// header): a well-formed datagram written into it is redirected and counted; with redirect
    /// flags bpf_redirect_neigh refuses, the same datagram is counted as failed.
    #[test]
    #[ignore = "creates a TUN and a dummy interface and loads a BPF program; run as root by the namespace tests"]
    fn redirects_and_failures_are_counted() {
        use std::io::Write;
        let run = |c: &str| assert!(std::process::Command::new("sh").arg("-c").arg(c).status().unwrap().success(), "{c}");
        let _ = std::process::Command::new("sh").arg("-c").arg("ip link del kpt0; ip link del kpd0").status();
        if !std::path::Path::new("/dev/net/tun").exists() {
            run("mkdir -p /dev/net && mknod /dev/net/tun c 10 200");
        }
        let f = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun").unwrap();
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: i16,
            pad: [u8; 22],
        }
        let mut req = IfReq { name: [0; 16], flags: 0x0001 | 0x1000, pad: [0; 22] }; // IFF_TUN | IFF_NO_PI
        req.name[..5].copy_from_slice(b"kpt0\0");
        // SAFETY: TUNSETIFF with an ifreq of the size the kernel reads.
        assert_eq!(unsafe { libc::ioctl(f.as_raw_fd(), 0x400454ca, &mut req) }, 0, "TUNSETIFF");
        run("ip addr add 198.18.0.1/24 dev kpt0 && ip link set kpt0 up");
        run("ip link add kpd0 type dummy && ip addr add 198.19.0.1/24 dev kpd0 && ip link set kpd0 up");
        run("ip neigh replace 198.19.0.2 lladdr 02:00:00:00:00:99 dev kpd0");
        let rule = KRule {
            remote: Ipv4Addr::new(198, 18, 0, 2),
            listen_port: 7002,
            link: Ipv4Addr::new(198, 19, 0, 1),
            link_port: 40000,
            target: Ipv4Addr::new(198, 19, 0, 2),
            target_port: 7002,
        };
        // an IPv4 UDP datagram, 198.18.0.2:40000 -> 198.18.0.1:7002, checksums right
        let payload = b"kpath-counter-test";
        let udp_len = 8 + payload.len();
        let mut ip = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 198, 18, 0, 2, 198, 18, 0, 1];
        ip[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        let sum = |b: &[u8]| {
            let mut t: u32 = b.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
            while t >> 16 != 0 {
                t = (t & 0xffff) + (t >> 16);
            }
            !(t as u16)
        };
        let c = sum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        let mut udp = vec![0x9c, 0x40, 0x1b, 0x5a];
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        let mut pseudo = vec![198, 18, 0, 2, 198, 18, 0, 1, 0, 17];
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&udp);
        let c = sum(&pseudo);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        let packet = [ip, udp].concat();
        for (flags, want_sent, want_failed) in [(0, 3, 0), (1, 0, 3)] {
            let k = KernelPath::start_with("kpt0", "kpd0", std::slice::from_ref(&rule), true, flags).unwrap();
            for _ in 0..3 {
                (&f).write_all(&packet).unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
            let (_, sent, failed) = k.slot(0).unwrap();
            assert_eq!((sent, failed), (want_sent, want_failed), "redirect flags {flags}");
            drop(k);
        }
        let _ = std::process::Command::new("sh").arg("-c").arg("ip link del kpd0").status();
    }
}
