// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Links, addresses and WireGuard devices through netlink, on synchronous sockets (ADR 0003):
//! what the Python tree asked of `ip` and `wg`.

use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, SocketAddr};

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST,
};
use netlink_packet_generic::ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd};
use netlink_packet_generic::GenlMessage;
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd, WireguardMessage, WireguardPeer,
    WireguardPeerAttribute,
};
use netlink_sys::protocols::{NETLINK_GENERIC, NETLINK_ROUTE};
use netlink_sys::{Socket, SocketAddr as NlAddr};

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Send one request and collect the replies: every part of a dump, or the one answer to a
/// request, ending at the kernel's acknowledgement. A refusal comes back as its errno.
fn request<T>(proto: isize, mut msg: NetlinkMessage<T>, flags: u16) -> io::Result<Vec<T>>
where
    T: NetlinkSerializable + NetlinkDeserializable + Debug,
{
    let mut sock = Socket::new(proto)?;
    sock.bind_auto()?;
    sock.connect(&NlAddr::new(0, 0))?;
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut tx = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut tx);
    sock.send(&tx, 0)?;
    let mut out = Vec::new();
    loop {
        let (rx, _) = sock.recv_from_full()?;
        let mut off = 0;
        while off < rx.len() {
            let m = NetlinkMessage::<T>::deserialize(&rx[off..]).map_err(|e| invalid(format!("netlink: {e}")))?;
            let len = m.header.length as usize;
            match m.payload {
                NetlinkPayload::Done(_) => return Ok(out),
                NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.to_io()),
                NetlinkPayload::Error(_) if !dump => return Ok(out),
                NetlinkPayload::InnerMessage(i) => out.push(i),
                _ => {}
            }
            if len == 0 {
                break;
            }
            off += (len + 3) & !3;
        }
    }
}

fn route(msg: RouteNetlinkMessage, flags: u16) -> io::Result<Vec<RouteNetlinkMessage>> {
    request(NETLINK_ROUTE, NetlinkMessage::from(msg), flags)
}

/// The link named ifname; None when there is none.
fn link(ifname: &str) -> io::Result<Option<LinkMessage>> {
    let mut m = LinkMessage::default();
    m.attributes.push(LinkAttribute::IfName(ifname.to_string()));
    match route(RouteNetlinkMessage::GetLink(m), 0) {
        Ok(v) => Ok(v.into_iter().find_map(|r| match r {
            RouteNetlinkMessage::NewLink(l) => Some(l),
            _ => None,
        })),
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => Ok(None),
        Err(e) => Err(e),
    }
}

fn index(ifname: &str) -> io::Result<u32> {
    link(ifname)?.map(|l| l.header.index).ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
}

/// The link's kind ("wireguard", "bridge", "veth", ...); None for a plain device or no device.
pub fn kind(ifname: &str) -> Option<String> {
    let l = link(ifname).ok()??;
    l.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|i| match i {
            LinkInfo::Kind(k) => Some(k.to_string()),
            _ => None,
        }),
        _ => None,
    })
}

/// The interface's addresses as "address/prefix", in the kernel's order; empty when there is none.
pub fn addresses(ifname: &str) -> Vec<String> {
    let Ok(Some(l)) = link(ifname) else {
        return Vec::new();
    };
    let Ok(all) = route(RouteNetlinkMessage::GetAddress(AddressMessage::default()), NLM_F_DUMP) else {
        return Vec::new();
    };
    all.into_iter()
        .filter_map(|r| match r {
            RouteNetlinkMessage::NewAddress(a) if a.header.index == l.header.index => Some(a),
            _ => None,
        })
        .filter_map(|a| {
            let local = a.attributes.iter().find_map(|x| match x {
                AddressAttribute::Local(ip) => Some(*ip),
                _ => None,
            });
            let addr = a.attributes.iter().find_map(|x| match x {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            });
            local.or(addr).map(|ip| format!("{ip}/{}", a.header.prefix_len))
        })
        .collect()
}

/// `ip link add <ifname> type wireguard`
pub fn add_wireguard(ifname: &str) -> io::Result<()> {
    let mut m = LinkMessage::default();
    m.attributes.push(LinkAttribute::IfName(ifname.to_string()));
    m.attributes.push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wireguard)]));
    route(RouteNetlinkMessage::NewLink(m), NLM_F_CREATE | NLM_F_EXCL).map(|_| ())
}

/// `ip link del <ifname>`
pub fn delete_link(ifname: &str) -> io::Result<()> {
    let mut m = LinkMessage::default();
    m.header.index = index(ifname)?;
    route(RouteNetlinkMessage::DelLink(m), 0).map(|_| ())
}

/// `ip link set <ifname> up`
pub fn set_up(ifname: &str) -> io::Result<()> {
    let mut m = LinkMessage::default();
    m.header.index = index(ifname)?;
    m.header.flags = LinkFlags::Up;
    m.header.change_mask = LinkFlags::Up;
    route(RouteNetlinkMessage::NewLink(m), 0).map(|_| ())
}

/// `ip link set <ifname> down`
pub fn set_down(ifname: &str) -> io::Result<()> {
    let mut m = LinkMessage::default();
    m.header.index = index(ifname)?;
    m.header.flags = LinkFlags::empty();
    m.header.change_mask = LinkFlags::Up;
    route(RouteNetlinkMessage::NewLink(m), 0).map(|_| ())
}

/// Whether the link is administratively up; None when there is no such link.
pub fn is_up(ifname: &str) -> Option<bool> {
    link(ifname).ok()?.map(|l| l.header.flags.contains(LinkFlags::Up))
}

/// `ip address add <ip/prefix> dev <ifname>`
pub fn add_address(ifname: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    let mut m = AddressMessage::default();
    m.header.index = index(ifname)?;
    m.header.prefix_len = prefix;
    m.header.family = if ip.is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    m.attributes.push(AddressAttribute::Local(ip));
    m.attributes.push(AddressAttribute::Address(ip));
    route(RouteNetlinkMessage::NewAddress(m), NLM_F_CREATE | NLM_F_EXCL).map(|_| ())
}

/// One IPv4 or IPv6 address of an interface, with the kernel's IFA_FLAGS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub ip: IpAddr,
    pub prefix: u8,
    pub noprefixroute: bool,
}

/// Every address of the interface (or of every interface, when ifname is None) as Addr.
pub fn address_list(ifname: Option<&str>) -> io::Result<Vec<(u32, Addr)>> {
    let want = match ifname {
        Some(i) => Some(index(i)?),
        None => None,
    };
    let all = route(RouteNetlinkMessage::GetAddress(AddressMessage::default()), NLM_F_DUMP)?;
    Ok(all
        .into_iter()
        .filter_map(|r| match r {
            RouteNetlinkMessage::NewAddress(a) if want.is_none_or(|w| w == a.header.index) => Some(a),
            _ => None,
        })
        .filter_map(|a| {
            let mut local = None;
            let mut addr = None;
            let mut flags = AddressFlags::empty();
            for x in &a.attributes {
                match x {
                    AddressAttribute::Local(ip) => local = Some(*ip),
                    AddressAttribute::Address(ip) => addr = Some(*ip),
                    AddressAttribute::Flags(f) => flags = *f,
                    _ => {}
                }
            }
            let ip = local.or(addr)?;
            Some((a.header.index, Addr { ip, prefix: a.header.prefix_len, noprefixroute: flags.contains(AddressFlags::Noprefixroute) }))
        })
        .collect())
}

fn address_msg(ifname: &str, ip: IpAddr, prefix: u8) -> io::Result<AddressMessage> {
    let mut m = AddressMessage::default();
    m.header.index = index(ifname)?;
    m.header.prefix_len = prefix;
    m.header.family = if ip.is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    m.attributes.push(AddressAttribute::Local(ip));
    m.attributes.push(AddressAttribute::Address(ip));
    Ok(m)
}

/// `ip address add <ip/prefix> dev <ifname> noprefixroute`: the address, and no route for its prefix.
pub fn add_address_noprefixroute(ifname: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    let mut m = address_msg(ifname, ip, prefix)?;
    m.attributes.push(AddressAttribute::Flags(AddressFlags::Noprefixroute));
    route(RouteNetlinkMessage::NewAddress(m), NLM_F_CREATE | NLM_F_EXCL).map(|_| ())
}

/// `ip address del <ip/prefix> dev <ifname>`
pub fn del_address(ifname: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    let m = address_msg(ifname, ip, prefix)?;
    route(RouteNetlinkMessage::DelAddress(m), 0).map(|_| ())
}

// ---------------------------------------------------------------- WireGuard (generic netlink)

fn wireguard_family() -> io::Result<u16> {
    let m =
        GenlMessage::from_payload(GenlCtrl { cmd: GenlCtrlCmd::GetFamily, nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".to_string())] });
    let replies = request(NETLINK_GENERIC, NetlinkMessage::from(m), 0)?;
    replies
        .iter()
        .flat_map(|r| r.payload.nlas.iter())
        .find_map(|a| match a {
            GenlCtrlAttrs::FamilyId(id) => Some(*id),
            _ => None,
        })
        .ok_or_else(|| invalid("netlink: no wireguard family id".to_string()))
}

fn wireguard(cmd: WireguardCmd, attributes: Vec<WireguardAttribute>, flags: u16) -> io::Result<Vec<WireguardMessage>> {
    let family = wireguard_family()?;
    let mut m = GenlMessage::from_payload(WireguardMessage { cmd, attributes });
    m.set_resolved_family_id(family);
    let replies = request(NETLINK_GENERIC, NetlinkMessage::from(m), flags)?;
    Ok(replies.into_iter().map(|g| g.payload).collect())
}

/// One peer as `wg show <if> dump` describes it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WgPeer {
    pub public_key: [u8; 32],
    /// None when the peer has no preshared key (all zero)
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: u16,
    /// the latest handshake as seconds since the epoch (wall clock, as the kernel keeps it); 0: none yet
    pub last_handshake: i64,
}

/// A WireGuard device as `wg show <if> dump` describes it. The private key is not kept.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WgDevice {
    /// None when the device has no private key
    pub public_key: Option<[u8; 32]>,
    pub listen_port: u16,
    pub peers: Vec<WgPeer>,
}

fn peer_from(attrs: &[WireguardPeerAttribute]) -> WgPeer {
    let mut p = WgPeer::default();
    for a in attrs {
        match a {
            WireguardPeerAttribute::PublicKey(k) => p.public_key = *k,
            WireguardPeerAttribute::PresharedKey(k) if k.iter().any(|b| *b != 0) => p.preshared_key = Some(*k),
            WireguardPeerAttribute::Endpoint(e) => p.endpoint = Some(*e),
            WireguardPeerAttribute::PersistentKeepalive(k) => p.keepalive = *k,
            WireguardPeerAttribute::LastHandshake(t) => p.last_handshake = t.seconds,
            WireguardPeerAttribute::AllowedIps(ips) => {
                for ip in ips {
                    let addr = ip.0.iter().find_map(|x| match x {
                        WireguardAllowedIpAttr::IpAddr(a) => Some(*a),
                        _ => None,
                    });
                    let cidr = ip.0.iter().find_map(|x| match x {
                        WireguardAllowedIpAttr::Cidr(c) => Some(*c),
                        _ => None,
                    });
                    if let (Some(a), Some(c)) = (addr, cidr) {
                        p.allowed_ips.push((a, c));
                    }
                }
            }
            _ => {}
        }
    }
    p
}

/// `wg show <ifname> dump`. The kernel may split the peers, and one peer's allowed IPs, over
/// several messages; a peer that continues from the previous message is merged into it.
pub fn wg_get(ifname: &str) -> io::Result<WgDevice> {
    let msgs = wireguard(WireguardCmd::GetDevice, vec![WireguardAttribute::IfName(ifname.to_string())], NLM_F_DUMP)?;
    let mut d = WgDevice::default();
    for mut m in msgs {
        for a in m.attributes.iter_mut() {
            match a {
                // the kernel sends the private key to a privileged caller; it is not kept
                WireguardAttribute::PrivateKey(k) => k.fill(0),
                WireguardAttribute::PublicKey(k) if k.iter().any(|b| *b != 0) => d.public_key = Some(*k),
                WireguardAttribute::ListenPort(p) => d.listen_port = *p,
                WireguardAttribute::Peers(peers) => {
                    for p in peers.iter() {
                        let np = peer_from(&p.0);
                        match d.peers.last_mut() {
                            Some(last) if last.public_key == np.public_key => {
                                last.allowed_ips.extend(np.allowed_ips);
                                last.last_handshake = last.last_handshake.max(np.last_handshake);
                            }
                            _ => d.peers.push(np),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(d)
}

/// What `wg set` is given for one new device: its key, its port and its one peer.
pub struct WgSet {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub allowed: (IpAddr, u8),
    pub preshared_key: Option<[u8; 32]>,
    pub keepalive: u16,
}

impl Drop for WgSet {
    fn drop(&mut self) {
        self.private_key.fill(0);
        if let Some(k) = self.preshared_key.as_mut() {
            k.fill(0);
        }
    }
}

/// `wg set <ifname> listen-port .. private-key .. peer .. endpoint .. allowed-ips .. [preshared-key ..] [persistent-keepalive ..]`
pub fn wg_set(ifname: &str, s: &WgSet) -> io::Result<()> {
    let (ip, cidr) = s.allowed;
    let fam = if ip.is_ipv4() { WireguardAddressFamily::Ipv4 } else { WireguardAddressFamily::Ipv6 };
    let mut peer = vec![
        WireguardPeerAttribute::PublicKey(s.peer_public_key),
        WireguardPeerAttribute::Endpoint(s.endpoint),
        WireguardPeerAttribute::AllowedIps(vec![WireguardAllowedIp(vec![
            WireguardAllowedIpAttr::Family(fam),
            WireguardAllowedIpAttr::IpAddr(ip),
            WireguardAllowedIpAttr::Cidr(cidr),
        ])]),
    ];
    if let Some(k) = s.preshared_key {
        peer.push(WireguardPeerAttribute::PresharedKey(k));
    }
    if s.keepalive != 0 {
        peer.push(WireguardPeerAttribute::PersistentKeepalive(s.keepalive));
    }
    let attrs = vec![
        WireguardAttribute::IfName(ifname.to_string()),
        WireguardAttribute::PrivateKey(s.private_key),
        WireguardAttribute::ListenPort(s.listen_port),
        WireguardAttribute::Peers(vec![WireguardPeer(peer)]),
    ];
    wireguard(WireguardCmd::SetDevice, attrs, 0).map(|_| ())
}

// ---------------------------------------------------------------- WireGuard peer freshness

/// A tunnel is up while its latest handshake is younger than this (ADR 0004 §4). WireGuard
/// renews a session at least every 120 s while packets flow (REKEY_AFTER_TIME), and a mesh
/// peer with a persistent keepalive always has packets flowing.
pub const HANDSHAKE_FRESH_S: i64 = 180;

/// The peer WireGuard sends `remote` to: the one whose allowed IPs hold it, the longest prefix first.
pub fn owner(dev: &WgDevice, remote: IpAddr) -> Option<&WgPeer> {
    dev.peers
        .iter()
        .filter_map(|p| {
            p.allowed_ips.iter().filter(|(net, cidr)| prefix_holds(*net, *cidr, remote)).map(|(_, c)| (*c, p)).max_by_key(|(c, _)| *c)
        })
        .max_by_key(|(c, _)| *c)
        .map(|(_, p)| p)
}

/// The handshake age, in seconds, of the WireGuard peer on ifname that WireGuard would send
/// `remote` to: the one whose allowed IPs hold it, the longest prefix first. Err says why there is none.
pub fn handshake_age(ifname: &str, remote: IpAddr, now: i64) -> Result<i64, String> {
    let dev = wg_get(ifname).map_err(|e| format!("cannot read {ifname}: {}", crate::sys::strerror(&e)))?;
    let Some(p) = owner(&dev, remote) else {
        return Err(format!("no peer on {ifname} has {remote} in its allowed IPs"));
    };
    if p.last_handshake == 0 {
        return Err(format!("the peer for {remote} on {ifname} has not completed a handshake"));
    }
    Ok((now - p.last_handshake).max(0))
}

pub fn prefix_holds(net: IpAddr, cidr: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let m = if cidr == 0 { 0 } else { u32::MAX << (32 - cidr.min(32) as u32) };
            u32::from(n) & m == u32::from(i) & m
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let m = if cidr == 0 { 0 } else { u128::MAX << (128 - cidr.min(128) as u32) };
            u128::from(n) & m == u128::from(i) & m
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(prefix_holds(ip("198.51.100.0"), 24, ip("198.51.100.5")));
        assert!(!prefix_holds(ip("198.51.100.0"), 25, ip("198.51.100.200")));
        assert!(prefix_holds(ip("0.0.0.0"), 0, ip("203.0.113.1")));
        assert!(prefix_holds(ip("2001:db8::"), 32, ip("2001:db8::1")));
        assert!(!prefix_holds(ip("2001:db8::"), 32, ip("198.51.100.5")));
    }
}

// ---------------------------------------------------------------- tc: the relay's kernel path (docs/adr/0006)

/// The handle of a tc filter on a clsact qdisc's ingress hook.
const INGRESS_PARENT: u32 = 0xFFFF_FFF2;

pub fn ifindex(ifname: &str) -> io::Result<u32> {
    index(ifname)
}

/// Add a clsact qdisc to the device; one that is there already is kept.
pub fn tc_clsact(ifname: &str) -> io::Result<()> {
    use netlink_packet_route::tc::{TcAttribute, TcHandle, TcMessage};
    let mut m = TcMessage::with_index(index(ifname)? as i32);
    m.header.parent = TcHandle::CLSACT;
    m.header.handle = TcHandle { major: 0xFFFF, minor: 0 };
    m.attributes.push(TcAttribute::Kind("clsact".to_string()));
    match route(RouteNetlinkMessage::NewQueueDiscipline(m), NLM_F_CREATE | NLM_F_EXCL) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r.map(|_| ()),
    }
}

/// Attach a loaded SCHED_CLS program (direct action) to the device's ingress at this priority.
pub fn tc_bpf_ingress(ifname: &str, prio: u16, prog_fd: i32, name: &str) -> io::Result<()> {
    use netlink_packet_route::tc::{TcAttribute, TcBpfFlags, TcFilterBpfOption, TcHandle, TcMessage, TcOption};
    let mut m = TcMessage::with_index(index(ifname)? as i32);
    m.header.parent = TcHandle::from(INGRESS_PARENT);
    m.header.handle = TcHandle { major: 0, minor: 1 };
    m.header.info = ((prio as u32) << 16) | (libc::ETH_P_ALL as u16).to_be() as u32;
    m.attributes.push(TcAttribute::Kind("bpf".to_string()));
    m.attributes.push(TcAttribute::Options(vec![
        TcOption::Bpf(TcFilterBpfOption::ProgFd(prog_fd as u32)),
        TcOption::Bpf(TcFilterBpfOption::ProgName(name.to_string())),
        TcOption::Bpf(TcFilterBpfOption::Flags(TcBpfFlags::DirectAction)),
    ]));
    route(RouteNetlinkMessage::NewTrafficFilter(m), NLM_F_CREATE | NLM_F_EXCL).map(|_| ())
}

/// One filter on a device's ingress hook, as a dump gives it.
#[derive(Debug, Clone)]
pub struct IngressFilter {
    pub prio: u16,
    pub protocol: u16,
    pub handle: u32,
    pub kind: String,
    /// a bpf filter's program name and id
    pub name: Option<String>,
    pub prog_id: Option<u32>,
}

/// Every filter on the device's ingress hook (none when it has no clsact or ingress qdisc).
pub fn tc_ingress_filters(ifname: &str) -> io::Result<Vec<IngressFilter>> {
    use netlink_packet_route::tc::{TcAttribute, TcFilterBpfOption, TcHandle, TcMessage, TcOption};
    let idx = match index(ifname) {
        Ok(i) => i,
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut m = TcMessage::with_index(idx as i32);
    m.header.parent = TcHandle::from(INGRESS_PARENT);
    let replies = match route(RouteNetlinkMessage::GetTrafficFilter(m), NLM_F_DUMP) {
        Ok(r) => r,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for r in replies {
        let RouteNetlinkMessage::NewTrafficFilter(t) = r else { continue };
        if t.header.index as u32 != idx {
            continue;
        }
        let mut f = IngressFilter {
            prio: (t.header.info >> 16) as u16,
            protocol: (t.header.info & 0xffff) as u16,
            handle: u32::from(t.header.handle),
            kind: String::new(),
            name: None,
            prog_id: None,
        };
        for a in &t.attributes {
            match a {
                TcAttribute::Kind(k) => f.kind = k.clone(),
                TcAttribute::Options(opts) => {
                    for o in opts {
                        match o {
                            TcOption::Bpf(TcFilterBpfOption::ProgName(n)) => f.name = Some(n.clone()),
                            TcOption::Bpf(TcFilterBpfOption::ProgId(i)) => f.prog_id = Some(*i),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // a dump also lists the chain heads (handle 0) of each priority
        if f.handle != 0 {
            out.push(f);
        }
    }
    Ok(out)
}

/// Remove exactly this filter from the device's ingress.
pub fn tc_filter_del_exact(ifname: &str, f: &IngressFilter) -> io::Result<()> {
    use netlink_packet_route::tc::{TcHandle, TcMessage};
    let mut m = TcMessage::with_index(index(ifname)? as i32);
    m.header.parent = TcHandle::from(INGRESS_PARENT);
    m.header.handle = TcHandle::from(f.handle);
    m.header.info = ((f.prio as u32) << 16) | f.protocol as u32;
    m.attributes.push(netlink_packet_route::tc::TcAttribute::Kind(f.kind.clone()));
    route(RouteNetlinkMessage::DelTrafficFilter(m), 0).map(|_| ())
}
