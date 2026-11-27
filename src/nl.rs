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
