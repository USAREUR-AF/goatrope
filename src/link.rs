// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Which interfaces a destination leaves through: sysfs for how devices stack, netlink for routes.

use std::collections::BTreeSet;
use std::net::IpAddr;

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

pub const SYS_NET: &str = "/sys/class/net";

/// ifname and every device beneath it: tp0.100 is carried by tp0.
pub fn lowers(ifname: &str) -> BTreeSet<String> {
    fn walk(ifname: &str, depth: u32, out: &mut BTreeSet<String>) {
        out.insert(ifname.to_string());
        if depth > 8 {
            return;
        }
        if let Ok(rd) = std::fs::read_dir(format!("{SYS_NET}/{ifname}")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Some(low) = n.strip_prefix("lower_") {
                    walk(low, depth + 1, out);
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(ifname, 0, &mut out);
    out
}

pub fn ifname_of(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: buf is IF_NAMESIZE bytes, as if_indextoname requires.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: if_indextoname wrote a NUL-terminated name into buf.
    Some(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

/// The device the kernel's route to addr leaves through, as `ip route get` names it.
pub fn route_dev(addr: IpAddr) -> Option<String> {
    let mut msg = RouteMessage::default();
    msg.header.address_family = if addr.is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    msg.header.destination_prefix_length = if addr.is_ipv4() { 32 } else { 128 };
    msg.attributes.push(RouteAttribute::Destination(match addr {
        IpAddr::V4(a) => RouteAddress::Inet(a),
        IpAddr::V6(a) => RouteAddress::Inet6(a),
    }));
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST;
    let mut req = NetlinkMessage::new(header, NetlinkPayload::from(RouteNetlinkMessage::GetRoute(msg)));
    req.finalize();
    let mut buf = vec![0u8; req.buffer_len()];
    req.serialize(&mut buf);

    let mut sock = Socket::new(NETLINK_ROUTE).ok()?;
    sock.bind_auto().ok()?;
    sock.connect(&SocketAddr::new(0, 0)).ok()?;
    sock.send(&buf, 0).ok()?;
    let (data, _) = sock.recv_from_full().ok()?;
    let mut off = 0;
    while off < data.len() {
        let m = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&data[off..]).ok()?;
        let len = m.header.length as usize;
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(r)) = &m.payload {
            for a in &r.attributes {
                if let RouteAttribute::Oif(i) = a {
                    return ifname_of(*i);
                }
            }
        }
        if let NetlinkPayload::Error(_) = m.payload {
            return None;
        }
        if len == 0 {
            break;
        }
        off += (len + 3) & !3;
    }
    None
}

/// The devices a connection to peer uses, down to the physical port: for a link-local
/// peer the scope names the interface; otherwise the route does.
pub fn peer_devices(peer: &str, scope: Option<&str>) -> BTreeSet<String> {
    let Some(ip) = crate::config::parse_ip(peer) else {
        return BTreeSet::new();
    };
    if ip.is_loopback() {
        return ["lo".to_string()].into();
    }
    let link_local = match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
    };
    let dev = match scope {
        Some(s) if link_local => Some(s.to_string()),
        _ => route_dev(ip),
    };
    dev.map(|d| lowers(&d)).unwrap_or_default()
}

// ---------------------------------------------------------------- netlink dumps

fn request(msg: RouteNetlinkMessage, dump: bool) -> Vec<RouteNetlinkMessage> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | if dump { netlink_packet_core::NLM_F_DUMP } else { 0 };
    let mut req = NetlinkMessage::new(header, NetlinkPayload::from(msg));
    req.finalize();
    let mut buf = vec![0u8; req.buffer_len()];
    req.serialize(&mut buf);
    let mut out = Vec::new();
    let Ok(mut sock) = Socket::new(NETLINK_ROUTE) else { return out };
    if sock.bind_auto().is_err() || sock.connect(&SocketAddr::new(0, 0)).is_err() || sock.send(&buf, 0).is_err() {
        return out;
    }
    loop {
        let Ok((data, _)) = sock.recv_from_full() else { return out };
        let mut off = 0;
        while off < data.len() {
            let Ok(m) = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&data[off..]) else { return out };
            let len = m.header.length as usize;
            match m.payload {
                NetlinkPayload::InnerMessage(i) => out.push(i),
                NetlinkPayload::Done(_) | NetlinkPayload::Error(_) => return out,
                _ => {}
            }
            if !dump {
                return out;
            }
            if len == 0 {
                return out;
            }
            off += (len + 3) & !3;
        }
    }
}

fn index_of(ifname: &str) -> Option<u32> {
    let c = std::ffi::CString::new(ifname).ok()?;
    // SAFETY: c is a valid NUL-terminated string.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// The link's kind as `ip -d link` names it ("bridge", "wireguard", "veth"), or None for a plain device.
pub fn kind(ifname: &str) -> Option<String> {
    use netlink_packet_route::link::{LinkAttribute, LinkInfo, LinkMessage};
    let index = index_of(ifname)?;
    let mut m = LinkMessage::default();
    m.header.index = index;
    for r in request(RouteNetlinkMessage::GetLink(m), false) {
        if let RouteNetlinkMessage::NewLink(l) = r {
            for a in &l.attributes {
                if let LinkAttribute::LinkInfo(infos) = a {
                    for i in infos {
                        if let LinkInfo::Kind(k) = i {
                            return Some(k.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Every address on ifname as "address/prefix", as `ip -j addr show dev` lists them.
pub fn addresses(ifname: &str) -> Vec<String> {
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};
    let Some(index) = index_of(ifname) else { return vec![] };
    let mut out = Vec::new();
    for r in request(RouteNetlinkMessage::GetAddress(AddressMessage::default()), true) {
        if let RouteNetlinkMessage::NewAddress(a) = r {
            if a.header.index != index {
                continue;
            }
            let mut local = None;
            let mut address = None;
            for at in &a.attributes {
                match at {
                    AddressAttribute::Local(ip) => local = Some(*ip),
                    AddressAttribute::Address(ip) => address = Some(*ip),
                    _ => {}
                }
            }
            if let Some(ip) = local.or(address) {
                out.push(format!("{ip}/{}", a.header.prefix_len));
            }
        }
    }
    out
}

/// Every device a default route in any table leaves through, ECMP next hops included.
pub fn default_route_devs() -> Vec<String> {
    let mut devs = BTreeSet::new();
    for fam in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut m = RouteMessage::default();
        m.header.address_family = fam;
        for r in request(RouteNetlinkMessage::GetRoute(m), true) {
            if let RouteNetlinkMessage::NewRoute(rt) = r {
                if rt.header.destination_prefix_length != 0 {
                    continue;
                }
                for a in &rt.attributes {
                    match a {
                        RouteAttribute::Oif(i) => {
                            if let Some(n) = ifname_of(*i) {
                                devs.insert(n);
                            }
                        }
                        RouteAttribute::MultiPath(hops) => {
                            for h in hops {
                                if let Some(n) = ifname_of(h.interface_index) {
                                    devs.insert(n);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    devs.into_iter().collect()
}
