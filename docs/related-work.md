<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Related work

What goatrope takes from established practice, where it comes from, and what goatrope adds.
The comparison with overlay networks follows the first table. The last table lists practice
goatrope does not follow yet; each item there is designed or proposed, not built.

## What goatrope follows

| Practice | Source | In goatrope |
|---|---|---|
| A tap that bridges a link never takes an address and is invisible on the link | Hak5 Packet Squirrel, `TRANSPARENT` network mode (docs.hak5.org); the Raspberry Pi bridge-tap projects (for example github.com/botherder/ntap) | Inline mode: no IPv4 or IPv6 on the bridge or its ports, STP off, LLDP forwarded. New here: install refuses a port that carries an address, a route, the operator's session or any established connection, and `check` re-reads every property |
| Offloads off on capture ports, at every boot | Suricata packet-capture guide (docs.suricata.io); Security Onion; Arkime FAQ (features marked `[fixed]` cannot be changed) | GRO, LRO, TSO and GSO off, and EEE off, by `goatrope-ports.service` at every boot; `check` treats a `[fixed]` feature as the driver's |
| A passive copper tap sees one direction per output and holds the link to 100 Mb/s | Great Scott Gadgets Throwing Star documentation | Listen mode takes two ports for a passive tap's two outputs and requires a declared speed |
| SPAN can drop copies under load; a tap does not | NIST SP 800-82r3, sections 5.2.3.3 and 6.3.2.1; tap and SPAN comparisons by tap vendors (one-sided sources) | [hardware.md](hardware.md) states each source's limits; [three-ways.md](three-ways.md) compares the ways to get a copy |
| The kernel delivers an ERSPAN mirror only to the `erspan` interface whose key equals the session ID | Linux `ip_gre` source; iproute2 `ip-link(8)` | `source = "erspan"`: `session_id` is the key of the interface goatrope makes; another session's mirror is not received (namespace test) |
| A one-peer WireGuard crossing: endpoint as an IP literal, exactly one allowed address, the peer replaced on every apply | WireGuard cryptokey routing (wireguard.com); goatcore `docs/design/simple-boundary-node.md` and role `goat-peering-wg` | The relay's `boundary` transport, set through netlink, checked every 2 s |
| One-way delivery does not depend on a reply | Unidirectional gateway practice (NIST SP 800-82r3, appendix E.1.2) | `udp://` destinations need nothing back; `tcp://` and `http(s)://` do, and are declared as such |
| Claim an IPv4 address on a link only after an ARP probe from 0.0.0.0 finds no other holder; announce it; give it up on a conflict | RFC 5227 (IPv4 Address Conflict Detection), §2.1 to §2.4 and its timing constants | Address proxy (ADR 0004 §4): three probes, a 2 s wait, two announcements; a conflict while probing waits 10 s and probes again, a conflict while held gives the address up (RFC 5227 §2.4 (a)). New here: the address is also held only while the remote's WireGuard handshake is younger than 180 s |
| Answer ARP for an address that stands for a machine across the overlay | ZeroTier 1.14.2 `osdep/Arp.cpp` (answers ARP requests for its local entries, and takes a reply only within 5 s of its own query) and `node/Switch.cpp` (an ARP broadcast becomes a multicast lookup across the overlay) | Address proxy: no ARP crosses the tunnel and goatrope keeps no ARP table of its own; the kernel answers for the proxy address once it is held. ZeroTier answers for its addresses without a conflict probe and whatever the peer's state; goatrope probes first and withdraws the address when the tunnel is stale, so machines on the link stop resolving a dead path. Only the conflict check reads incoming ARP, and only frames sent by another machine |
| Bridging is off unless a member is approved as a bridge; a member's frame from any other source MAC is dropped | ZeroTier 1.14.2, `node/Switch.cpp` (`onLocalEthernet`, "not a bridge") and `node/IncomingPacket.cpp` (`_doEXT_FRAME`, "bridging not allowed") | The layer-2 lane exists only with `accept_layer2 = true`. New here: from the tunnel only the declared source MACs pass, not any MAC behind an approved bridge, and ARP only when its sender hardware address is that MAC; a frame from this link looped back by the far side's bridge is dropped, since its source is not declared there |
| A rule set that matches EtherType and MAC and ends in drop | ZeroTier 1.14.2, `node/Network.cpp` (`_doZtFilter`), `rule-compiler/rule-compiler.js` and its example rule set (`drop not ethertype 0x0800 not ethertype 0x0806 not ethertype 0x86dd`) | tc flower in the kernel at both lane ends, on the ingress of both bridge members, then a matchall drop that counts; each filter carries a cookie, and the relay stops when one is removed or replaced |
| A virtual Ethernet MTU above the path MTU, fragmented underneath | ZeroTier 1.14.2, `node/Constants.hpp` (`ZT_DEFAULT_MTU` 2800) and `include/ZeroTierOne.h` (`ZT_DEFAULT_PHYSMTU` 1432), with ZeroTier's own packet fragmentation | GRETAP MTU 1500 with `nopmtudisc` and `ignore-df`: the kernel fragments the outer IPv4 packet and WireGuard carries the fragments; goatrope has no fragmentation code |
| Namespace topologies for acceptance tests | Linux kernel `tools/testing/selftests/net/` (`rtnetlink.sh`, `forwarding/mirror_gre*.sh`) | `tests/netns`: veth pairs, namespaces, a mirroring switch namespace for ERSPAN, a WireGuard boundary point |

## Overlay networks compared

An overlay network such as ZeroTier makes distant machines members of one virtual Ethernet
segment. goatrope does not try to be one: in a goat deployment a WireGuard mesh (NetBird) gives
the machines their addresses, keys and paths, and goatrope adds what the mesh does not do for a
sensor link. The table sets ZeroTier 1.14.2, read from its source, against goatrope with such a
mesh, job by job. Each goatrope entry has the status it has on `main`, and the measured figures
come from the namespace phases in [ADR 0004](adr/0004-relay-1-0.md) (Validation) and from
[performance.md](performance.md).

| Job | ZeroTier 1.14.2 | goatrope with a WireGuard mesh | Where goatrope does more, or less |
|---|---|---|---|
| Membership, addresses, keys, NAT traversal | Its own controller and root servers; members are admitted by the controller (`controller/`, `node/Topology.cpp`) | The mesh's job (NetBird). goatrope holds no peer keys; with `transport = "boundary"` it runs one WireGuard interface with one declared peer | Less: goatrope has no controller and admits no one. A peer's identity is whatever the mesh authenticated |
| Encryption | Its own protocol: Curve25519 identities, Salsa20/12 with Poly1305, or AES-GMAC-SIV (`node/Packet.hpp`) | WireGuard, the mesh's or goatrope's boundary interface | Neither adds cryptography; goatrope depends on WireGuard's |
| Default policy | A network created without rules accepts every frame, "a flat L2 segment" (`controller/DB.cpp`) | Default deny: the relay forwards only the ports, directions and peers its rules name, and refuses to start while IP forwarding would route around them | More: nothing crosses that the declaration does not name |
| Getting a copy of a link that is not on the overlay | Not a ZeroTier function | A tap device, a mirror port, ERSPAN or goatrope's own inline tap, recorded and decoded on the machine; listen ports drop every outgoing frame | More: this is goatrope's main role. Less: a process with `CAP_NET_RAW` can get past the listen drop |
| Port-level forwarding to a machine on a link | Rules can match ports, but traffic is bridged or routed between members | The relay: UDP and TCP rules in either direction, sent from the relay's own address, with `max_connections` and keepalive bounds | More: a machine on the link needs no client and no route; it sees one local address |
| A remote machine under a local address | Managed IPs on the virtual network; `osdep/Arp.cpp` answers ARP for its own entries | `[[relay.proxy]]`: an RFC 5227 probe before the address is taken; held only while the peer's WireGuard handshake is younger than 180 s (removed 180.6 and 181.1 s after the last handshake, measured) | More: no address is taken that another machine holds, and none is held for a dead path |
| Layer-2 bridging | Every member is on the segment; a member may bridge other MACs only when the controller marks it `activeBridge` (`node/Switch.cpp`, `node/IncomingPacket.cpp`) | `[[relay.l2]]`, accepted by name: one port to one peer over GRETAP, only the declared EtherTypes, and from the tunnel only the declared source MACs (ARP only with a matching sender address); the rest dropped and counted | More: a named list of source MACs, not any MAC behind a bridge. Less: one peer per lane, IPv4 tunnel addresses only, and no segment with many members |
| Frame filtering | A rule engine evaluated on sender and receiver: EtherType, MAC, IP, ports, tags, capabilities (`node/Network.cpp`, `rule-compiler/`) | tc flower in the kernel at both lane ends, a final matchall drop, a cookie on every filter; the relay stops when one is removed or changed | Less: EtherType and source MAC only. More: a tampered filter stops the relay |
| Full-size frames over a smaller path | A 2,800-byte virtual MTU over a 1,432-byte physical one, with ZeroTier's own fragmentation (`node/Constants.hpp`, `include/ZeroTierOne.h`) | GRETAP MTU 1,500 with outer fragmentation (`nopmtudisc`, `ignore-df`); the kernel fragments and WireGuard carries the fragments. A 1,472-byte ping with DF set crossed 10 of 10 over WireGuard MTU 1,280 (measured) | Equal for 1,500-byte frames; goatrope carries no frames above 1,500 bytes |
| Following a path that has died | Peer and path timeouts (`ZT_PEER_ACTIVITY_TIMEOUT`, `ZT_PATH_HEARTBEAT_PERIOD`) | The lane and the proxy address follow the WireGuard handshake: the lane went down 180.6 to 182.8 s after the last one in namespaces and 182.0 s in the emulated arm64 VM, and came back within 1 s of a fresh one (2.2 s in the VM) (measured) | More for the link side: the proxy address is withdrawn and the lane closed, so machines on the link stop sending into a dead path |
| Multicast | Multicast groups with a per-network recipient limit (`multicastLimit`, 32 by default) and broadcast on by default (`node/Multicaster.cpp`, `controller/DB.cpp`) | Designed (ADR 0004 §3), not built. On the lane, multicast and broadcast cross only within the declared EtherTypes and MACs | Less, until it is built |
| Copying frames to an observer | Rule actions `TEE` and `WATCH` send a copy of a frame to another member (`include/ZeroTierOne.h`) | `[[tap.mirror]]` (ADR 0004 §5): designed, not built. Its kernel path, tc `mirred` to an ERSPAN interface over WireGuard, mirrored 85,397 to 238,555 frames a second with none lost (measured) | Less, until it is built |
| Platforms | Linux, macOS, Windows and the BSDs (`osdep/*EthernetTap*`), and an Android binding (`java/`) | Ubuntu 24.04 and 26.04 on amd64 and arm64; phones and desktops reach it as mesh peers | Less: goatrope runs only on the machine at the link |

## Not followed yet

| Practice | Source | Status in goatrope |
|---|---|---|
| Forward 802.1X (EAPOL, 01:80:C2:00:00:03) across an inline bridge as well as LLDP: `group_fwd_mask` 0x4008 | Linux bridge source; netdev discussion of LLDP and EAPOL on bridges | Proposed. Inline forwards LLDP only (0x4000); a port that authenticates with 802.1X fails behind the inline tap today |
| Link-state propagation: when one side of an inline bridge loses carrier, take the other side down | Tap vendors' link failure propagation (for example Garland Technology) | Proposed. A Linux bridge does not do it; goatrope would watch carrier over netlink |
| `gretap` (L2GRE) mirrors, for platforms that mirror over plain GRE rather than ERSPAN | iproute2 `ip-link(8)` | Proposed; would reuse the ERSPAN path |
| Cloud traffic mirroring: VXLAN on UDP 4789 (two large clouds) or Geneve (a third) | Cloud providers' traffic-mirroring documentation | Proposed; would reuse the ERSPAN path with a `vxlan` or `geneve` interface |
| Relay: refuse a rule whose destination is a listen address, carry the original sender in a header rather than spoofing it (WireGuard drops a source outside the peer's allowed address), end multicast at each side and cross unicast | WireGuard cryptokey routing; samplicator's `-S` option and its limits | Designed in [ADR 0002](adr/0002-relay.md) as next steps of the relay; not built |
| ASTERIX decoders generated from machine-readable category definitions | github.com/zoranbosnjak/asterix-specs (BSD-3-Clause) | For first-bite, whose pinned `mind` goatrope runs; goatrope itself decodes nothing |
