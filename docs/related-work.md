<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Related work

What goatrope takes from established practice, where it comes from, and what goatrope adds.
The last table lists practice goatrope does not follow yet; each item there is designed or
proposed, not built.

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
| Namespace topologies for acceptance tests | Linux kernel `tools/testing/selftests/net/` (`rtnetlink.sh`, `forwarding/mirror_gre*.sh`) | `tests/netns`: veth pairs, namespaces, a mirroring switch namespace for ERSPAN, a WireGuard boundary point |

## Not followed yet

| Practice | Source | Status in goatrope |
|---|---|---|
| Forward 802.1X (EAPOL, 01:80:C2:00:00:03) across an inline bridge as well as LLDP: `group_fwd_mask` 0x4008 | Linux bridge source; netdev discussion of LLDP and EAPOL on bridges | Proposed. Inline forwards LLDP only (0x4000); a port that authenticates with 802.1X fails behind the inline tap today |
| Link-state propagation: when one side of an inline bridge loses carrier, take the other side down | Tap vendors' link failure propagation (for example Garland Technology) | Proposed. A Linux bridge does not do it; goatrope would watch carrier over netlink |
| `gretap` (L2GRE) mirrors, for platforms that mirror over plain GRE rather than ERSPAN | iproute2 `ip-link(8)` | Proposed; would reuse the ERSPAN path |
| Cloud traffic mirroring: VXLAN on UDP 4789 (two large clouds) or Geneve (a third) | Cloud providers' traffic-mirroring documentation | Proposed; would reuse the ERSPAN path with a `vxlan` or `geneve` interface |
| Relay: refuse a rule whose destination is a listen address, carry the original sender in a header rather than spoofing it (WireGuard drops a source outside the peer's allowed address), end multicast at each side and cross unicast | WireGuard cryptokey routing; samplicator's `-S` option and its limits | Designed in [ADR 0002](adr/0002-relay.md) as next steps of the relay; not built |
| ASTERIX decoders generated from machine-readable category definitions | github.com/zoranbosnjak/asterix-specs (BSD-3-Clause) | For first-bite, whose pinned `mind` goatrope runs; goatrope itself decodes nothing |
