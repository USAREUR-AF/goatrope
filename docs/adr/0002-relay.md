<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0002: The relay is a default-deny, fixed-port forwarder through WireGuard

| Field | Value |
|---|---|
| Status | Proposed; amended by [ADR 0004](0004-relay-1-0.md), which takes the relay to 1.0 |
| Date | 2026-11-24 |
| Deciders | operator |
| Related | [ADR 0001](0001-goatrope-is-its-own-repository.md) |

## Decision

The relay lets a remote machine exchange traffic with named machines on a local
link as though it were there, for an explicit list of addresses, ports and
directions, and nothing else. It is a separate role from the tap: it is off unless
the declaration has a `[relay]` table, it transmits on the link from an interface
and address of its own, and it never shares a port with a listen-mode tap.

Of the three shapes compared below, goatrope uses the **fixed-port forwarder**:
the remote machine authenticates through WireGuard, each allow rule maps one
tunnel port to one address and port on the link, and replies return only from that
target. The address-level proxy is the next step if a remote machine must appear
under a local address. The encrypted layer-2 tunnel is not used.

## The three shapes

**Encrypted layer-2 tunnel.** The remote machine's frames are carried in an
encrypted tunnel (for example VXLAN or GRETAP inside WireGuard) and bridged onto
the link, so it appears as one more Ethernet host.

- Broadcast and multicast cross in both directions, ARP included, so the remote
  machine can discover and be discovered.
- It brings the remote machine's whole stack onto the link: its ARP, its IPv6
  neighbor discovery, its DHCP client, anything it broadcasts. A misconfigured or
  compromised remote machine can claim any address on the link.
- The link inherits the tunnel's latency, jitter and loss for every frame,
  including ARP. Protocols with tight timers (spanning tree, some industrial
  protocols) can fail.
- MTU: the tunnel adds 50 to 80 bytes. Either the link's frames are fragmented
  (layer-2 tunnels do not fragment by themselves, so large frames are dropped) or
  the tunnel's path must carry over 1,580 bytes.
- When the tunnel drops, the remote "host" vanishes from the link with no notice;
  the local machines time out on their own schedules.
- Default deny is hard: filtering must be done on frames, by MAC and EtherType and
  then by IP, in a bridge filter.
- It is the shape that most easily bridges a whole private network onto the link
  by mistake: one wrong bridge membership on the remote side does it.

**Address-level proxy.** The relay holds a local address for each remote machine
and answers ARP for it (proxy ARP); IP packets to that address are routed through
the tunnel and back, with the source address preserved.

- Local machines see a normal host at a local address; the remote machine keeps
  its own addressing behind the tunnel.
- No broadcast or multicast crosses unless forwarded on purpose.
- ARP: the relay answers for addresses it is told to own. If the address is also
  used by a real local machine, two machines claim it and traffic splits between
  them. The relay must check before claiming (an ARP probe, RFC 5227) and must stop
  answering when the tunnel is down, or local machines keep sending into a dead
  path.
- MTU: routed, so the relay can fragment or send ICMP "packet too big"; the tunnel
  overhead lowers the path MTU by about 80 bytes.
- Latency and loss of the tunnel apply only to the proxied traffic.
- Default deny is ordinary routing plus a firewall table keyed by address, port
  and direction.

**Fixed-port forwarder.** The relay has one local address of its own. Each allow
rule maps a port on the tunnel side to one address and port on the link. The relay
receives a datagram from the authenticated remote machine and sends it again from
its own address; replies from that target go back to the remote machine.

- Nothing crosses that a rule does not name. No broadcast, multicast or ARP is
  forwarded; the relay answers ARP only for its own address, as any host does.
- Source addresses change: local machines see the relay's address, not the remote
  machine's. A protocol that checks or embeds the sender's address needs the
  address-level proxy.
- No address can be claimed twice, because the relay claims only its own.
- MTU: datagrams are re-sent, not encapsulated; a datagram larger than the link
  MTU is fragmented by the relay's own stack.
- Tunnel loss: forwarding stops and the relay keeps its address; local machines
  see a host that stops sending. Replies sent while the tunnel is down are
  dropped and counted.
- Latency added is the tunnel's plus one user-space hop.

## Transport: the existing mesh, or a dedicated tunnel to a boundary point

The relay always reaches the remote side through WireGuard. A declaration picks one
of two transports with `[relay].transport`.

**`mesh` (the default): the WireGuard the site already runs.** goatrope creates no
tunnel. `remote_interface` names a WireGuard interface that already exists.

- In a deployment that runs a WireGuard mesh between its sites (a NetBird mesh, whose
  interface is a kernel WireGuard device, usually `wt0`), the relay uses that
  interface. The controller and the relay are both peers of the mesh. The mesh
  authenticates each peer by its key and assigns its address, so a rule's `remote`
  names a peer the mesh admitted. The mesh's own access policy decides which peers
  may reach the relay at all; the relay's rules then narrow that to named ports,
  targets and directions. Peers, keys and access stay with the mesh's owner; goatrope
  holds none of them.
- With no mesh (goatrope used on its own), the operator brings up a WireGuard
  interface with the usual tools and names it.
- A mesh client that runs WireGuard in user space presents a TUN device, not a
  WireGuard interface. The relay refuses it, because it cannot then tell that the
  source address inside the tunnel was authenticated.

**`boundary`: a dedicated tunnel to one declared boundary point.** For a site that
must be treated as outside the deployment, because it cannot run the mesh
(technology) or may not join it (policy), and is reached only through a boundary
point specified for that crossing. goatrope runs a WireGuard interface of its own,
separate from the mesh, with exactly one peer: the boundary point.

- `[relay.boundary]` fixes the tunnel: the boundary point's public key, its endpoint
  (an address and a port, never a name), its single tunnel address, this end's tunnel
  address, the listen port (never 51820, the mesh's port), the private key file and,
  where policy asks for one, a preshared key file.
- Every allow rule's `remote` is the boundary point's tunnel address. The interface
  accepts nothing else: its one peer may send only from that address (WireGuard's
  allowed addresses are that one /32 or /128).
- Before the relay starts, and every two seconds while it runs, the interface is
  checked against the declaration: one peer, that key, that endpoint, that one
  allowed address, that listen port, the key derived from the declared file, the
  declared keepalive and preshared key, and this end's address. A difference refuses
  the start, or stops the relay.
- The private key is made on the machine (`goatrope boundary key`, mode 600, never
  replaced by goatrope) and never leaves it. Only public keys are exchanged, out of
  band; `goatrope boundary sheet` prints what the boundary point's operator needs.
- The relay makes the interface when it is absent; `goatrope boundary up` and `down`
  do it by hand. Other tooling may make it instead; goatrope then only checks it.
- This is the same shape goat uses for its own dedicated crossings (one interface,
  one peer, one allowed address, a listen port that is not the mesh's), so a goat
  deployment's boundary point and goatrope's interface pair with each other.
- `examples/relay-boundary.toml` is this case.

**Several sensor sites and one controller site.** One relay runs at each sensor
site, on that site's mesh peer. The controller reaches each sensor at the mesh
address of that site's relay and a port. Sensor sites may reuse the same link
addresses, because the controller never sees them: it sees one mesh address per
site. A sensor that answers whatever address last spoke to it sees the relay's link
address and answers the relay, which returns the datagram to the controller
(direction `both`). `examples/relay-over-mesh.toml` is this case. No address-level
proxy, layer-2 tunnel or second tunnel is needed for a protocol of this kind.

## What the relay requires and refuses

| Property | Rule |
|---|---|
| Off unless declared | no `[relay]` table, no relay; `wip = true` is required while it is WIP |
| Remote authentication | the remote side is a WireGuard interface: an existing one (`mesh`: the site mesh's, or one the operator made) or goatrope's own with exactly one peer that matches `[relay.boundary]` (`boundary`); see Transport. WireGuard authenticates each peer by its key and accepts from a peer only the tunnel addresses listed for it, so the source address inside the tunnel names an authenticated machine. A rule names that address |
| Default deny | each rule names direction, protocol, remote tunnel address, tunnel port, target address and target port; everything else is dropped and counted |
| Directions | `remote-to-link`, or `both`: replies are accepted only from the rule's target address and port, and go only to the remote machine that last used the rule |
| Its own interface | the link side is a plain interface holding the declared address; never a tap port, the tap's bridge, a bridge member or a tunnel |
| Never with listen | a listen-mode port can never be a relay interface (refused at validation) |
| Nothing else sent | IPv6 must be off on the link interface when the relay's address is IPv4; otherwise the kernel sends neighbor discovery and MLD frames |
| No network bridged | no layer-2 forwarding and no routing between the tunnel and the link; only the listed datagrams are re-sent. The relay refuses to start, and stops, while IP forwarding is on for either interface (or IPv6 forwarding globally): the kernel would route between them around the rules |
| One machine per rule | a target that is the relay's own address, the link's network or broadcast address, or a multicast address is refused |
| Send errors | a datagram the relay cannot send (tunnel down, peer without an endpoint) is dropped and counted in `send_errors`; the relay keeps running |
| Replies | replies are accepted from the rule's target address and port. A machine on the link that sends from that address and port to the relay's port is relayed as the target would be: the link is not authenticated, only the tunnel is |
| Boundary interface | with `boundary`: one peer, the declared key, endpoint, single allowed address and listen port (not 51820); private key file owned by root, mode 600; checked at start and every two seconds, the relay stops on a difference; a name that exists and is not WireGuard is refused |
| Logging | one line per rule at start; denied datagrams logged at most every 10 s; counters per rule in `/var/lib/goatrope/relay.health` |

## Built (WIP)

`goatrope relay --config <file>` runs the fixed-port forwarder for UDP in the
foreground. `goatrope install` installs no relay unit, so a relay runs only while
someone runs it. Code: [`src/relay.rs`](../../src/relay.rs).

Tested in network namespaces on Ubuntu 24.04 and 26.04 (`tests/netns`, phase
`relay`), with real WireGuard interfaces between a "remote" namespace and the relay
and a veth to a "link" namespace:

| Test | Result on both versions |
|---|---|
| 20 datagrams from the allowed tunnel address reach the one target, from the relay's address | 20 of 20 |
| replies from the target return to the remote machine (`both`) | 20 of 20 |
| a `remote-to-link` rule forwards | 5 of 5 |
| a tunnel port with no rule | 0 forwarded |
| an authenticated peer that is not the rule's remote | denied, logged |
| datagrams from outside the tunnel to the relay port | 0 forwarded |
| frames sent on the link | only ARP and the allowed datagrams |
| refusals: remote side not WireGuard; link interface without the declared address; a target off the link; a broadcast target; IPv6 on the link interface; IP forwarding on | each refused, exit 2 |
| a reply that cannot be sent (the remote peer removed from the WireGuard interface) | counted; the relay keeps running |
| IP forwarding turned on while it runs | the relay stops, exit 1 |

Boundary transport, in the same namespaces, against a "boundary point" namespace
with its own WireGuard interface (phase `boundary`):

| Test | Result |
|---|---|
| `goatrope boundary key` writes a mode-600 key, prints only the public key, refuses to replace it | as stated |
| the relay makes its interface when absent; datagrams from the boundary point reach the target, replies return | 10 of 10 |
| a second peer added while it runs | the relay stops, exit 1 |
| allowed addresses widened; another endpoint; another listen port; a key file others can read | each a difference (`check` exit 3) and a refused start (exit 2) |
| `down` removes the interface; `up` makes it again | as stated |
| refusals at validation: listen port 51820; a rule whose remote is not the boundary point; an endpoint given as a name | each refused, exit 2 |

Not built: TCP, the address-level proxy, a systemd unit, IPv6 targets beyond
parsing, and rate limits per rule. Not measured: latency, loss and throughput
through a real tunnel and link.

## Open

1. Which protocols a first real use needs (UDP only, or TCP too), and whether any
   of them checks the sender's address, which decides between this forwarder and
   the address-level proxy.
2. Where a relay runs on a Pi with two USB ports used by the tap: the relay needs a
   third link-side port, or a machine of its own.
