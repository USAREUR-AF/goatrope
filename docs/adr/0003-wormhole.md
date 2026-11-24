<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0003: The wormhole is an address-level proxy at both ends

| Field | Value |
|---|---|
| Status | Proposed; the smallest case is built as WIP |
| Date | 2026-11-24 |
| Deciders | operator |
| Related | [ADR 0002](0002-relay.md) (the relay and the three shapes), [ADR 0001](0001-goatrope-is-its-own-repository.md) |

## Decision

Several sensor sites and one controller site are far apart. A goatrope machine at each site
makes the controller and the sensors reach each other as though they shared a link: the
controller sees each sensor at an address on the controller's own link, and each sensor sees
the controller at an address on the sensor's own link.

The default shape is ADR 0002's **address-level proxy, at both ends**. Each machine claims,
on its link, the addresses the declaration gives to the far machines, and carries only the
declared protocols and ports between them, through a WireGuard interface that belongs to that
pair. Each end uses only addresses of its own link, so two sensor sites may have the same
subnet and the same sensor address.

The **layer-2 tunnel** is a declared option for one pair, for a controller protocol that
cannot work without it. It is designed below and not built.

| ADR 0002's shape | In the wormhole |
|---|---|
| address-level proxy | the default, at both ends; built for UDP and TCP (WIP) |
| fixed-port forwarder | the mechanism of one rule between the two machines |
| layer-2 tunnel | per pair, by declaration, with the risks below; not built |

## How a packet crosses

```
controller 192.0.2.10                                             sensor 198.51.100.10
   | to 192.0.2.101:6000                                             ^ from 198.51.100.200
   v                                                                 |
[goatrope, controller site]  == WireGuard, this pair only ==>  [goatrope, sensor site]
 claims 192.0.2.101             to its tunnel port 7201         claims 198.51.100.200
```

An `out` rule at one end and an `in` rule at the other name the same tunnel port. The addresses
are rewritten at both ends, and each end knows only its own link: that is the per-pair address
translation that lets subnets overlap. The sender's source port is kept where it is free. A
protocol that carries addresses inside its payload is not rewritten (see *Not decided*).

Nothing is routed. Every datagram and stream passes through a socket one rule opened, as in
the relay, and the machine refuses to run while IP forwarding is on.

## Rules

| Property | Rule |
|---|---|
| Off unless declared | no `[wormhole]`, no wormhole; `wip = true` is required. `goatrope install` adds no unit; it runs in the foreground |
| Default deny | an `out` rule names protocol, the one local machine, the claimed address, the port and the tunnel port. An `in` rule names protocol, tunnel port, the claimed address it sends as, the one local machine and its port. UDP states whether replies cross. Everything else is dropped; what reaches a rule's socket from the wrong machine is counted |
| Direction | a rule carries traffic one machine starts, and replies to it. Traffic the other machine starts needs a rule of its own |
| Authentication | each pair has a WireGuard interface with one peer, allowed one /32. Another allowed address, or a second peer, is refused. The links themselves are not authenticated: a machine on a link that takes the declared machine's address is taken for it |
| Own interface | the link side is a plain interface holding the machine's own address; never a tap port, the tap's bridge, a bridge member, a tunnel or the management interface |
| Never with listen | a listen-mode port can never be the wormhole's link or tunnel (refused at validation). A tap and a wormhole may share a machine, on different ports |
| One role per machine | `[relay]` and `[wormhole]` together are refused for now |

## Claiming an address

- **Probe first.** Three ARP probes one second apart, then two seconds of silence, then the
  announcement (RFC 5227). An answer, or another machine's probe for the same address, means
  the address is not claimed; it is probed again after 60 s.
- **A real machine wins.** ARP from another machine that uses a claimed address makes goatrope
  give it up at once. It does not defend the address.
- **Only while the far end is heard.** Each end sends a heartbeat every second inside the pair's
  tunnel. After 3.5 s of silence the claims of that pair go: ARP stops being answered, TCP
  streams are reset and UDP flows end. Three heartbeats in a row start the probing again. The
  other pairs are not affected.
- **A claim ends by itself.** It is added to the kernel with a 10 s lifetime and renewed every
  3 s, so a killed or hung process stops answering in about 10 s.
- **On one interface.** `net.ipv4.conf.all.arp_ignore` must be 1 or 2, or the kernel would answer
  for a claim on the management interface too.

A claim means the far goatrope machine is heard. It does not mean the far sensor is up: a sensor
that is off looks, at the controller, like a machine that answers ARP and nothing else (UDP gets
no reply; TCP connects and is reset).

## Address plan

| Site | Subnet (example) | Own machine | goatrope | Claims |
|---|---|---|---|---|
| controller | 192.0.2.0/24 | controller .10 | .50 | .101 = sensor 1, .102 = sensor 2 |
| sensor 1 | 198.51.100.0/24 | sensor .10 | .50 | .200 = the controller |
| sensor 2 | 198.51.100.0/24, the same | sensor .10, the same | .50 | .200 = the controller |

Claims must be set aside on each link by whoever assigns addresses there: the probe catches a
machine that is on, not one that is off. A machine at the controller site holds one WireGuard
interface and one set of claims per pair; tunnel ports are per pair and may repeat.

## TCP and UDP

- **UDP** datagrams are sent again whole. One larger than an MTU is fragmented by the kernel of
  the machine that sends it, so no MTU is declared. WireGuard's overhead is 60 bytes over IPv4;
  a path that drops fragments loses large datagrams.
- **TCP** is ended at each goatrope machine: three connections, with a 64 KiB buffer each way
  and half-close carried across. Segment sizes are each leg's own, so there is no MTU problem. A
  local machine's connection opens before the far machine has answered; if the far machine
  refuses, the open connection is reset.
- **Limits:** 256 flows or streams per rule; a UDP flow ends after 120 s idle.
- **Multicast** (not built): an explicit rule naming one group and port, one interface at each
  end, one direction, and a rate limit; the far end sends to the group from its claim, with TTL
  1. No rule forwards broadcast. Discovery that needs broadcast, or answers to the discoverer's
  own address in the payload, needs the layer-2 option.

## Latency, jitter and loss

| Part | Amount |
|---|---|
| goatrope, each time a datagram passes one machine | measured: 28 to 57 us median, 70 to 344 us p99, 2.6 ms highest of 16,000 (amd64, see below) |
| goatrope, a round trip (four passes) | about 0.13 to 0.21 ms |
| the network between the sites, and WireGuard | unchanged; not goatrope's to reduce |
| loss | UDP loss passes through. TCP recovers on the leg that lost it, and the others wait |

The budget belongs to the controller protocol: its timeouts must allow the network's round trip
plus 1 ms. What the controller sees when the network between sites drops: up to 3.5 s in which
UDP is lost and TCP stalls; then ARP for that sensor goes unanswered and its connections are
reset, as when a local machine is unplugged. A neighbor's ARP cache may hold the address for
longer, and frames sent to it are dropped. After the network returns, claims are back in about
7 to 9 s (three heartbeats, then the probe).

## Counters

`/var/lib/goatrope/wormhole-<interface>.health`, every 2 s. Per pair: up, heartbeat round trip
(last and highest), heartbeats lost, times down. Per claim: waiting, probing, held, tunnel down
or the conflicting MAC; conflicts. Per rule: datagrams or streams each way, bytes each way, denied,
not held, errors, source ports that could not be kept, flows refused at the limit.

## The layer-2 option (designed, not built)

For one pair, declared as `layer2 = true` with a reason, when the controller protocol needs
broadcast or multicast discovery, or puts MAC addresses in its messages. The pair's links are
joined by a layer-2 tunnel inside the pair's WireGuard interface.

| Risk | What the option must do |
|---|---|
| Broadcast, ARP, DHCP, spanning tree and neighbor discovery cross between sites | a bridge filter that passes named MAC addresses and EtherTypes only; DHCP, spanning tree and router advertisements always dropped |
| A far machine can claim any address on this link | filter by MAC **and** by the address inside ARP |
| Two sites with the same subnet cannot both be joined to one controller link | refused: at most one layer-2 pair per controller link |
| A loop, where two paths join the same links, floods both | refused when the link has another bridge; a rate limit on flooded frames |
| Frames over the tunnel's MTU are dropped with no notice | the path must carry 1,600 bytes, checked before the tunnel starts |
| Every frame inherits the network's delay and loss | stated; protocols with tight timers fail |
| Default deny is harder | on frames, not sockets; a listen port and a tap's bridge can never join |

## Built (WIP)

`goatrope wormhole --config <file>`; code: [`goatrope/wormhole.py`](../../goatrope/wormhole.py);
examples: `examples/wormhole-controller.toml`, `examples/wormhole-sensor.toml`. Tested in network
namespaces on Ubuntu 24.04 and 26.04 (phase `wormhole`): one controller site, two sensor sites
with the same subnet and the same sensor address, real WireGuard per pair.

| Test | Result on both versions |
|---|---|
| nothing claimed until the far end is heard; three probes before the first announcement | pass |
| UDP to each sensor and its reply; a 4,000-byte datagram; each sensor to the controller | pass; the sensor sees 198.51.100.200 and the sender's own source port |
| TCP, 5 MB to each sensor and 1 MB back | intact, half-close carried |
| another machine, another port, the machine's own address, a routed packet | 0 across, denials counted |
| frames on each link from goatrope | ARP, UDP, TCP and ICMP port-unreachable only |
| 2,000 round trips | none lost |
| a 50 ms network | round trip median 52 to 53 ms, 50 of them the network's |
| the tunnel drops | the claim gone in 3 to 4 s, TCP reset, the other pair unaffected; back 7 to 9 s after it returns |
| a real machine uses a claim, before or after | given up, or never claimed |
| the process killed; stopped; IP forwarding turned on | claim gone in 8 to 11 s; at once; it stops and releases |
| refused declarations and machines | 20 |

Latency was measured with each datagram timestamped entering and leaving each machine, on one
clock, 2,000 datagrams per machine, two runs on each version, in containers on a busy shared amd64
host (load 10 to 17).

Not built: multicast, the layer-2 option, IPv6, a systemd unit, rate limits, more than one
controller machine. Not measured: throughput, a real network, arm64, a Raspberry Pi.

## Not decided: it depends on the controller protocol

| Fact about the protocol | It decides |
|---|---|
| Which protocols and ports, and which side starts each exchange | the rules; whether UDP and TCP are enough |
| Does it carry an IP or MAC address, or a host name, inside its messages? | rewriting per protocol (a codec), or the layer-2 option |
| Does it check the sender's source port, or choose ports while running? | fixed ports, or a helper that reads the negotiation |
| Does it discover machines by broadcast or multicast? Can discovery be replaced by configured addresses? | multicast rules, the layer-2 option, or neither |
| Its timeouts, polling rate and largest acceptable delay and jitter | whether it works over the network at all |
| What each side does when the other disappears and returns | whether 3.5 s is the right silence; whether a short loss should be hidden rather than shown |
| Is it authenticated or encrypted end to end? Does it bind to addresses? | whether addresses can be rewritten, and whether the links need protection |
| May two controllers be connected at once? | failover, and a rule against two sites claiming one sensor |
| Is any of it safety-relevant, such that a lost or late command must be refused? | a limit on age, and commands never queued while the tunnel is down |
| Does it need multicast time or a clock signal from the link? | time must come another way; the wormhole carries none |

Until these are known, a wormhole must not carry commands to real equipment.
