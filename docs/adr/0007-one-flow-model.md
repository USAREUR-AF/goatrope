<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0007: One flow model: every path through goatrope is a flow with a source, a destination, a filter, a transform and a carriage

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-28 |
| Deciders | operator |
| Owner | `goat-owners` |
| Related | [ADR 0002](0002-relay.md), [ADR 0004](0004-relay-1-0.md), [ADR 0006](0006-data-path.md); goatcore ADR 1260 (every tactical link in one registry with one health record) and ADR 1266 (a tactical data chain judged hop by hop); issues #55, #33, #41, #48, #49, #54, #56, #57, #58; #21 items 10 and 12 |

## Decision

Everything goatrope does to traffic is a **flow**. A flow takes traffic from one place,
lets through only what its filter names, may change it, and delivers it to one or more
places, carried in a stated way. The eight tables the declaration has today are eight
spellings of that one idea. They become shorthands that the parser turns into flows, and a
new declaration form, schema 2, writes flows directly.

| Part | Says | Examples |
|---|---|---|
| **source** (`from`) | where the traffic enters goatrope, and how it is authenticated | a copy from a tap port; a machine on the link; a mesh peer; a dedicated port's frames |
| **destination** (`to`) | where it leaves: one place or several | a recording ring; a UDP, TCP, HTTP or file destination; a machine on the link; a mesh peer; a collector |
| **filter** | what is let through; everything else is dropped and counted | a BPF expression; protocol and ports; the link hosts allowed; EtherTypes and source MACs |
| **transform** | what goatrope changes on the way, if anything | none; convert with the linked engine; decode with a pinned first-bite decoder; appear on the link under a proxy address; copy to every member of a group |
| **carriage** | how the bytes cross, chosen from source and destination and declared only where there is a choice | a relay socket (user space) or the kernel path; ERSPAN; GRETAP; a capture ring; the inline bridge |

Every flow also has a **name**, which is its identity in `check`, `status`, its health record
and the goat link registry; **replies** (whether traffic may come back from the
destination to the source); **limits**; and the **acceptances** the operator gives by name
(`layer2`, `routed_remote`, `kernel_bypasses_netfilter`).

The roles stay what they are. The tap, decode-and-send and the relay are the programs that
carry flows; a flow says what a program carries. No capability is added or removed by this
ADR, and no refusal is weakened: the same mistakes are refused, in the same words wherever
they appear.

## Why

The declaration grew one table per feature, and each table names the same things in its own
words (#55):

| The same thing | is called |
|---|---|
| the machine at the far end of the tunnel | `remote` in a relay rule, `peer` in a lane, `peer_address` in `[relay.boundary]`, `remote` in a mirror |
| goatrope's own address on a side | `link_address` on the relay, `local` in a lane and a mirror, `address` in a boundary |
| who may send | `remote`, `sources` or `macs` |
| what is let through | a BPF `filter`, a `match` table, `ethertypes`, a `listen_port` |

Each table has its own validation code in `src/config.rs` (1,618 lines). One mistake gets
different wording in different tables, and a fix to one table's checks does not reach the
others. Some requirements belong to one part of the relay but are imposed on all of it: a
relay that runs only a layer-2 lane must still declare a link interface, a link address and
a fixed-port rule it never uses (#33). And one process supervises every part as a unit, so a
changed filter on one lane stops every UDP and TCP rule (#54).

goatcore ADR 1260 makes every tactical link at a site report one health record and appear in
one registry; ADR 1266 judges a data chain hop by hop. goatrope's paths are such links and
hops. A path that has a name, a source and a destination maps onto a registry row and a chain
hop directly; a path that is an implicit consequence of three tables does not.

## The flow

### Sources

| Source | Written | Authentication | Today's spelling |
|---|---|---|---|
| a copy of a link, receive only | `tap:<port>` (one or two ports; inline: the bridge port that sees both directions) | none needed: goatrope never sends on it | `[tap]` listen or inline, `[tap.record].ports`, `[[send]].port`, `[[decode]].ports`, `[[tap.mirror]].ports` |
| an ERSPAN mirror arriving on an address of this machine | `erspan:<session>` with `underlay`, `local`, `remote` | the session's key and the sender's address | `[tap]` `source = "erspan"`, `[tap.erspan]` |
| a machine on the link that sends first | `link:<address>` (one or a list) at `local:<port>` | none: the link is not authenticated, so the list is the control; an optional MAC per address (#49) | a `link-to-remote` rule's `sources` and `listen_port` |
| a mesh peer that sends first | `peer:<address>` at `local:<port>` over a transport | WireGuard: the peer that owns the address, allowed exactly that address unless `routed_remote` is accepted (#41) | a `remote-to-link` or `both` rule's `remote` and `listen_port` |
| the frames of a dedicated port | `port:<ifname>` | none on the port; the filter is the control | `[[relay.l2]].port` |
| the frames of a mesh peer's lane | `peer-l2:<address>` over a transport | WireGuard, plus the declared source MACs | `[[relay.l2]].peer` |

### Destinations

| Destination | Written | Today's spelling |
|---|---|---|
| a bounded recording ring | `ring` with `files`, `file_mb`, `directory` | `[tap.record]` |
| a UDP, TCP, HTTP(S) or file destination | `udp://...`, `tcp://...`, `http(s)://...`, `file:///var/lib/goatrope/send/...` | `[[send]].to` |
| a pinned decoder's own outputs | `component:<sha256>` (the decoder's sinks are its own) | `[[decode]]` |
| a machine on the link | `link:<address>:<port>`, or a group `link:<group>:<port>` with `ttl` | a rule's `target` and `target_port`; a multicast `target` |
| a mesh peer | `peer:<address>:<port>` (one or a list) over a transport | a `link-to-remote` rule's `remote` and `remote_port`; a multicast rule's list of remotes |
| a collector | `collector:<address>` over a transport, with `session` | `[[tap.mirror]]` `remote` and `session_id` |
| the other end of a lane | `peer-l2:<address>` over a transport, with `key` | `[[relay.l2]]` `peer` and `key` |
| the inline bridge's other port | `tap:<port>` | `[tap]` inline (the link passing through the machine) |

### Filters

| Filter | Applies to | Today's spelling |
|---|---|---|
| `bpf = "<expression>"`, compiled by tcpdump | copies of a link | `[tap.record].filter`, `[[tap.mirror]].filter`, `[[decode]].filter` |
| `protocol`, `src`, `dst`, `src_port`, `dst_port` | datagrams taken from a copy | `[[send]].match` |
| `protocol` and the source's and destination's ports | relayed datagrams and connections | a rule's `protocol`, `listen_port`, `target_port`, `remote_port` |
| `ethertypes`, `macs` (and per MAC, optionally, `ips`, #49) | layer-2 frames | `[[relay.l2]]` |

A filter is always a list of what passes. Nothing is let through by default, and what is
dropped is counted per flow.

### Transforms

| Transform | Today's spelling |
|---|---|
| none: the bytes as they arrived (a recording, a mirror, a lane, a send without `convert`) | (the absence of the others) |
| `convert` with the linked engine, pinned by `packs_sha256` | `[[send]].convert` |
| `decode` with a first-bite decoder, pinned by `sha256` | `[[decode]]` |
| relay: the datagram or connection is re-sent from goatrope's own address on the destination side | every relay rule |
| `appear_as = <address>`: on the link, from a proxy address that stands for the peer | `[[relay.proxy]]` and a rule's `link_address` |
| `fanout`: one copy to every listed peer | a multicast `link-to-remote` rule with a list of remotes |

### Carriages

goatrope chooses the carriage from the source and the destination; a declaration names it only
where ADR 0006 leaves a choice.

| Carriage | Used for | Choice |
|---|---|---|
| capture ring and recorder | a recording | none |
| capture and a sender per destination | decode-and-send | none |
| relay socket, batched, in user space | relay UDP and TCP | the default |
| relay kernel path (tc, `bpf_redirect_neigh`) | relay UDP `remote-to-link` | `carry = "kernel"`, with `kernel_bypasses_netfilter` accepted where netfilter would see it (ADR 0006) |
| ERSPAN type II | a remote mirror | none |
| GRETAP in a bridge | a layer-2 lane | none |
| the inline bridge | the link through an inline tap | none |

### Transports

The tunnel a flow's mesh end uses is declared once and named, because several flows share
it:

| Transport | Written | Today's spelling |
|---|---|---|
| an existing WireGuard interface (the mesh) | `[transport.<name>] kind = "mesh", interface = "wt0"` | `[relay] transport = "mesh"`, `remote_interface` |
| goatrope's own WireGuard interface with one peer | `[transport.<name>] kind = "boundary"` and the keys of today's `[relay.boundary]` | `[relay] transport = "boundary"`, `[relay.boundary]` |

goatrope's own place on the link, today `link_interface` and `link_address`, becomes
`[link] interface` and `address`. It is required only when a flow has a `link:` source or
destination (#33).

## Each table, as flows

| Today | Becomes |
|---|---|
| `[tap]` inline, `[tap.record]` | two flows: `tap:A` to `tap:B` and back over the inline bridge (the link itself, fail-closed), and `tap:A` to `ring`, filtered by `[tap.record].filter` |
| `[tap]` listen (copper tap, mirror port, bypass relay) and `[tap.record]` | one flow per recorded port: `tap:<port>` to `ring` |
| `[tap]` listen with `source = "erspan"` and `[tap.erspan]` | the source `erspan:<session>`; the recording is a flow from it to `ring` |
| `[[send]]` | `tap:<port>` to each `to`, filtered by `match`, transformed by `convert` when present |
| `[[decode]]` | `tap:<ports>` to `component:<sha256>`, filtered by `filter`, transformed by `decode` |
| `[relay].allow`, `remote-to-link` | `peer:<remote>` at `local:<listen_port>` to `link:<target>:<target_port>`, no replies |
| `[relay].allow`, `both` (UDP) | the same, with replies from the target only |
| `[relay].allow`, `link-to-remote` | `link:<sources>` at `local:<listen_port>` to `peer:<remote>:<remote_port>`, replies from the peer only |
| a TCP rule | the same flows; for TCP, `from` is the side that opens the connection, and replies are the connection's other direction |
| a multicast `target` / `group` (#60) | `to = link:<group>:<port>` with `ttl`; or `from = link:<sources>` at the group, `to` a list of peers, `fanout` |
| `[[relay.proxy]]` and a rule's `link_address` | `appear_as = <address>` on that rule's flow; the proxy's probing and holding are unchanged |
| `[[relay.l2]]` | one flow `port:<port>` to `peer-l2:<peer>`, replies (the other direction), filtered by `ethertypes` and `macs`, accepted with `layer2` |
| `[[tap.mirror]]` (#24) | `tap:<ports>` to `collector:<remote>` over a transport, filtered by `bpf`, carried as ERSPAN |
| `[relay.boundary]` | a transport, not a flow |
| `[relay]` `kernel_path` (#35) | `carry = "kernel"` on the flows it applies to |

## The declaration, schema 2

A declaration with `schema = 2` writes flows. These are some of today's examples in it; the
values are documentation values.

```toml
schema = 2

[transport.mesh]
kind = "mesh"
interface = "wt0"

[link]
interface = "eth1"
address = "192.0.2.50/24"

# a controller on the mesh sends to a sensor on the link; the sensor's replies go back
[[flow]]
name = "sensor-control"
from = { peer = "203.0.113.20", via = "mesh", protocol = "udp", port = 40000 }
to = { link = "192.0.2.10", port = 40000 }
replies = true

# a machine on the link opens TCP connections to a mesh peer
[[flow]]
name = "upload"
from = { link = ["192.0.2.10"], protocol = "tcp", port = 7300 }
to = { peer = "203.0.113.20", via = "mesh", port = 7300 }
max_connections = 16

# one dedicated port bridged to one peer, accepted by name
[[flow]]
name = "lane0"
from = { port = "eth2" }
to = { peer_l2 = "203.0.113.21", via = "mesh", key = 4242, local = "203.0.113.20" }
filter = { ethertypes = ["0x0806", "0x0800"], macs = ["02:00:00:00:b0:01"] }
replies = true
accept = ["layer2"]

# a copy of a link, decoded datagrams sent to a mesh address
[[flow]]
name = "feed-a"
from = { tap = "enxPORTA" }
filter = { protocol = "udp", src = "192.0.2.10", dst_port = 5000 }
transform = { convert = { version = "0.8.0", from = "remote-id", to = "cot-xml", packs = "/opt/packs", packs_sha256 = "..." } }
to = ["udp://203.0.113.30:9000"]
```

The lane above declares no `[link]` rule it does not use (#33). The tap itself (mode, ports,
management interface, speed) keeps its own table, `[tap]`: it describes the machine's ports,
not a path, and every tap flow names its port.

## How the old tables stay accepted

- **Two schemas, one model.** `schema = 1` (today's tables) and `schema = 2` (flows) both
  parse into the same flows inside goatrope. Every role runs flows, so the two schemas cannot
  behave differently. A file is one schema or the other, never a mix.
- **Same refusals, same words.** Each refusal belongs to the part of the flow it is about (a
  source, a destination, a filter), and is worded once. A schema 1 table that breaks it gets
  the same refusal, with the table's own key named in it so the operator can find the line.
- **A printer, not a migration tool that edits files.** `goatrope validate --flows` prints
  the schema 2 form of any valid declaration, so an operator can move a file by hand and
  compare. `check` and `status` show the flows either way.
- **For how long.** Schema 1 is accepted for every 1.x release. 1.0 documents schema 2 as the
  form to write, and the examples move to it. From the first 1.x release after schema 2 ships,
  `validate` prints one notice that the file uses schema 1. Removing schema 1 is a 2.0 change
  and needs its own ADR. No date is set here.
- **The installed state does not depend on the schema.** The state file records flows by
  name, so changing a file from schema 1 to schema 2 with the same paths and the same names
  is not a change to the machine. Names come from the table for schema 1: `send-<name>`,
  `decode-<name>`, `relay-<protocol>-<listen_port>`, `lane-<name>`, `mirror-<session>`,
  `record-<port>`, `inline`.

## What check and status show per flow

Every flow gets one block, in the order declared, after the machine-wide items (the OS, the
tap ports' settings, IP forwarding, the relay's link filter, the watchdog).

| | Shows |
|---|---|
| `status` | `flow <name>`: from, to, filter and transform in one line of words; its state; and since the process started: received, passed, dropped by the filter, converted, sent per destination, failed, the time of the last message and the last error |
| `check` | `flow:<name>:<part>` items: what carries it is running (its unit, its socket, its tc filters or interfaces), and each part as declared. A difference names the flow |
| `check --json` | the same items with the flow name as a field, for the deploy play and the goat registry |

A flow's state is one of:

| State | Means |
|---|---|
| `flowing` | it carried something in the last 60 s |
| `idle` | it is ready and nothing came; for a source that is often quiet, normal |
| `waiting` | an interface, address or peer it needs is not there yet (as the relay waits since #34) |
| `held-off` | it is ready but closed on purpose: a lane with no fresh handshake, a proxy address not held |
| `refused` | a check before start failed; the reason is the refusal's text |
| `stopped` | the program that carries it is not running |

Each flow is supervised on its own (#54). A flow whose parts drift is closed, rebuilt and
reported alone. What every flow depends on stops them all: IP forwarding turned on, the
relay's link filter changed, a transport's interface re-made.

## The per-flow health record (ADR 1260, #21 item 12)

The program that carries a flow writes its record every 2 s to
`/var/lib/goatrope/flows/<name>.health`. Kernel-carried flows (a mirror, a lane, the kernel
path) take their counts from their tc counters, read by the relay or `goatrope-ports`. The
fields are ADR 1260's, so goat's publisher can put the record on the fabric unchanged. goatrope
still opens no Zenoh session (ADR 0001).

| ADR 1260 field | goatrope's value |
|---|---|
| link id | `goatrope/<host>/<flow name>` |
| state | the flow state above |
| messages in | received from the source (frames, datagrams or connections, as the flow counts) |
| converted | converted or decoded, for a flow with a transform; absent otherwise |
| failed | conversions that failed, plus sends that failed |
| sent per destination | one count per `to` |
| time of the last message | the last one received |
| the last error | its time and text |
| summary: messages per second | over the last 10 s |
| summary: distinct identities | the distinct sources seen in the last 60 s (link hosts, peers, MAC addresses) |
| summary: source identifiers | what the converter reports (for example ASTERIX SAC/SIC); absent for flows that do not decode |
| summary: data class | declared on the flow (`class = "..."`), not inferred |
| owner | the role and the declaration file, as ADR 1260's declared links carry them |

goatrope also keeps what ADR 1260 does not ask for: dropped by the filter, denied (a sender
the flow does not accept), and the carriage's own counters (ring drops, reassembly failures,
the link filter's drops).

- **The registry manifest.** `goatrope flows --json` prints every declared flow with its name,
  source, destination and owner. This is the manifest ADR 1260 §1 has every role that starts
  links render, so the goat registry imports goatrope's flows as declared links.
- **Chains.** In ADR 1266, a chain's hops reference declared things. A goatrope flow is one
  such hop, by its link id, and its record's counts are the hop's in and out.

## Consequences

- **One parser and one validator.** `src/config.rs` parses both schemas into one `Flow` type.
  The validator checks sources, destinations, filters and transforms once each; today's eight
  table readers shrink to eight shorthand translators. #55 is resolved by this; #56 and #57
  are made easier, since one type replaces per-table plumbing.
- **Every role is an implementation of one trait.** The tap, send, decode, relay and lane
  implement render, preflight, apply, check, status and remove. The install module owns the
  state file and the order of operations, and the tap module keeps only the tap (#58).
- **Optional parts move into the flow, not new tables.** Optional source MACs (#49) and the
  `routed_remote` acceptance (#41) are fields of a source. A relay with only a lane needs no
  link (#33).
- **A filter acts before goatrope answers.** What a flow's source does not accept gets no
  reply of any kind, including a TCP handshake (#48, PR #61), for every flow, not per table.
- **More state files, fewer special cases.** `relay.health` and the send heartbeats become one
  health record per flow; `relay.health` stays readable through 1.x for anything that reads it
  now.
- **No code changes with this ADR.** The work is ordered: one `Flow` type and the shorthand
  translators, with every namespace phase passing unchanged; then the per-flow health record
  and `check`/`status` blocks; then schema 2, its validator and its printer; then per-flow
  supervision. Each step is one pull request.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep the tables and share helper functions between them | It fixes duplicated code, not duplicated concepts: the names stay different, the requirements stay coupled (#33), and nothing gives a path a name the registry can use |
| A generic rule engine (match on anything, action on anything), as ZeroTier's flow rules or nftables | It would let a declaration say things goatrope cannot carry safely (a copy of a link sent back onto it, a forwarded route). The flow's parts are typed, so an impossible combination does not parse |
| Make every flow a separate process | A flow is a declaration unit, not a process unit: thousands of relay rules in one batched loop are cheaper than one process each (ADR 0006). Per-flow supervision is done inside the carrying program |
| Remove schema 1 at 1.0 | Every installed machine and the deploy play's host_vars use it; a break at 1.0 for a naming change is not worth it |
