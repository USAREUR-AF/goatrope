<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0004: the recording is published by a pinned first-bite tap by default

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-27 |
| Deciders | operator |
| Owner | `goat-owners` |
| Related | [ADR 0002](0002-relay.md), [ADR 0003](0003-goatrope-is-written-in-rust.md); goatcore ADR 1270 (Proposed: first-bite is the home of capture and inspection, every end node taps its sensor link by default); goatcore ADR 1032 (`volatile/`, routed never stored); first-bite `deployment/tap` |

## Decision

On a goatrope machine, each recorded port also runs a first-bite tap
(`mind --tap-only`) by default, from a `mind` binary pinned by SHA-256 like a
`[[decode]]` component. The tap writes one-minute pcap slices to its own bounded
ring and publishes each finished slice to a Zenoh key through a local REST port,
in the grammar of goatcore ADR 1270:

```
volatile/<anchor>/stream/@pcap/<sensor>/<machine>
```

The declaration gains a `[tap.publish]` section. It is on by default once the
machine has a Zenoh REST port to publish to; `enabled = false` with a `reason`
turns it off.

```toml
[tap.publish]
rest = "http://127.0.0.1:8000"     # the local Zenoh REST port; required to publish
sensor = "radar-a"                 # the <sensor> chunk; required
anchor = "<32-hex anchor>"         # the machine's write anchor; required
slice_seconds = 60                 # default
slice_mb = 1                       # default; one sample stays under 1 MiB
keep = 60                          # default: one hour of slices, at most 60 MiB
# enabled = false
# reason = "..."                   # required with enabled = false
```

goatrope adds no `[[send]]` for this and no Zenoh session of its own. A
`[[send]]` matches UDP datagrams and cannot carry a pcap file; first-bite
already captures, rotates, retries and publishes, and keeps a slice in its ring
when the publish fails.

## Why

When a feed looks wrong downstream, the question is what crossed the link. The
tcpdump ring under `[tap.record]` answers it on the machine, for whoever can log
in. The published slice answers it for anyone on the fabric's capture reader
list, saved unchanged with `mind goat watch <key> --save <dir>`, without a login
and while the problem is happening. goatcore ADR 1270 makes the tap the default on
every end node; a goatrope machine is an end node.

## How it stays within goatrope's rules

| Rule | How |
|---|---|
| Never transmits on the tapped link | the tap reads the recorded port receive-only, as its own dynamic user with `CAP_NET_RAW` and `CAP_NET_ADMIN` only; the REST destination is refused at install and at run time when its route leaves through a tap port, as for a `[[send]]` destination |
| Runs only what was checked | the pinned binary is hashed and copied to `/var/lib/goatrope/components/<sha256>` and the copy runs |
| Fits on disk | `install` counts the tap's ring (`keep` x `slice_mb`) with the tcpdump rings and refuses when they do not fit |
| Raw is shed before decoded | captures publish in the bulk class of `volatile/` (congestion control drop, lowest priority); decoded output keeps its own class |

## Built and not built

| Piece | State |
|---|---|
| `mind --tap-only` with ring and publish to a local REST port | built in first-bite; in its release candidate 1.2.0-rc.2 |
| `[[decode]]` running a pinned `mind` | built |
| `[tap.publish]`, its defaults, the disk check and the route check for the REST port | not built |
| Fabric write and read rules for `@pcap` keys | goatcore ADR 1270, not built |

## Alternatives considered

- **Publish the tcpdump ring's files.** Rejected: it adds a publisher to goatrope,
  which opens no Zenoh session, and duplicates first-bite's retry and ring logic.
- **A `[[send]]` that carries files.** Rejected: `[[send]]` is a datagram path;
  a second meaning makes both harder to check.
- **Off by default.** Rejected: the slice that explains a fault is the one
  recorded before anyone asked.
