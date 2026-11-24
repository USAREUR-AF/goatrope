<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0001: goatrope is its own repository, usable without goat

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-24 |
| Deciders | operator |
| Owner | **OPEN**: no owner has been named |
| Related | goatcore ADR 1257 and `docs/design/goatbuilder-build-targets.md` §3.8 (the network tap as a build target type); [ADR 0002](0002-relay.md) (the relay) |

## Decision

goatrope is a public repository of its own. It builds one small machine on one
Ethernet link into up to three declared roles: a **tap** that records the link, a
**decode-and-send** stage that reads the tap's copy and delivers it, and a **relay**
that lets a remote machine act as though it is on the link. It has its own
releases, its own ADRs and its own owner, and it runs with no goat component
installed. goat's build tool (goatbuilder) calls it at a pinned, signed release and
checks the end state it reports; goatrope does not depend on goat.

The operator's words (2026-11-23): "tap is not goat core"; "Its own public
repository, usable without goat. It needs an ADR, its own releases and an owner";
"we want this repo to also in some cases build a relay that allows a remote machine
to act as though it is local thorugh it and in other cases to be a tap that gets
copies of data deerializes decodes and sends" (quoted as written).

## Why a repository of its own

A tap machine's job is the link, not any one consumer of it. Three properties make
it a separate unit:

- **It is a machine, not a service.** goatrope owns the interfaces, the bridge,
  the boot behavior, the watchdog and the recording disk of a host. The services
  that read its copy (first-bite, goat-transformers) are installed on many kinds of
  machine and must not carry host-level network changes with them.
- **It transmits, in two of its modes.** An inline tap forwards every frame of the
  link, and a relay originates frames on it. first-bite's design rule is that it
  never transmits on its capture interface, so the transmitting code cannot live
  there.
- **It must work without goat.** A tap is useful on a link with no fabric, mesh or
  goat identity. goat consumes it the way it consumes the other edge kinds: a
  pinned release and an end-state check (goatcore ADR 1257, decision 6).

## Scope

In scope:

| Role | What goatrope does | Status |
|---|---|---|
| tap, inline | bridges two ports; records on one port; link drops when the machine stops | built; namespace-tested on Ubuntu 24.04 and 26.04 |
| tap, listen | receives on one port, or two for a passive tap's two outputs; drops every outgoing frame | built; namespace-tested on both versions |
| decode-and-send | `[[send]]`: UDP payloads from the tap's copy to UDP, TCP, HTTP or a file, optionally converted by a pinned goat-transformers binary; `[[decode]]`: a pinned first-bite `mind` configured, run and health-checked | built; namespace-tested with a converter stand-in; first-bite and goat-transformers themselves not run |
| relay | design in ADR 0002; a WIP fixed-port UDP forwarder through WireGuard | WIP; namespace-tested; not installed as a service |
| hardware | Raspberry Pi with two USB or built-in Ethernet ports, Ubuntu 24.04 or 26.04, arm64; amd64 small computers | Pi supported; see [hardware.md](../hardware.md) |

Out of scope: decoding formats (first-bite owns that), converting formats
(goat-transformers), any Zenoh session of goatrope's own (only a component's own
sink), mesh enrolment and identity (goat), operating-system installation and disk
encryption (the operator, or goatbuilder's golden path), and network gear.

## Cross-repository check

Each repository below was read at its current `main`. None of them does what
goatrope does, and goatrope reimplements none of them.

| Repository | What it is | Overlap with goatrope | Boundary |
|---|---|---|---|
| first-bite | decodes binary messages from a copy of a link against a JSON dictionary and publishes records; `deployment/tap` runs `mind --tap-only` to write and publish pcap slices; `deployment/capture-node` records with dumpcap and copies to a bucket | both record a link | first-bite reads an interface it is given and never transmits; goatrope prepares the machine and the interfaces, records the raw ring, and runs a pinned first-bite as an optional component |
| octo-pod | edge gateway: ingress arms take sensor feeds addressed to it (UDP, TCP listen, TCP dial), records and audits them, releases chosen keys to the Zenoh fabric | both deliver data off a small machine over UDP and TCP | octo-pod receives traffic sent to it; goatrope takes copies of traffic between other machines. A goatrope `[[send]]` can feed an octo-pod ingress arm |
| open-billie | node provisioning and sensor-specific kid packages that decode one sensor's output and publish it through the Billie translator and Zenoh | both run on a small Ubuntu node beside sensors | a kid talks to its sensor; goatrope sits on a link and touches no sensor |
| goat-processors | correlation, fusion, filtering and quality on translated track data | none | downstream of anything goatrope delivers |
| goatcore, Reticulum bridge (ADR 1050) | a bridge between the Zenoh fabric and Reticulum for links below the IP layer | both are "bridges" in name | the Reticulum bridge carries fabric samples over a non-IP bearer; goatrope's relay carries IP datagrams between a WireGuard tunnel and an Ethernet link |

## Boundary table

| Concern | Owner |
|---|---|
| tap ports, bridge, STP, LLDP forwarding, offloads, EEE, link speed | goatrope |
| no address, IPv6, RA or LLDP sent from tap interfaces; listen-mode egress drop | goatrope |
| bounded recording ring on a port | goatrope |
| hardware watchdog setting; boot that waits for no tap port | goatrope |
| refusal to take the interface carrying the session or the default route | goatrope |
| end-state check (`goatrope check`, exit 0 / 3) | goatrope; goatbuilder calls it |
| decoding with a dictionary | first-bite, run by goatrope at a pinned hash |
| format conversion | goat-transformers, run by goatrope at a pinned hash |
| delivery to UDP, TCP, HTTP, file | goatrope `[[send]]` |
| delivery to Zenoh | a component's own sink only |
| remote machine on the link | goatrope relay (ADR 0002) |
| WireGuard keys and peers for the relay | the operator, or goat's mesh |
| OS install, disk encryption, mesh enrolment | the operator or goatbuilder |

## Consequences

- goatrope publishes releases (archive, SHA256SUMS, keyless signature, provenance
  attestation) from its own release workflow, tagged `goatrope-v<version>`.
- goatbuilder's network-tap target type pins a goatrope release and reads
  `goatrope check --json`.
- The end state goatcore §3.8 lists is what `goatrope check` reads, with two
  differences: the declaration's file format is goatrope's TOML (the §3.8 YAML is a
  sketch), and the encrypted root is reported, not required, because the operator
  deferred encryption for the one existing machine ("in the future such machiens
  should be encrypted but we don't need to trouble over it in this particular
  case").

## Open

1. **Owner.** The repository needs a named owner before it is created on GitHub.
2. **GitHub organization.** Not chosen; nothing has been pushed.
3. **When encryption becomes a check.** `check` reports the root's encryption as
   information today.
