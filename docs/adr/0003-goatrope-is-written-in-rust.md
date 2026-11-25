<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0003: goatrope is written in Rust

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-25 |
| Deciders | operator |
| Owner | `goat-owners` |
| Related | [ADR 0001](0001-goatrope-is-its-own-repository.md), [ADR 0002](0002-relay.md); goatcore ADR 0112 (`docs/adr/0112-tech-strategy-workload-shape-language-boundary.md`, language by workload shape) |

## Decision

goatrope is written in Rust. It ships as one statically linked binary for each of
amd64 and arm64, and both binaries go in the one release archive.

The Python tree is ported role by role and then removed. No new feature goes into
the Python tree. The ERSPAN source is built only in the Rust version.

## Why Rust

goatcore ADR 0112 chooses the language by workload shape. A long-running process
on a per-packet path is Rust; scripts and test drivers may be Python. goatrope's
roles fall on the Rust side of that line:

| Role | Workload | ADR 0112 row |
|---|---|---|
| decode-and-send | a daemon reading every frame on a tap port, reassembling, matching and sending | per-packet hot path: Rust |
| relay | a daemon forwarding every datagram between a tunnel and the link | per-packet hot path: Rust |
| tap (install, check, status, uninstall, deploy) | a command run once, changing interfaces, files and units | none of its own; shares the binary |

The tap commands go in the same binary, so one file is installed, verified and
rolled back. goatbuilder, goat's build tool, is a Rust command-line program of the
same kind. first-bite, whose decoder goatrope runs, is Rust.

## What does not change

| Contract | Stays |
|---|---|
| The declaration | `/etc/goatrope/goatrope.toml`, `schema = 1`, every key, every refusal and its message |
| The commands | `install`, `deploy [--dry-run]`, `status`, `check [--json]`, `uninstall [--purge]`, `validate`, `relay`, `boundary key\|sheet\|up\|check\|down`, and the internal `apply-ports`, `run-send`, `verify-component` |
| Exit codes | 0 success or match, 1 error, 2 refused or invalid declaration, 3 check differs |
| What install writes | the same files, units and state, so `check` and `uninstall` behave the same on a machine installed by either version |
| The release | exactly one archive, `SHA256SUMS` and `SHA256SUMS.cosign-bundle`, signed keylessly at the tag. The archive holds `bin/goatrope` (a launcher that picks the binary for the machine) and the two binaries |
| The acceptance suite | `tests/netns` drives the command line from outside, in network namespaces, on Ubuntu 24.04 and 26.04, and in the emulated arm64 machine. It stays Python, which ADR 0112 allows for test drivers, and its assertions do not change |

## How the port is done

1. **Config and `validate`.** The Rust binary parses and validates the declaration
   with the same messages. Every verb it does not handle yet it passes to the Python
   tree beside it, so the whole suite runs against each step.
2. **decode-and-send** (`run-send`, `verify-component`).
3. **relay**, the mesh and boundary transports included (`relay`, `boundary`).
4. **tap** (`install`, `deploy`, `status`, `check`, `uninstall`, `apply-ports`). This
   step removes the Python tree and moves the release to the two-binary archive.
5. **ERSPAN source**, as a new listen source.

Each step is one pull request that passes the namespace suite on Ubuntu 24.04 and
26.04, and the arm64 run, before it merges.

## How it touches the machine

| Interface | Used through |
|---|---|
| Links, addresses, routes, bridge, `erspan` interfaces | netlink (`netlink-packet-route`, `netlink-sys`), not `ip` |
| WireGuard interface, keys, peer | netlink (`netlink-packet-wireguard`), not `wg`; the public key is derived in process (X25519), so a key value never reaches another program |
| Capture for decode-and-send | an `AF_PACKET` socket bound to the tap port, receive only |
| Recording | `tcpdump`, unchanged: its ring and file format are what operators already read |
| Offloads, EEE, speed; the egress drop | `ethtool` and `tc`, whose command lines are those tools' stable interfaces |
| Units and network files | `systemctl` and `networkctl` |

Dependencies are pure Rust where one exists, so the binary links statically against
musl with no C library at run time.

## Decoding

`[[decode]]` keeps running the pinned first-bite `mind` as a separate process under
its own dynamic user with capture capabilities only. A parser of untrusted link
traffic stays outside the process that installs units and changes interfaces.
`[[send]]` parses Ethernet, VLAN, IPv4, IPv6 and UDP headers with `etherparse`, the
crate first-bite uses.

## Consequences

- One file to install, hash and roll back, with no interpreter on the machine.
- Two toolchains in CI during the port; one after it.
- The arm64 binary is built on an arm64 runner, natively, not emulated.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep Python | The relay and decode-and-send are per-packet daemons; ADR 0112 puts those in Rust |
| Go | ADR 0112 puts the sustained per-packet regime in Rust; goat's tools of this kind are Rust |
| Rewrite in one pull request | The suite could not tell which change broke which behavior; the role-by-role order keeps every step tested |
