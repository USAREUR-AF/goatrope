<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Hardware

goatrope needs a copy of the link's traffic and a machine to receive it. Where the copy
comes from decides what the link does while that machine is off.

| Where the copy comes from | What the machine needs | While the goatrope machine is off | Declaration | Status |
|---|---|---|---|---|
| Passive copper tap | two receive-only Ethernet ports, one per direction | the link carries on | `mode = "listen"`, `source = "copper-tap"`, two ports, `speed_mbps = 100` | built; tested in namespaces; no device measured |
| Powered tap device that closes the link when its power fails | one or two receive-only Ethernet ports | the link carries on | `mode = "listen"`, `source = "bypass-relay"` | built; tested in namespaces; no device measured |
| Switch mirror port (SPAN; RSPAN at the destination switch) | one receive-only Ethernet port | the link carries on | `mode = "listen"`, `source = "mirror-port"`, one port | built; tested in namespaces |
| ERSPAN: a mirror sent in GRE to an IP address | an address on an ordinary interface, where the mirror arrives | the link carries on | `source = "erspan"` | designed ([ADR 0003](adr/0003-goatrope-is-written-in-rust.md), step 5); not built |
| goatrope's own inline tap | two Ethernet ports the link passes through | **the link is down** | `mode = "inline"`, two ports | built; tested in namespaces |

Every case needs a management interface that is not a tap port, Ubuntu Server 24.04 or
26.04 on arm64 or amd64, and room for the recording ring.

## Prebuilt tap devices and mirror ports

goatrope runs in listen mode behind each of these. The device that carries the link is
not the goatrope machine, so the link stays up while the machine is off, restarting or
being replaced; only the recording has a gap.

| Device | How it connects | Limits |
|---|---|---|
| Passive copper tap | in the link; two outputs, one per direction, to the two tap ports | 10 or 100 Mb/s only: a passive tap cannot carry 1 Gb/s, which uses all four pairs in both directions. The outputs do not negotiate |
| Powered tap device that closes the link when its power fails | in the link; one or two monitor outputs | the link is interrupted for the moment the relay inside switches, on power loss and on return |
| Switch mirror (SPAN) port | a port on the switch that copies chosen traffic to the machine | the switch may drop copies under load; it copies what it is configured to copy |
| RSPAN | a mirror carried over a VLAN to a port on another switch | as SPAN; the goatrope machine sees it on the destination switch's port, declared as `mirror-port` |

Behind any of these, listen mode drops every outgoing frame on the tap ports at
the kernel's egress hook. The one-way property of the link itself belongs to the
device: a passive copper tap's outputs carry no traffic back into the link at all.
A process with `CAP_NET_RAW` (root has it) that sends with `PACKET_QDISC_BYPASS`
skips the egress hook (the namespace tests record this), so on a mirror port, where
a frame sent could reach the switch, the drop is a software guarantee for ordinary
processes, not a physical one. Where transmission onto the link must be impossible,
use a passive copper tap or a tap device whose monitor ports cannot transmit.

## ERSPAN (designed)

A switch or router sends the mirror inside GRE to an IP address. goatrope will make a
Linux `erspan` interface on a declared underlay address, keyed by the mirror's session
ID (the kernel delivers a mirror only to the interface whose key matches it), and
record and decode from that interface as from a listen port. The goatrope machine
needs no port on the mirrored link at all, only a route from the switch. Built only in
the Rust version (ADR 0003, step 5).

## goatrope's own inline tap: a small computer

goatrope supports a Raspberry Pi with two wired Ethernet ports for the tap and a
third interface for management.

| Part | Requirement |
|---|---|
| Computer | Raspberry Pi 4 or 5 (arm64). Any amd64 small computer with the same ports also works |
| Operating system | Ubuntu Server 24.04 or 26.04, arm64 or amd64 |
| Tap ports | two wired Ethernet ports: the built-in port and a USB 3 adapter, or two USB 3 adapters |
| Management | a third interface: Wi-Fi, or a third Ethernet port (a USB adapter) on a separate network. A wired management port with DHCP is easier to reach than Wi-Fi when the machine is moved |
| Storage | room for the recording ring you declare (`files` x `file_mb`), with 10% to spare; `install` refuses a ring that does not fit |
| Watchdog | the Pi's hardware watchdog (`/dev/watchdog0`); `check` fails without a watchdog device. goatrope has not yet been run on a Pi, so the device's presence under Ubuntu is unverified here. A machine too slow for systemd to feed it within 15 s is reset: time `systemctl daemon-reload` on the hardware first (0.3 s in an amd64 VM; 13 s in an emulated arm64 one, which the watchdog did reset) |
| Packages | `tcpdump`, `ethtool`, `iproute2`, `systemd-networkd` (part of Ubuntu Server) |

The same small computer can run in listen mode behind a tap device or on a mirror port.

**Inline on a Pi is fail-closed.** In inline mode the Pi bridges its two ports and
every frame passes through it. While it is off, restarting or hung, the link is
down. The hardware watchdog restarts a hung Pi, and the bridge comes back with no
one touching it. One measurement, from the private installer goatrope replaces,
with a Raspberry Pi 5 bridging two laptops: across one power cycle the receiver saw
no traffic for 39.0 s (37 s measured by a ping each second), and the bridge and the
recordings came back by themselves.

**Each side negotiates its own speed.** In inline mode each tap port negotiates
with the device cabled to it, so the two sides of the link can run at different
speeds (one pair measured with the private installer: 1 Gb/s on one side, 10 Mb/s
on the other). The Pi buffers between them. `speed_mbps` forces both ports.

**USB adapters.** A USB adapter appears after boot starts. goatrope waits up to
120 s for each port and never holds up boot for one. Name ports by their stable
names (`enx` followed by the adapter's MAC address), which do not change when
adapters are plugged into other sockets.

## Recording rate

The recorder is `tcpdump` writing a ring of files with a kernel buffer of 8 MiB.
Rates a Pi sustains without dropping frames have not been measured with goatrope.
The status of a recorder is in `systemctl status goatrope-record@<port>`; tcpdump
reports frames dropped by the kernel when it stops.
