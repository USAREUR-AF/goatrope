<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Hardware

goatrope supports a Raspberry Pi with two wired Ethernet ports for the tap and a
third interface for management, on Ubuntu 24.04 or 26.04. Fail-open hardware,
which keeps the link up while the machine is off, comes later and has not been
measured with goatrope.

## Supported now: Raspberry Pi

| Part | Requirement |
|---|---|
| Computer | Raspberry Pi 4 or 5 (arm64). Any amd64 small computer with the same ports also works |
| Operating system | Ubuntu Server 24.04 or 26.04, arm64 or amd64 |
| Tap ports | two wired Ethernet ports: the built-in port and a USB 3 adapter, or two USB 3 adapters |
| Management | a third interface: Wi-Fi, or a third Ethernet port (a USB adapter) on a separate network. A wired management port with DHCP is easier to reach than Wi-Fi when the machine is moved |
| Storage | room for the recording ring you declare (`files` x `file_mb`), with 10% to spare; `install` refuses a ring that does not fit |
| Watchdog | the Pi's hardware watchdog (`/dev/watchdog0`); `check` fails without a watchdog device. goatrope has not yet been run on a Pi, so the device's presence under Ubuntu is unverified here |
| Packages | `tcpdump`, `ethtool`, `iproute2`, `systemd-networkd` (part of Ubuntu Server) |

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

## Later: fail-open hardware (none measured)

Each of these keeps the link up while the goatrope machine is off, because the
device that carries the link is not the machine. goatrope runs in listen mode
behind each one. None has been measured with goatrope.

| Device | How it connects | Limits | goatrope declaration |
|---|---|---|---|
| Passive copper tap | in the link; two outputs, one per direction, to the two tap ports | 10 or 100 Mb/s only: a passive tap cannot carry 1 Gb/s, which uses all four pairs in both directions. The outputs do not negotiate | `mode = "listen"`, `source = "copper-tap"`, two ports, `speed_mbps = 100` |
| Powered tap device that closes the link when its power fails | in the link; one or two monitor outputs | the link is interrupted for the moment the relay inside switches, on power loss and on return | `source = "bypass-relay"` |
| Switch mirror (SPAN) port | a port on the switch that copies chosen traffic to the machine | the switch may drop copies under load; it copies what it is configured to copy | `source = "mirror-port"`, one port |

Behind any of these, listen mode drops every outgoing frame on the tap ports at
the kernel's egress hook. The one-way property of the link itself belongs to the
device: a passive copper tap's outputs carry no traffic back into the link at all.
A process with `CAP_NET_RAW` (root has it) that sends with `PACKET_QDISC_BYPASS`
skips the egress hook (the namespace tests record this), so on a mirror port, where
a frame sent could reach the switch, the drop is a software guarantee for ordinary
processes, not a physical one. Where transmission onto the link must be impossible,
use a passive copper tap or a tap device whose monitor ports cannot transmit.

## Recording rate

The recorder is `tcpdump` writing a ring of files with a kernel buffer of 8 MiB.
Rates a Pi sustains without dropping frames have not been measured with goatrope.
The status of a recorder is in `systemctl status goatrope-record@<port>`; tcpdump
reports frames dropped by the kernel when it stops.
