<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Getting data out of a system that seems locked down

A system that sends its data only to its own display or controller often looks closed:
there is no export, no interface for others, and nobody wants its configuration touched.
There are still three ways to get a copy of what it sends, and a fourth when nobody can
change anything at all. None of them takes control of the system.

| | 1. One more destination | 2. A mirror port | 3. One more listen-only client | 4. A cable tap |
|---|---|---|---|---|
| **What it takes** | The system's owner adds one destination to the output it already sends (most systems that send to one address can send to two) | The network administrator configures the switch the data crosses to copy that port's traffic to a free port: SPAN on the same switch, RSPAN to another switch, ERSPAN to an address over IP | Our machine registers with the system as one more client that only receives, as its own displays do | A tap device in the cable the data crosses: a passive copper tap (10 or 100 Mb/s) or a powered tap device |
| **Who acts** | The system's owner or its vendor | The site network administrator | We do, with the system's interface description from its owner | We do, with the system owner's agreement |
| **What changes on the system** | One configuration entry | None on the system; the switch configuration gains a mirror session that adds a copy | None to its configuration; one more client connected | None to any configuration; the cable is re-made through the tap |
| **Risk** | Low: the owner makes a change it understands | Low: a switch under load may drop copies, never the original traffic | The client must never take control or change the system's state; the interface must be documented | A brief interruption while the cable is re-made; a passive tap holds the link to 100 Mb/s |
| **How it is undone** | Remove the entry | Delete the mirror session | Stop the client | Remove the tap and re-make the cable |
| **Where goatrope fits** | Not needed: the copy arrives addressed to the receiving machine | Listens on the mirror port: `source = "mirror-port"` (SPAN, RSPAN) or `source = "erspan"` (ERSPAN) | Not goatrope's role; a client for the system's own protocol | Listens behind the tap (`source = "copper-tap"` or `"bypass-relay"`), or is itself the inline tap (`mode = "inline"`) |

## Choosing

- **Way 1 is the cleanest.** The copy is the system's own output, addressed to us,
  and contains nothing of anyone else's traffic.
- **Way 2 needs only the network administrator.** The system is not touched, and the
  copy can be filtered at the switch to the system's traffic alone.
- **Way 3 needs the system's interface description.** It suits systems built to serve
  several displays. It is the one course where a mistake could affect the system, so
  the client is built to receive only.
- **Way 4 depends on nobody outside the team** once the system's owner agrees, and
  is the course when the system and its network both stay as they are.

Ways 1 and 3 hand over the system's data on purpose. Ways 2 and 4 copy what crosses a
cable, so they also see any other traffic on that cable; goatrope's recording filter and
`[[send]]` match keep only what is named.

## In goatrope

| Way | Declaration |
|---|---|
| 2. SPAN or RSPAN | `[tap] mode = "listen"`, `source = "mirror-port"`, one port |
| 2. ERSPAN | `mode = "listen"`, `source = "erspan"` and `[tap.erspan]` ([hardware.md](hardware.md#erspan)) |
| 4. Passive copper tap | `mode = "listen"`, `source = "copper-tap"`, two ports (one per direction), `speed_mbps = 100` |
| 4. Powered tap device | `mode = "listen"`, `source = "bypass-relay"` |
| 4. goatrope as the tap | `mode = "inline"`: a small computer with two Ethernet ports bridges the link; the link is down while it is off ([README](../README.md#inline-is-fail-closed)) |

[hardware.md](hardware.md) has each source's limits.
