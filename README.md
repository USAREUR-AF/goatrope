<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# goatrope

goatrope turns one small computer with two Ethernet ports, such as a Raspberry Pi,
into a machine on one network link, in up to three declared roles:

| Role | What it does | Status |
|---|---|---|
| **tap** | records the link: **inline** (the machine bridges the link) or **listen** (a tap device or mirror port hands it a copy) | built; tested in network namespaces on Ubuntu 24.04 and 26.04 |
| **decode-and-send** | takes the tap's copy, extracts the datagrams you name, optionally decodes or converts them with pinned first-bite or goat-transformers components, and sends them to UDP, TCP, HTTP or a file | built; tested in network namespaces |
| **relay** | lets a remote machine exchange named datagrams with machines on the link through WireGuard | WIP; design in [ADR 0002](docs/adr/0002-relay.md) |

It runs with no goat component installed. Why it is a repository of its own, and
what it leaves to other repositories: [ADR 0001](docs/adr/0001-goatrope-is-its-own-repository.md).

## Inline is fail-closed

**In inline mode the link is down whenever the machine is off, restarting or
hung.** Every frame passes through the machine's bridge, and nothing carries the
frames when its processor stops. No software setting changes this. A hardware
watchdog restarts a hung machine. To keep the link up while the machine is down,
use listen mode behind a passive copper tap, a powered tap device that closes the
link on power loss, or a switch mirror port ([hardware.md](docs/hardware.md)).

## Install

Short form; the [install card](docs/install-card.md) has every step.

```console
sudo apt-get install -y tcpdump ethtool
sudoedit /etc/goatrope/goatrope.toml          # start from examples/inline.toml
./bin/goatrope validate --config /etc/goatrope/goatrope.toml
sudo ./bin/goatrope install --config /etc/goatrope/goatrope.toml
sudo goatrope check                           # exit 0: matches; 3: differs
```

## The declaration

One TOML file, `/etc/goatrope/goatrope.toml`. What the operator must decide has no
default, and a missing value is refused: the mode, the ports, the management
interface, the recording filter and ring size, and every address and port number in
a `[[send]]` or `[relay]` section.

```toml
schema = 1

[tap]
mode = "inline"                    # "inline" or "listen"; required
ports = ["enxPORTA", "enxPORTB"]   # inline: exactly two; listen: one, or two for a passive tap's outputs
management = "eth0"                # never a tap port
# listen only:  source = "copper-tap" | "mirror-port" | "bypass-relay"
# optional:     speed_mbps = 100   (forced, full duplex; required for copper-tap)

[tap.record]
ports = ["enxPORTA"]               # inline: one bridge port (it sees both directions); listen: one ring per port
filter = ""                        # a BPF filter, or "" for every frame
file_mb = 50
files = 40
```

`examples/` holds an inline tap, a listen tap behind a passive copper tap, and a
listen tap with decode-and-send.

## Commands

| Command | Does |
|---|---|
| `goatrope install` | applies the declaration. Refuses, changing nothing, when the OS is not Ubuntu 24.04 or 26.04, a port is missing, wireless, in another bridge, holds an address, carries the default route, the operator's session or any established connection, or when the ring does not fit on disk |
| `goatrope status` | the mode in plain words, each port's carrier and speed, the bridge, each recorder and its ring, each send and decoder, and the check result |
| `goatrope check [--json]` | compares the machine with the declaration. Exit **0** matches, **3** differs, anything else is an error (2: invalid or unreadable declaration) |
| `goatrope uninstall [--purge]` | removes every unit, network file, sysctl and watchdog drop-in install wrote, deletes the bridge, and restores each port's offloads, EEE, speed, ARP, IPv6 and up/down state as install found them. Keeps the declaration and recordings unless `--purge` |
| `goatrope validate` | checks the declaration alone |
| `goatrope relay` | runs the WIP relay in the foreground |

## What the tap sets, and what `check` reads

| Property | Inline | Listen |
|---|---|---|
| no IPv4 or IPv6 address on a tap port or the bridge; IPv6 disabled; no DHCP, RA or LLDP sent | yes | yes |
| the `.network` file systemd-networkd applies to each port is goatrope's | yes | yes |
| one bridge of exactly the two ports, STP off, forward delay 0, ports forwarding | yes | no bridge holds a port |
| LLDP frames (group address 01:80:C2:00:00:0E) forwarded across the bridge | yes | n/a |
| every outgoing frame dropped (tc egress `matchall drop`), ARP off; the port goes up only after the drop is in place | n/a | yes |
| GRO, LRO, TSO and GSO off; Energy-Efficient Ethernet off; declared speed | yes | yes |
| recording on a port, not the bridge device, as a bounded tcpdump ring (`files` x `file_mb`) | yes | one ring per port |
| boot waits for no tap port (`RequiredForOnline=no`; the port service does not block boot) | yes | yes |
| hardware watchdog: `RuntimeWatchdogSec=15s`, and a watchdog device present | yes | yes |
| bridged frames do not pass through iptables (`bridge-nf-call-*` = 0 where present) | yes | n/a |
| root filesystem encryption | reported, not required | reported, not required |

## Decode-and-send

A `[[send]]` reads frames on one tap port, receive only, reassembles IPv4
fragments, keeps the UDP datagrams its `match` names (at least one address or
port is required), optionally converts each payload with a goat-transformers
binary pinned by SHA-256, and sends it to each destination: `udp://`, `tcp://`
(`framing = "len32be"` or `"raw"`), `http(s)://` (one POST per message) or
`file:///var/lib/goatrope/...` (`format = "jsonl"` or `"raw"`). A destination
whose route leaves through a tap port is refused at install and at send time:
decode-and-send never transmits on the tapped link. TCP stream reassembly is not
built.

A `[[decode]]` runs a first-bite `mind` binary pinned by SHA-256 on the declared
ports, with its own dictionary and its own sinks. Zenoh delivery goes only through
a component's own sink; goatrope opens no Zenoh session.

## Tests

`tests/netns/run.sh` runs the tests in a privileged container with systemd as PID 1,
once on Ubuntu 24.04 and once on 26.04, using veth pairs and network namespaces on
the host's kernel. No hardware is involved. They cover:

- inline: 500 UDP datagrams each way, ping, and LLDP frames through the bridge;
  every frame received at either end is in the recording on one port; no frame from
  the tap's own addresses reaches either end;
- listen: every injected frame on each of two ports recorded on that port only, and
  no frame reaching the feed side during install, traffic, attempts to send (ping,
  raw sockets) and service restarts;
- 25 refusals, each changing nothing;
- `check` exit codes: 3 before install, 0 after, 3 for each induced difference
  (address, GRO, recorder stopped, STP on, ARP on, egress drop removed, a changed
  component binary), 0 when undone, 2 for an invalid or missing declaration;
- a container restart with the ports appearing after boot: check returns to 0 and
  traffic passes with no one touching it;
- `uninstall` leaves only the declaration and recordings; `uninstall --purge` leaves
  the file tree and port state exactly as before install;
- decode-and-send to UDP, TCP, HTTP and file destinations, fragment reassembly,
  and a converter stand-in pinned by hash (not goat-transformers itself);
- the WIP relay (ADR 0002).

Known limits the tests record: a root process sending with `PACKET_QDISC_BYPASS`
skips the listen-mode egress drop; stopping a recorder can lose up to the last
second of frames that tcpdump had not yet written.

Not tested: real hardware, real watchdog devices (a stand-in file is used), forced
link speed (veth cannot be forced), arm64 (the host is amd64), first-bite and
goat-transformers binaries, and recording throughput.

## Layout

| Path | Holds |
|---|---|
| `bin/goatrope` | the entry point |
| `goatrope/` | `config.py` (the declaration), `tap.py`, `send.py`, `relay.py`, `sysutil.py`, `cli.py`; Python 3 standard library only |
| `examples/` | declarations with placeholder names and documentation addresses |
| `tests/netns/` | the namespace tests and their container |
| `tools/build-release.sh` | the release archive and SHA256SUMS |
| `docs/` | ADRs, hardware, install card |

## License

Written by U.S. Federal government employees; public domain in the U.S., Apache
License 2.0 elsewhere. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [INTENT.md](INTENT.md).
