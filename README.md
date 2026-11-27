<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# goatrope

goatrope takes a copy of the traffic on one network link and records it, sends on the
datagrams you name, and can relay named datagrams to a remote machine. The copy can
come from any of these:

| Where the copy comes from | goatrope declaration | Status |
|---|---|---|
| a **prebuilt tap device** in the cable: a passive copper tap, or a powered tap device that keeps the link closed when its power fails | `mode = "listen"`, `source = "copper-tap"` or `"bypass-relay"` | built; tested in network namespaces; no device measured with goatrope |
| a switch **mirror port**: SPAN on the same switch, or RSPAN delivered to a port of another | `mode = "listen"`, `source = "mirror-port"` | built; tested in network namespaces |
| **ERSPAN**: a mirror sent over IP, in GRE, to an address on the goatrope machine | `mode = "listen"`, `source = "erspan"` and a `[tap.erspan]` table | built; tested in network namespaces with a mirroring namespace |
| goatrope's **own inline tap**: a small computer with two Ethernet ports, such as a Raspberry Pi, bridging the link | `mode = "inline"` | built; tested in network namespaces |

When the system that sends the data seems locked down, [three-ways.md](docs/three-ways.md)
compares the ways to get a copy without taking control of it.
[related-work.md](docs/related-work.md) lists the established practice goatrope follows, with
its sources, and the practice it does not follow yet.

On the machine that receives the copy, goatrope runs in up to three declared roles:

| Role | What it does | Status |
|---|---|---|
| **tap** | records the link: **listen** (a tap device or mirror port hands the machine a copy) or **inline** (the machine bridges the link) | built; tested in network namespaces on Ubuntu 24.04 and 26.04 |
| **decode-and-send** | takes the tap's copy, extracts the datagrams you name, optionally decodes or converts them with pinned first-bite or goat-transformers components, and sends them to UDP, TCP, HTTP or a file | built; tested in network namespaces |
| **relay** | lets a remote machine exchange named datagrams with machines on the link, over the WireGuard mesh the site already runs, or, for a site outside the deployment, over a dedicated tunnel with one peer: the declared boundary point | built (fixed-port UDP rules, as a service; an address proxy for a remote machine); tested in network namespaces on Ubuntu 24.04 and 26.04; [ADR 0002](docs/adr/0002-relay.md), [ADR 0004](docs/adr/0004-relay-1-0.md) |

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
# listen only:  source = "copper-tap" | "mirror-port" | "bypass-relay" | "erspan" (with [tap.erspan])
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
| `goatrope install` | applies the declaration. Refuses, changing nothing, when the OS is not Ubuntu 24.04 or 26.04, a port is missing, wireless, in another bridge, carries a VLAN or other device, holds an address, carries the default route, the operator's session or any established connection (link-local ones included), when the rings (one per recorded port) and file destinations do not fit on disk, or when the state file of an earlier install is unreadable |
| `goatrope deploy [--dry-run]` | `install`, only when the machine does not already have this software and declaration and match it. With `--dry-run`, makes every refusal and changes nothing. [docs/deploy.md](docs/deploy.md): the Ansible play that runs it from a verified release file |
| `goatrope status` | the mode in plain words, each port's carrier and speed, the bridge, each recorder and its ring, each send and decoder, the relay's rules and counters, and the check result |
| `goatrope check [--json]` | compares the machine with the declaration. Exit **0** matches, **3** differs, anything else is an error (2: invalid or unreadable declaration) |
| `goatrope uninstall [--purge]` | removes every unit, network file, sysctl and watchdog drop-in install wrote, `relay.health` and the relay's boundary interface, deletes the bridge, and restores each port's offloads, EEE, speed, ARP, IPv6 and up/down state as install found them. Keeps the declaration and recordings unless `--purge` |
| `goatrope validate` | checks the declaration alone |
| `goatrope relay` | runs the relay in the foreground (`install` runs it as `goatrope-relay.service`) |
| `goatrope boundary key\|sheet\|up\|check\|down` | the relay's boundary interface (`transport = "boundary"`): make the key, print what the boundary point needs, bring it up, check it (exit 0 or 3), remove it |

## What the tap sets, and what `check` reads

| Property | Inline | Listen |
|---|---|---|
| no IPv4 or IPv6 address on a tap port or the bridge; IPv6 disabled; no DHCP, RA or LLDP sent | yes | yes |
| the `.network` file systemd-networkd applies to each port is goatrope's | yes | yes |
| one bridge of exactly the two ports, STP off, forward delay 0, ports forwarding | yes | no bridge holds a port |
| LLDP frames (group address 01:80:C2:00:00:0E) forwarded across the bridge | yes | n/a |
| every outgoing frame from an ordinary process dropped (tc egress `matchall drop`), ARP off; the port goes up only after the drop is in place. **A process with `CAP_NET_RAW` (root has it) that sends with `PACKET_QDISC_BYPASS` skips this drop** (the tests show it) | n/a | yes |
| GRO, LRO, TSO and GSO off; Energy-Efficient Ethernet off; declared speed | yes | yes |
| recording on a port, not the bridge device, as a bounded tcpdump ring (`files` x `file_mb`) | yes | one ring per port |
| boot waits for no tap port (`RequiredForOnline=no`; the port service does not block boot) | yes | yes |
| NetworkManager, where it runs, manages no tap port (`unmanaged-devices+=`, reloaded at install) | yes | yes |
| hardware watchdog: `RuntimeWatchdogSec=15s`, and a watchdog device present | yes | yes |
| bridged frames do not pass through iptables (`bridge-nf-call-*` = 0 where present) | yes | n/a |
| root filesystem encryption | reported, not required | reported, not required |

**Where transmission onto the link must be impossible, use a physically
receive-only tap**: a passive copper tap, whose outputs have no path back into the
link, or a tap device whose monitor ports cannot transmit. Listen mode's egress drop
is software on the goatrope machine; a process with `CAP_NET_RAW` can get past it, and
on a mirror port a frame that gets past it reaches the switch.

## Decode-and-send

A `[[send]]` reads frames on one tap port, receive only, reassembles IPv4
fragments, keeps the UDP datagrams its `match` names (at least one address or
port is required), optionally converts each payload with a goat-transformers
binary pinned by SHA-256, and sends it to each destination: `udp://`, `tcp://`
(`framing = "len32be"` or `"raw"`), `http(s)://` (one POST per message, redirects
refused) or `file:///var/lib/goatrope/...` (`format = "jsonl"` or `"raw"`, and
`max_mb`: the file is cut there and one older file kept). A destination whose
route leaves through a tap port, or whose name does not resolve, is refused at
install and at send time: decode-and-send never transmits on the tapped link. TCP
stream reassembly is not built.

The converter runs `goat-xf convert --packs <packs> --packs-only <from>,<to>` once
per message. On an amd64 workstation one such run took 0.14 s with the two packs
(0.7 s with every pack), so a converted feed is limited to a few messages per
second.

A `[[decode]]` runs a first-bite `mind` binary pinned by SHA-256 on the declared
ports, with its own dictionary and its own sinks, as its own dynamic user with
`CAP_NET_RAW` and `CAP_NET_ADMIN` only and a read-only system. Zenoh delivery goes
only through a component's own sink; goatrope opens no Zenoh session.

A pinned binary is hashed and copied to `/var/lib/goatrope/components/<sha256>`
in one read, and the copy is what runs: a binary replaced after the check never
runs, and `check` reports it.

## Relay

A `[relay]` forwards the UDP datagrams and TCP connections its `allow` rules name between a
remote machine, authenticated by WireGuard, and machines on the link, from the relay's own
interface and address. Everything else is dropped and counted. The rules and the refusals are in
[ADR 0002](docs/adr/0002-relay.md) and [ADR 0004](docs/adr/0004-relay-1-0.md).

| `direction` | `protocol` | The relay listens on | It accepts | It sends to | Required keys |
|---|---|---|---|---|---|
| `remote-to-link` | `udp` or `tcp` | the remote interface, `listen_port` | the rule's `remote` only | `target`:`target_port` on the link, from its link address | `remote`, `listen_port`, `target`, `target_port` |
| `both` | `udp` | as above | as above; and replies from the target only | as above, and the target's replies back to the remote | as above |
| `link-to-remote` | `udp` or `tcp` | its link address, `listen_port` | the `sources` listed (the link is not authenticated, so the list is the control) | `remote`:`remote_port` through the remote interface; UDP replies go back to the sender | `remote`, `listen_port`, `remote_port`, `sources` |

TCP: the relay accepts a connection, opens one to the other side, and copies both ways until
each side has closed; a side that closes only its sending half is passed on as a half-close.
A connection it does not accept is closed at once and counted as denied. `max_connections`
(default 64) bounds the connections open on a rule at once; one more is closed and counted.
`direction = "both"` is refused for TCP, because a connection always carries both directions.
A peer that vanishes without closing (the normal case when a WireGuard path dies) frees its slot
within a fixed 2 minutes: both sockets of a connection send keepalive probes after 60 s idle,
every 10 s, and give up after 6 unanswered, and data not acknowledged within 120 s fails the
connection (`TCP_USER_TIMEOUT`); it is then closed both ways and counted as broken. Both sockets
have `TCP_NODELAY`, so small messages are not held back.
`relay.health` counts, per rule, the datagrams each way (UDP) or the connections open and
accepted and the bytes each way (TCP), and what was denied, over the limit, could not be sent or
broken.
Examples: `examples/relay-over-mesh.toml`, `examples/relay-boundary.toml`,
`examples/relay-link-initiated.toml`.

A declaration may hold only `[relay]`. `goatrope install` then installs the software, the
declaration and `goatrope-relay.service`, and touches no tap port, network file, sysctl or
watchdog setting. With a `[tap]` too, it installs both.

| Property | What `check` reads |
|---|---|
| `goatrope-relay.service` is installed as rendered, enabled and active | `file:`, `enabled:` and `unit:` items |
| the relay is running, not hung: it rewrites `/var/lib/goatrope/relay.health` every 2 s | `relay-health`: written in the last 10 s |

The unit has `Restart=on-failure`, so a relay that stops (for example because IP forwarding
was turned on while it ran, exit 1) is started again. A refusal (exit 2: IPv6 or IP forwarding
on, an interface missing or not WireGuard, the address not held) is not restarted
(`RestartPreventExitStatus=2`): the unit stays failed and `check` exits 3 until the cause is
fixed and the unit is started again. The relay runs with `CAP_NET_RAW` (to bind its sockets to
an interface) and `CAP_NET_ADMIN` (the boundary interface) only, on a read-only system except
`/var/lib/goatrope`. `wip` is no longer needed; `wip = true` is accepted and does nothing.

Installing a declaration with no `[tap]` over an installed tap is refused: run `goatrope
uninstall` first, so the tap ports are restored.

### Address proxy

A `[[relay.proxy]]` gives a remote machine an address of its own on the link
([ADR 0004](docs/adr/0004-relay-1-0.md) §4, [example](examples/relay-proxy.toml)). A rule
whose `link_address` names it sends to its target from that address, so machines on the link
see the remote there, and their replies to it go back to the remote.

| Key | Value |
|---|---|
| `address` | an IPv4 address on the link's network: not the relay's own, the network, a broadcast, multicast or a rule's target. IPv6 is refused |
| `remote` | the remote machine it stands for; a rule must name it as its `remote` |
| a rule's `link_address` | a proxy address whose `remote` is the rule's own; every proxy address must be used by a rule |

| What the relay does | When |
|---|---|
| sends three ARP probes from 0.0.0.0 (RFC 5227), then waits 2 s | the remote's tunnel is up: the WireGuard peer whose allowed IPs hold the remote has a handshake younger than 180 s |
| adds the address to `link_interface` as a /32 with `noprefixroute`, then sends two announcements | no machine answered for it or probed for it |
| does not take it, logs and counts a conflict, and probes again 10 s later | another machine answered for it or probed for it |
| removes it, logs and counts it | the handshake is 180 s old or older (checked every 2 s), another machine claims it, or the relay stops (SIGTERM, `systemctl stop`, any exit) |
| removes it at start, then probes before taking it again | an earlier run that was killed left it on `link_interface` |

A rule's sockets on the address are bound with `IP_FREEBIND`, so they exist while the address
is absent: the kernel delivers to them only while it is on `link_interface`. While the address
is not held, a datagram for the link counts as `send_errors`, a TCP connection toward the link
is not made (also `send_errors`), and an open TCP connection on it is closed. Every rule shape
can use it: on a `link-to-remote` rule, machines on the link send to `<address>:<listen_port>`. IP forwarding stays off
and no route names the remote, so the kernel does not route to it; only the rules' sockets on
the address forward anything. The relay refuses to start when the link interface does not use
ARP, or when the address is already configured on this machine by someone else. With a proxy
declared, the unit also allows `AF_PACKET` sockets, for the probes.

| Property | What `check` reads |
|---|---|
| each proxy address is on `link_interface` exactly when the relay says it holds it | `relay-proxy-<address>`: held (with the handshake age) or not held, and why |

`relay.health` carries, per proxy address: `held`, `why`, `handshake_age`, `probes`,
`conflicts`, `added` and `removed`. `status` prints them.

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
- install refusals, each changing nothing: among them a VLAN on a port, a TCP
  connection or SSH session over a port (link-local ones included), rings that do
  not fit once there is one per port, a recording directory outside goatrope's own,
  a newline or quote in the filter, and an unreadable state file;
- `check` exit codes: 3 before install, 0 after, 3 for each induced difference
  (address, GRO, recorder stopped, STP on, ARP on, egress drop removed, a changed
  component binary), 0 when undone, 2 for an invalid or missing declaration;
- a container restart with the ports appearing after boot: check returns to 0 and
  traffic passes with no one touching it;
- `uninstall` leaves only the declaration and recordings; `uninstall --purge` leaves
  the file tree and port state (IPv6 address generation included) exactly as before
  install;
- decode-and-send to UDP, TCP, HTTP and file destinations, fragment reassembly, a
  file destination cut at `max_mb`, and a converter stand-in pinned by hash;
- `components`, when `GOATROPE_TEST_COMPONENTS` names a directory holding them: the
  real goat-transformers `goat-xf` converting in a `[[send]]`, and the real
  first-bite `mind` decoding in a `[[decode]]` as its own user;
- `networkmanager`, in an image with NetworkManager managing the wired ports:
  install takes the ports from it at once and leaves the management port alone,
  and uninstall gives them back;
- the relay (ADR 0002): default deny, refusals, IP forwarding, send errors;
- `relay-service` (ADR 0004 module 1): install of a relay-only declaration writes and starts the
  unit and writes no tap file; check exits 0 while it runs, 3 when it is stopped and 3 when it is
  hung (relay.health older than 10 s); a failure is restarted and a refusal is not; uninstall
  leaves only the declaration and `--purge` leaves nothing; a declaration with a tap and a relay
  installs, checks and removes both;
- `relay-tcp` (ADR 0004 module 2): TCP both ways through a rule with a half-close; a connection
  from another peer denied; `max_connections` enforced; a remote that vanishes without a FIN
  freed at the 120 s bound; link-initiated UDP and TCP flows reach the
  remote and are answered; a link address not in `sources` denied; refusals of TCP `both` and of a
  missing or off-link `sources`;
- the relay's boundary transport: its own interface with one peer, drift and refusals;
- `proxy` (ADR 0004 module 4): an address another machine on the link holds is not taken (probes
  sent, no announcement, datagrams for its rule counted as send errors); once free it is probed,
  taken as a /32 with `noprefixroute` and announced twice, and answers ARP from the link; the
  remote's datagrams and TCP connections reach the link from it, and link machines' datagrams and
  TCP connections to it reach the remote; the kernel does
  not route to the remote; the address is removed within 180 s (+ one 2 s tick) of the peer's
  latest handshake once the peer stops, and taken back after a new probe when it returns; a
  killed relay's address is removed at the next start; SIGTERM and `systemctl stop` remove it;
  `check` and `status` report it; IP forwarding stays off throughout;
- `deploy`, in an image with Ansible: the play from a release file. Refusals leave the machine,
  `current` and the ledger as they were; install, a second run that changes nothing, repair,
  a changed declaration, a newer release, rollback, and inline with no ping lost on a re-run;
- `units`: a full disk, HTTP redirects, the reassembly bound, default routes in other
  tables, the state backup, and the operator's own tc filters kept.

`tests/arm64/run.sh 24.04|26.04` runs the same phases, except `components`,
`networkmanager` and `deploy`, in an emulated arm64 Ubuntu VM
(the Ubuntu arm64 cloud image under qemu-system-aarch64, inside a container), with an
emulated i6300esb watchdog, so `check` reads a real `/dev/watchdog0`. Emulation shows
that the arm64 packages behave as the amd64 ones; it says nothing about a Raspberry
Pi's timing or its USB adapters. In the VM the uninstall comparison covers, under
`/var/lib`, goatrope's own directories only.

Known limits the tests record: a process with `CAP_NET_RAW` sending with
`PACKET_QDISC_BYPASS` skips the listen-mode egress drop; stopping a recorder can
lose up to the last second of frames that tcpdump had not yet written.

Not tested: real hardware (a Raspberry Pi, USB adapters, a passive tap), the Pi's
own watchdog, forced link speed (veth cannot be forced), and recording throughput.

`bench`, in a container of its own after the others, measures the data paths: relay UDP
over real WireGuard, the remote mirror, and decode-and-send with a converter. It records
numbers and passes or fails nothing; [performance.md](docs/performance.md) has the method
and the results.

## Layout

| Path | Holds |
|---|---|
| `bin/goatrope` | the entry point: runs `bin/x86_64/goatrope` or `bin/aarch64/goatrope`, which `tools/build-bin.sh` builds and each release archive holds |
| `src/` | the Rust source: `config.rs` (the declaration), `tap.rs`, `send.rs`, `relay.rs`, `proxy.rs`, `boundary.rs`, `link.rs` (netlink), `sysutil.rs`, `main.rs`; one static binary ([ADR 0003](docs/adr/0003-goatrope-is-written-in-rust.md)) |
| `deploy/ansible/` | the play and role that install the tap from a release file |
| `examples/` | declarations with placeholder names and documentation addresses |
| `tests/netns/` | the namespace tests, their container, and `benchgen.py` (the `bench` phase's traffic generator) |
| `tools/` | `build-release.sh` (the archive and SHA256SUMS), `check-release.sh` (the release is exactly its three files) |
| `docs/` | ADRs, hardware, install card |

## License

Written by U.S. Federal government employees; public domain in the U.S., Apache
License 2.0 elsewhere. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [INTENT.md](INTENT.md).
