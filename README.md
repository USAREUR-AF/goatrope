<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# goatrope

goatrope takes a copy of the traffic on one network link and records it, sends on the
datagrams you name, and lets remote machines reach named machines on the link through
WireGuard. The copy can come from any of these:

| Where the copy comes from | goatrope declaration | Status |
|---|---|---|
| a **prebuilt tap device** in the cable: a passive copper tap, or a powered tap device that keeps the link closed when its power fails | `mode = "listen"`, `source = "copper-tap"` or `"bypass-relay"` | built; tested in network namespaces; no device measured with goatrope |
| a switch **mirror port**: SPAN on the same switch, or RSPAN delivered to a port of another | `mode = "listen"`, `source = "mirror-port"` | built; tested in network namespaces |
| **ERSPAN**: a mirror sent over IP, in GRE, to an address on the goatrope machine | `mode = "listen"`, `source = "erspan"` and a `[tap.erspan]` table | built; tested in network namespaces with a mirroring namespace |
| goatrope's **own inline tap**: a small computer with two Ethernet ports, such as a Raspberry Pi, bridging the link | `mode = "inline"` | built; tested in network namespaces |

When the system that sends the data seems locked down, [three-ways.md](docs/three-ways.md)
compares the ways to get a copy without taking control of it.
[related-work.md](docs/related-work.md) lists the established practice goatrope follows, with
its sources, and the practice it does not follow yet, and compares goatrope on a WireGuard mesh
with the ZeroTier overlay network, job by job.

On the machine that receives the copy, goatrope runs in up to three declared roles:

| Role | What it does | Status |
|---|---|---|
| **tap** | records the link: **listen** (a tap device or mirror port hands the machine a copy) or **inline** (the machine bridges the link) | built; tested in network namespaces on Ubuntu 24.04 and 26.04 |
| **decode-and-send** | takes the tap's copy, extracts the datagrams you name, optionally decodes them with a pinned first-bite decoder or converts them with the goat-transformers engine linked into goatrope, and sends them to UDP, TCP, HTTP or a file | built; tested in network namespaces |
| **relay** | lets remote machines exchange the UDP datagrams and TCP connections its rules name with machines on the link, in either direction, over the WireGuard mesh the site already runs or, for a site outside the deployment, over a dedicated tunnel whose one peer is the declared boundary point. It can give a remote machine an address of its own on the link, and, accepted by name, bridge one port to one peer at layer 2 | built on `main`, not yet in a release (0.2.0 has the UDP rules and the boundary transport, as work in progress); tested in network namespaces on Ubuntu 24.04 and 26.04; [ADR 0002](docs/adr/0002-relay.md), [ADR 0004](docs/adr/0004-relay-1-0.md) |

The relay's parts, and the data paths under them, each with its status on `main`:

| Feature | Declaration | Status |
|---|---|---|
| The relay as a service | `[relay]`; `goatrope install` writes `goatrope-relay.service` | built ([ADR 0004](docs/adr/0004-relay-1-0.md) §1) |
| UDP rules, remote to link, with replies | `[relay].allow`, `protocol = "udp"`, `direction = "remote-to-link"` or `"both"` | built ([ADR 0002](docs/adr/0002-relay.md)) |
| TCP rules, and traffic that machines on the link start | `protocol = "tcp"`; `direction = "link-to-remote"` with `sources` | built (ADR 0004 §2) |
| Multicast groups on the link | | designed (ADR 0004 §3), not built |
| A remote machine under a local address of its own | `[[relay.proxy]]` and a rule's `link_address` | built (ADR 0004 §4) |
| Frames from a tap port sent to a remote collector as ERSPAN | `[[tap.mirror]]` | designed (ADR 0004 §5), not built; the kernel path it uses is measured in [performance.md](docs/performance.md) |
| One port bridged to one peer, filtered by EtherType and source MAC | `[[relay.l2]]` with `accept_layer2 = true` | built (ADR 0004 §6); also run in the emulated arm64 VM |
| A dedicated tunnel to a boundary point | `transport = "boundary"`, `[relay.boundary]` | built |
| Batched UDP forwarding | a rule's `receive_buffer_kb` (default 8,192) | built ([ADR 0006](docs/adr/0006-data-path.md)) |
| UDP forwarding inside the kernel (a tc program), opt-in; netfilter does not see its datagrams | `kernel_path = true`, and `kernel_path_bypasses_netfilter = true` where netfilter has rules for these interfaces | built (ADR 0006) |
| Conversion in the send process, with the goat-transformers engine linked in | `convert` in a `[[send]]`, with `packs_sha256` | built (ADR 0006) |
| Every phase on two machines joined by a real NetBird mesh | | not run yet |

Measured in network namespaces on one shared workstation ([performance.md](docs/performance.md)):
the relay forwards 77,000 to 218,000 datagrams of 64 bytes a second over WireGuard with under
0.1 % loss in user space and 290,000 to 356,000 with its kernel path, and the linked converter turns 22,581 to 52,666 Remote ID messages a second into
Cursor on Target, one message in 51 to 115 µs at p99. No hardware link and no real mesh is
measured yet.

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

`examples/` holds an inline tap (`inline.toml`), a listen tap behind a passive copper tap
(`listen-copper-tap.toml`), an ERSPAN listen tap (`listen-erspan.toml`), decode-and-send
(`send.toml`), and relays: over the mesh (`relay-over-mesh.toml`), to a boundary point
(`relay-boundary.toml`), started from the link (`relay-link-initiated.toml`), with an address
proxy (`relay-proxy.toml`) and with a layer-2 lane (`relay-l2.toml`).

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
| `goatrope relay-kernel-off` | removes every filter of the relay's kernel path, on any interface, with no declaration needed; the relay unit runs it after the relay stops |
| `goatrope packs-digest PACKS FROM TO` | prints the `version` and `packs_sha256` a `convert` with the linked engine declares for those packs |
| `goatrope l2 down` | closes every layer-2 lane (takes its GRETAP interface down); the relay unit runs it whenever the relay stops |
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
port is required), optionally converts each payload with the goat-transformers engine linked into goatrope,
and sends it to each destination: `udp://`, `tcp://`
(`framing = "len32be"` or `"raw"`), `http(s)://` (one POST per message, redirects
refused) or `file:///var/lib/goatrope/...` (`format = "jsonl"` or `"raw"`, and
`max_mb`: the file is cut there and one older file kept). A destination whose
route leaves through a tap port, or whose name does not resolve, is refused at
install and at send time: decode-and-send never transmits on the tapped link. TCP
stream reassembly is not built.

A `convert` converts with the goat-transformers engine linked into goatrope
([ADR 0006](docs/adr/0006-data-path.md)), the only converter: the send process loads the two
packs and the model modules they use once, at start, and converts each message in process.
`version` must be the linked engine's (`0.8.0`), and `packs_sha256` pins what it loads;
`goatrope packs-digest <packs> <from> <to>` prints both. The files are read once, hashed,
and the engine loads those same bytes; a digest that differs refuses the start, and `check`
reports it. A `convert` that names a goat-xf `binary` is refused. One conversion takes a
millisecond or less (Remote ID to Cursor on Target on amd64: p99 110 to 115 µs over 10,000
messages, asserted by phase `linked-engine`); loading the two packs at start takes 0.1 to
0.4 s and 3.3 MiB.
`status` shows each conversion's count, p50, p99 and maximum time. Rates are in
[performance.md](docs/performance.md).

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

The relay sleeps in `poll` until a socket is readable, takes up to 64 datagrams from it in one
`recvmmsg` call, applies the rule to each, and sends the allowed ones in one `sendmmsg` call.
A UDP rule may set `receive_buffer_kb` (256 to 1,048,576; 8,192 when not set), the receive
buffer of each of its sockets, which holds a burst while the relay is not running
([ADR 0006](docs/adr/0006-data-path.md); rates in [performance.md](docs/performance.md)).

The relay can also forward in the kernel, opt-in: `kernel_path = true` in `[relay]` makes it
attach a tc program to the WireGuard interface's ingress (`pref 3000`) that forwards the
datagrams of the UDP `remote-to-link` and `both` rules (IPv4, no proxy address) straight to the
link, without waking the relay ([ADR 0006](docs/adr/0006-data-path.md)). The program forwards
only what the relay's socket would accept for a rule, and only when well formed (no IP options,
a valid header checksum, not a fragment, lengths consistent, within the link's MTU); it sends
each as the relay's link socket would (the relay's link address and that socket's port, to the
rule's target, TTL 64). Everything else reaches the relay's sockets as before: every denial,
fragments, the target's replies (sent to the remote the program last saw), IPv6,
`link-to-remote` rules and rules with a proxy address. It follows addresses added to and removed
from the WireGuard interface (up to 8 IPv4 addresses) and the link's MTU within 2 s.

**The mesh's ACL and the host firewall do not see kernel-path datagrams.** tc ingress runs
before netfilter's PREROUTING and INPUT, and the redirect skips OUTPUT and POSTROUTING, so for
those datagrams the relay's own default-deny rules are the only control. If netfilter has any
rule that can see the WireGuard interface's input or the link interface's output (a NetBird
mesh always installs rules on its interface), the relay refuses to start with `kernel_path =
true` unless the declaration also says `kernel_path_bypasses_netfilter = true`, accepting that
by name. A rule that matches another interface by name does not count; a base chain with policy
drop does; when the ruleset cannot be read (nf_tables loaded and no `nft` command), it refuses.

| `[relay]` key | Default | Means |
|---|---|---|
| `kernel_path` | `false` | `true`: forward the eligible rules in the kernel |
| `kernel_path_bypasses_netfilter` | `false` | `true`: accepted that netfilter does not see kernel-path datagrams; needed when netfilter has rules for these interfaces |

The program needs `CAP_BPF`, which the unit grants and the relay drops once the program is
attached. When it cannot be loaded, the relay says why and forwards everything in user space.
No filter outlives the relay: before it starts, the relay removes any filter of its program on
any interface, whatever its declaration says, and refuses to start if one cannot be removed; it
removes its own on the way out; the unit's `ExecStopPost` runs `goatrope relay-kernel-off`,
which needs no declaration, after any exit; `uninstall` removes it too. `relay.health` gives
`kernel_path` (loaded and its mode, or why not) and each rule's `kernel_to_link` and
`kernel_failed`; `status` prints them; `check` compares the filters at `pref 3000` on every
interface with the one the declaration would attach (`relay-kernel-path`) and exits 3 on any
difference, a stray filter included.

A datagram larger than the tunnel's MTU less 28 bytes (1,392 on WireGuard's 1,420) crosses the
tunnel as fragments and is relayed whole. After an overload of fragments, fragmented traffic
is lost until the kernel's reassembly entries time out (`net.ipv4.ipfrag_time`, 30 s by
default; goatrope does not change it) while unfragmented traffic keeps flowing.
`relay.health` carries `reassembly` (this machine's reassembly failures and time-outs since
the relay started), and `status` prints them when there are any.

## Layer-2 lane (opt-in)

A `[[relay.l2]]` table bridges one dedicated port with a GRETAP interface to one mesh peer
([ADR 0004](docs/adr/0004-relay-1-0.md) §6), so machines on the two links exchange frames
as on one segment, within declared lists. It is refused unless the table says
`accept_layer2 = true`: the lane keeps the risks [ADR 0002](docs/adr/0002-relay.md) lists for
a layer-2 tunnel (the far side's ARP and broadcasts, any address it claims, the tunnel's loss
and latency on every frame), bounded by the lists. `examples/relay-l2.toml` is one end; the
far end declares the same lane with `peer` and `local` swapped and its own `macs`. Status:
built; tested in network namespaces on Ubuntu 24.04 and 26.04 and in the emulated arm64 VM.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | 1 to 11 lowercase letters, digits or hyphens; the bridge is `l2b-<name>`, the GRETAP interface `l2g-<name>` |
| `port` | yes | a dedicated Ethernet port: no address, IPv6 off (`disable_ipv6 = 1`), in no other bridge, no qdisc of anyone else's; never a tap port, the management interface, or the relay's link or remote interface |
| `peer`, `local` | yes | the far end's and this end's IPv4 tunnel addresses on `remote_interface`; `local` must be held there, and on the mesh a WireGuard peer must be allowed `peer`. With `transport = "boundary"`, they are the boundary point and this end |
| `key` | yes | the GRE key (1 to 4294967295), the same at both ends |
| `accept_layer2` | yes, `true` | the operator's acceptance of the lane by name |
| `ethertypes` | yes, 1 to 16 | e.g. `["0x0806", "0x0800"]`. A VLAN tag (0x8100, 0x88a8, 0x9100) is refused, because the filter sees only the outer EtherType |
| `macs` | yes, 1 to 64 | source MAC addresses accepted from across the tunnel; group and all-zero addresses are refused |

The relay makes the lane when it starts, and owns it while it runs:

| Part | As made |
|---|---|
| bridge `l2b-<name>` | the port and the GRETAP interface only; STP off, forward delay 0; no address and no IPv6 address (`addrgenmode none`); multicast snooping and querier off, so multicast floods to the one other member; no VLAN filtering; link-local group frames (01:80:C2:00:00:0X) not forwarded. A tc drop on its own ingress and egress: this machine neither receives from the lane nor sends into it |
| GRETAP `l2g-<name>` | `local` to `peer`, keyed, bound to `remote_interface`; MTU 1500 with `nopmtudisc` and `ignore-df`, so a 1,514-byte frame crosses as two outer fragments over a WireGuard MTU below 1,500 |
| filters (tc flower, clsact ingress) | from the port: only the declared EtherTypes. From the tunnel: only the declared EtherTypes from the declared source MACs, and ARP only when its sender hardware address is that source MAC too. Then a matchall drop. Each filter carries a cookie naming what it passes; `goatrope status` and `tc -s filter show` count what passed and what was dropped |
| state | the GRETAP interface is up only while the WireGuard peer that owns `peer` has a handshake younger than 180 s, read every 2 s; down otherwise. The relay takes it down when it stops (SIGTERM, or the unit's `ExecStopPost=goatrope l2 down` after any stop, a crash included) |

The relay refuses to start when the port is not as above, `ip` or `tc` is missing, the lane's
interface names are taken by another kind of interface, or `net.bridge.bridge-nf-call-iptables`,
`-ip6tables` or `-arptables` is 1 (bridged frames would pass through the firewall and its NAT).
IP forwarding stays off: the relay's forwarding check covers the port, the bridge and the
GRETAP interface too. Every 2 s the relay re-reads the lane; when any part differs from the
declaration (a filter removed or changed, the bridge or the GRETAP interface deleted, a setting
changed), it closes every lane and stops (exit 1), and the unit's restart builds the lane again.
`check` reports each part (`l2:<name>:bridge`, `:gretap`, `:port`, `:filters:<interface>`,
`:bridge-nf-call`); `uninstall` deletes the bridge and the GRETAP interface and removes the
port's filters. The port's own settings (IPv6, up) are the operator's and are not restored.

Each end needs a WireGuard peer that handshakes: when neither end sends a persistent keepalive
(NetBird sends one every 25 s), an idle tunnel stops handshaking and the lane stays down until
other traffic to the peer renews it. The relay prints a warning at start when this end's peer
has none.

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
- decode-and-send to UDP, TCP, HTTP and file destinations, fragment reassembly, and a
  file destination cut at `max_mb`;
- `relay-kernel`: off unless declared; with `kernel_path = true` it forwards 200 of 200 allowed
  datagrams, each as the relay's socket sends it, IP and UDP checksums verified in the captured
  frames; crafted packets sent into the tunnel (a UDP checksum of 0, IP options, fragments, bad
  UDP and IP lengths, a bad IP checksum, a destination that is not the relay's, another peer's
  source) are forwarded by the kernel only when well formed, and otherwise reach the link
  exactly as with the socket path alone; still denied: another peer, a port with no rule, the
  rule's addresses over the underlay; fragments and datagrams over the link MTU go by the
  socket path; an address added to and removed from wg0 is followed; replies return; a
  netfilter rule for wg0 refuses it unless `kernel_path_bypasses_netfilter = true`, and then
  that rule does not see its datagrams; a killed relay's filter is removed by the next relay
  and by `relay-kernel-off` with no valid declaration; without `CAP_BPF` it forwards in user
  space; the service drops `CAP_BPF`, `check` matches the filter and reports a stray one, its
  `ExecStopPost` removes the filter after a kill and with an invalid declaration, and
  `uninstall --purge` removes it;
- `fragments`: a 1,400-byte datagram relayed and a 1,514-byte frame mirrored whole over a
  1,420-byte tunnel; after an overload of them, unfragmented datagrams and small frames still
  cross, `relay.health` counts the reassembly failures, and fragmented traffic crosses again
  once `ipfrag_time` has passed;
- `linked-engine`, with the packs of the pinned goat-transformers commit (run.sh copies them from
  Cargo's checkout): a `convert` converts 50 of 50 Remote ID messages to Cursor
  on Target in the send process, and over 10,000 more, p99 of one conversion 1 ms or less
  (asserted on amd64); another `version` and a goat-xf `binary` are refused; a changed pack
  makes `check` exit 3 and is refused at start;
- `components`, when `GOATROPE_TEST_COMPONENTS` names a directory holding them: the
  linked engine converting with the given packs in a `[[send]]`, and the real
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
- `l2` (ADR 0004 module 6): refusals without `accept_layer2` and of bad lists; ARP, IPv4 and a
  declared EtherType crossing both ways between two link hosts, each behind its own lane end,
  over real WireGuard; an undeclared EtherType, an undeclared source MAC and a spoofed ARP sender
  dropped and counted; a 1,472-byte ping over a WireGuard MTU of 1,280 (NetBird's); a start that
  fails while making the lane removes what it made; the lane down within
  180 s and one tick of the last handshake and up again when it is fresh; check 3 when a filter,
  the GRETAP interface or the bridge is removed, and 0 once the restarted relay builds it again;
  uninstall leaves nothing;
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
own watchdog, forced link speed (veth cannot be forced), recording throughput, and the phases
on two machines joined by a real NetBird mesh.

`bench`, in a container of its own after the others, measures the data paths: relay UDP
over real WireGuard, the remote mirror, and decode-and-send with a converter. It records
numbers and passes or fails nothing; [performance.md](docs/performance.md) has the method
and the results.

## Layout

| Path | Holds |
|---|---|
| `bin/goatrope` | the entry point: runs `bin/x86_64/goatrope` or `bin/aarch64/goatrope`, which `tools/build-bin.sh` builds and each release archive holds |
| `src/` | the Rust source: `config.rs` (the declaration), `tap.rs`, `send.rs`, `engine.rs` (the linked converter), `relay.rs`, `kpath.rs` (the relay's kernel path), `proxy.rs`, `l2.rs` (the layer-2 lane), `boundary.rs`, `nl.rs` and `link.rs` (netlink; WireGuard peers and their handshakes), `sys.rs` and `sysutil.rs`, `main.rs`; one static binary ([ADR 0003](docs/adr/0003-goatrope-is-written-in-rust.md)) |
| `deploy/ansible/` | the play and role that install the tap from a release file |
| `examples/` | declarations with placeholder names and documentation addresses |
| `tests/netns/` | the namespace tests, their container, and `benchgen.py` (the `bench` phase's traffic generator) |
| `tools/` | `build-release.sh` (the archive and SHA256SUMS), `check-release.sh` (the release is exactly its three files) |
| `docs/` | ADRs, hardware, install card |

## License

Written by U.S. Federal government employees; public domain in the U.S., Apache
License 2.0 elsewhere. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [INTENT.md](INTENT.md).
