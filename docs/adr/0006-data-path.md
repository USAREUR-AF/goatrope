<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0006: The data path: where goatrope handles the bytes of each path

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-28 |
| Deciders | operator |
| Owner | `goat-owners` |
| Related | [ADR 0002](0002-relay.md), [ADR 0003](0003-goatrope-is-written-in-rust.md), [ADR 0004](0004-relay-1-0.md), [performance.md](../performance.md) |

## Decision

| Path | Where the bytes are handled | Measured ceiling (Ubuntu 24.04 / 26.04) | Status |
|---|---|---|---|
| Relay UDP | user space, one thread that sleeps in `poll` until a socket is readable (no busy polling); batched: `recvmmsg` takes up to 64 datagrams in one call, the rule is applied to each, `sendmmsg` sends the allowed ones in one call; each rule's sockets have the receive buffer the rule declares (`receive_buffer_kb`, default 8 MiB); every UDP rule goes through one internal interface (`Datapath` in `src/relay.rs`) | 97,260 to 157,750 datagrams/s at 64 bytes over two runs on each version, loss under 0.1 % (one call per datagram before: 21,509 / 54,388) | built |
| Relay UDP in the kernel | a tc program on the WireGuard interface rewrites addresses, ports and checksums and redirects to the link interface (`bpf_redirect_neigh`) | 173,274 to 297,510 datagrams/s at 64 bytes over two runs on each version (prototype, `tests/netns/relay_tc.c`); WireGuard alone carried 137,851 to 344,808 | designed, not built |
| Relay TCP (ADR 0004 module 2) | user space (`src/relay_tcp.rs`); a connection's rate is bounded by the connection, not by a per-datagram cost | not measured | as module 2 built it |
| Remote mirror (ADR 0004 module 5) | the kernel: tc `mirred` to an ERSPAN type II interface; no user space | 204,061 to 238,555 frames/s at 64 bytes and 85,397 to 169,706 at 1,514 bytes, none lost, over six runs | as module 5 builds it |
| Layer-2 lane (ADR 0004 module 6) | the kernel: a bridge of the port and a GRETAP interface, tc flower filters; no user space | not measured; the same kind of path as the mirror | as module 6 builds it |
| Decode-and-send, conversion | the goat-transformers engine linked into goatrope, in the send process, the only converter; packs loaded once at start, pinned by digest | 22,581 to 52,666 messages/s over two runs on each version (goat-xf run once per message, before: 0.4 to 0.6); one conversion p99 51 to 115 µs, asserted ≤ 1 ms | built; the goat-xf `binary` form is removed |
| Fragmented datagrams and frames | relayed and mirrored as fragments; the kernel reassembles them; the relay counts this machine's reassembly failures in `relay.health` | after an overload of fragments, unfragmented datagrams 200 of 200, fragmented 0 of 100, and 100 of 100 again after `ipfrag_time` | built; see [Fragments](#fragments) |
| Decode-and-send, capture | user space, one `recv` per frame on an `AF_PACKET` socket | not measured apart from conversion | unchanged |

The numbers are from the `bench` phase on one shared workstation whose load changed
between runs; [performance.md](../performance.md) has the method and every number.

## Relay UDP

The relay received and sent one datagram per system call. Its socket was where the loss
happened: offered more than it took, it dropped hundreds of thousands of datagrams in its
receive buffer (counted in `RcvbufErrors`), and it forwarded about a fifth of what WireGuard
alone carried on the same path.

The UDP loop now goes through one interface, `Datapath::pump(rule, socket)`: forward what is
waiting on one of a rule's sockets, counting every datagram as sent, denied or failed. Its
one implementation, `Batched`, takes up to 64 datagrams per `recvmmsg`, applies the rule to
each (the sender must be one the rule accepts; replies only from the destination, only for
`both` and `link-to-remote`), and sends the allowed ones with one `sendmmsg` per outgoing
socket, from the same buffers. It takes at most 8 batches from one socket before serving the
others. A datagram that cannot be sent is counted and the rest of the batch is sent.

Batching alone raised what the relay delivers when offered more than it takes (63,000 to
137,000 a second at 64 bytes) but not the rate without loss: the relay's one thread shares
the processors with everything else, and while it is not running a burst overflows the
default receive buffer (208 KiB). Each UDP rule now declares how much its sockets may hold,
`receive_buffer_kb` (256 to 1,048,576; 8,192 when the rule names none). The relay sets it
with `SO_RCVBUFFORCE`, which the unit's `CAP_NET_ADMIN` allows (`SO_RCVBUF`, up to
`net.core.rmem_max`, otherwise), so a burst waits instead of being dropped. A rule's buffer
is memory the kernel may hold for that rule; a rule carrying a fast feed is given more, a
rule carrying a few datagrams a second can be given the minimum.

The loop does not busy-poll: it sleeps in `poll(2)` until a socket is readable (or for 1 s,
to write `relay.health`), then drains each readable socket with non-blocking `recvmmsg`
calls until one returns less than a full batch, and at most 8 batches before serving the
others. `SO_BUSY_POLL` is not set. The rules, the counters, `relay.health` and the refusals
are unchanged; the relay test phases pass unchanged.

| Option | 64 B | 512 B | 1,400 B | Kept |
|---|---|---|---|---|
| one datagram per call, default buffer (before) | 21,509 / 54,388 | 44,931 / 53,756 | 31,807 / 6,007 | no |
| batched, default buffer (24.04 only) | 59,890 | 27,709 | 35,720 | no |
| batched, 8 MiB buffer (after) | 135,612 / 157,750 and 97,260 / 111,552 | 90,224 / 169,228 and 99,537 / 102,024 | 69,202 / 129,292 and 66,502 / 36,265 | yes |
| tc program in the kernel (prototype) | 214,501 / 297,510 and 193,668 / 173,274 | 345,632 / 336,930 and 165,173 / 218,871 | not handled: fragments go to the socket | designed, not built |
| WireGuard alone, no relay (the path's own limit) | 323,619 / 344,808 and 285,482 / 137,851 | 321,755 / 343,431 and 257,005 / 295,927 | 138,335 / 151,392 and 60,387 / 91,677 | |

Datagrams per second with loss under 0.1 %, Ubuntu 24.04 / 26.04. Latency added by the relay
at 10,000 datagrams a second was within the run-to-run spread of the WireGuard-alone path
(p50 about 150 to 400 µs, p99 about 3 ms on this loaded host), except 64 B on 26.04 (p50 320
µs against 198 µs) and the 1,400-byte p99 on 24.04 (21 ms against 3.6 ms); the figures are in
[performance.md](../performance.md).

### The kernel path: designed, not built

`tests/netns/relay_tc.c` is a tc program for one `remote-to-link` rule: on the WireGuard
interface's ingress, a datagram from the rule's remote to the rule's port has its addresses,
ports and checksums rewritten and is redirected out of the link interface with
`bpf_redirect_neigh`, which fills in the Ethernet header from the neighbor table. Everything
else, fragments included, goes on to the relay's socket. The bench compiles it with clang
when clang is present and measures it on the same rule.

It is not built into goatrope, for these reasons:

- It needs a compiled BPF object in the release, or a compiler on the machine, a loader in
  the binary, and `CAP_BPF` and `CAP_NET_ADMIN` for the relay.
- The default deny moves into the program. The program is then the allow list, and `check`
  must read the loaded program and its rules back, as it reads tc filters today.
- Replies (`both`) need state: the remote's address and port, which the user-space relay
  learns from the first datagram. In the kernel that is a BPF map per rule, written by the
  program and read by `check` and `status`.
- The counters (`to_link`, `denied`, `send_errors`) would come from BPF maps.
- Fragmented datagrams still need the socket path, because the program sees one fragment
  at a time.

The prototype was made because user space did not get within a factor of 2 of WireGuard
alone: in seven of the eight 64- and 512-byte rows of the two runs, WireGuard alone carried
2.0 to 3.6 times what the batched relay did (the eighth, 1.2, is a 26.04 run whose
WireGuard-alone ceiling was low). The prototype carries 165,000 to 346,000 small datagrams a
second, 1.5 to 3.8 times the batched relay. It is built when a declared feed needs
more than the batched relay carries. The prototype,
the bench and this section are what that work starts from. The BPF object adds no crate to
goatrope.

## Converting in decode-and-send

goatrope ran `goat-xf convert` once per message. Each run reads every model module beside
the packs (69 MB in goat-transformers `37d2430`), so one message cost about 2 s and a
converted feed carried 0.4 to 0.6 messages a second (goatrope#29: 1.85 s per message on
x86-64 and 12.5 s on a Cortex-A55, where every conversion hit the 10 s limit).

The requirement: a message conversion takes a millisecond or less. It is a preplanned,
deterministic operation, and anything slower means something is wrong.

| Option | Messages/s (24.04 / 26.04) | Integrity | Kept |
|---|---|---|---|
| (i) goat-xf once per message (before) | 0.4 to 0.6 over four runs | the binary pinned by SHA-256, hashed and copied in one read, the copy runs | no, removed |
| (ii) one long-lived goat-xf-pipe per `[[send]]`, fed over a pipe | 2,849 to 32,395 over four runs (goat-xf-pipe alone, on UDP, outside goatrope, loss under 0.1 %) | the same binary pin | no |
| (iii) the engine linked into goatrope | 22,581 to 52,666 over three runs on each version (offered more than it takes; at 90 % of that rate 55 % to 99 % arrived) | the engine is part of the goatrope binary; the packs pinned by digest and loaded from the bytes that were hashed | yes, the only path |

(ii) is not taken. goat-xf-pipe converts and also delivers: its outputs are its own
endpoints. Fed over a pipe and read back, a message that fails conversion gives no output
line, so goatrope could not match outputs to inputs without a framing goat-xf-pipe does not
have. Letting goat-xf-pipe send to the destinations itself would bypass goatrope's route
guard (never send through a tap port) and its file and HTTP destinations.

(iii) meets it. Timed in the send process around each call (hex encoding, the engine,
trimming the output), Remote ID to Cursor on Target on amd64:

| Run | Conversions | p50 | p99 | max |
|---|---|---|---|---|
| phase `linked-engine`, 2,000 messages a second, three runs | 10,050 each | 51 to 54 µs | 110 to 115 µs | 433 µs to 16.3 ms |
| bench, offered more than it takes, 24.04 | 273,426 | 28.6 µs | 51.0 µs | 30.4 ms |
| bench, offered more than it takes, 26.04 | 271,223 | 28.1 µs | 51.1 µs | 70.4 ms |

p50 and p99 are over the last 16,384 conversions. A maximum above 1 ms is the send process's
one thread waiting for a processor on a host whose load average was 25 to 40 (the time is
wall-clock around the call), not the engine's work; the maxima above 1 ms all came from runs
beside the functional suite or the bench. Phase `linked-engine` asserts p99 ≤ 1 ms on amd64 (other
architectures report the number), and `status` and the send heartbeat show the count, p50,
p99 and max of every running conversion.

The one-time load at start, for the named packs only: 5 files (two `pack.def` and the three
model modules they use) in 0.093 to 0.40 s over five starts, with the process resident at
3.3 MiB afterward and at most 7.5 MiB during it. Not measured on arm64 hardware. Most of that time is reading every file of `model/` once (69 MB in
`37d2430`) to find which module each holds: the model directory has no index of module names.
goat-xf's 1.85 s and about 400 MiB come from loading every model module even with
`--packs-only` (goat-transformers `Engine::load_tree` loads every file of the model
directory); goat-xf-pipe and goatrope's linked load select the modules the packs use. That
is a goat-transformers defect in goat-xf, which goatrope no longer runs.

(iii) is taken, and it is the only converter: it measured faster than (ii) in every run
(22,581 to 52,666 against 2,849 to 32,395), and it keeps goatrope's route guard and
destinations. The engine (`engines/rust` of goat-transformers) uses only the standard
library and has no dependency of its own. It is a git dependency of goatrope at a fixed
commit (Cargo.toml names it, Cargo.lock records it, and a unit test holds `src/engine.rs` to
Cargo.lock), so the code that converts is the goatrope binary the deployment already pins
and verifies. A `convert` declares:

```toml
convert = { component = "goat-transformers", version = "0.8.0", from = "remote-id", to = "cot-xml",
            packs = "/usr/local/share/goat-transformers/packs", packs_sha256 = "<64 hex digits>" }
```

- `version` must be the linked engine's version; another is refused, naming the linked
  engine and its commit.
- `packs_sha256` pins the data the engine loads: each named pack's `pack.def`, and `core`
  with the model modules the packs use, transitively, from `model/` beside the packs
  directory. It is SHA-256 over, for each file in path order, its path relative to the tree
  (as if the packs directory were called `packs`), a NUL, its length in decimal, a NUL, and
  its bytes. `goatrope packs-digest <packs> <from> <to>` prints it.
- The send process reads those files once at start, hashes them, refuses to start when the
  digest is not the declared one, and loads the engine from the same bytes, so what was
  checked is what loads. `check` recomputes the digest from disk and reports a difference
  (exit 3), as it does for a pinned binary. This is the guarantee the pinned goat-xf had
  (hash and copy in one read, run the copy), now for the packs, while the engine's own code
  is covered by the pin on the goatrope binary.
- A `convert` naming a goat-xf `binary` or a `sha256` is refused, with the fix: remove them
  and declare `packs_sha256`. Upgrading the engine is a goatrope release.
- The engine runs in the send process, which `goatrope-send@<name>.service` restarts if it
  stops; one `[[send]]` failing does not stop another.

## Fragments

A UDP datagram larger than the tunnel's MTU less 28 bytes (1,392 bytes on WireGuard's default
1,420; 1,252 on 1,280) crosses the tunnel as IP fragments, and the receiving machine's kernel
reassembles it. When the tunnel drops some fragments under overload, the incomplete
datagrams hold reassembly memory (`net.ipv4.ipfrag_high_thresh`, 4 MiB) until they time out
(`net.ipv4.ipfrag_time`, 30 s by default). While it is full, every fragmented datagram that
arrives is dropped. Unfragmented traffic is not affected.

| Path | What goatrope does |
|---|---|
| Relay, toward the link | the relay machine reassembles the remote's fragments before the relay's socket sees the datagram; the relay sends the whole datagram on the link |
| Relay, toward the tunnel (replies, `link-to-remote`) | the relay sends the whole datagram; the kernel fragments it to the tunnel's MTU, and the remote reassembles it |
| Relay, both | `relay.health` carries `reassembly`: this machine's reassembly failures and time-outs (IPv4 and IPv6) since the relay started, and `status` prints them when there are any |
| Remote mirror | a full-size frame (1,514 bytes) in ERSPAN is larger than the tunnel's MTU, so its outer packet is always fragmented (ADR 0004 §5); the collector reassembles it |

goatrope relays datagrams above the tunnel MTU rather than dropping them, because a feed's
datagram size is the sensor's, not goatrope's. It does not change `ipfrag_time` or
`ipfrag_high_thresh`: they apply to the whole machine. The operator who needs fragmented
traffic to recover sooner after an overload lowers `ipfrag_time` on the machine that
reassembles (the relay machine, the remote, or the mirror's collector).

Phase `fragments` shows it on the relay and on the mirror (the mirror built with `ip` and
`tc` as module 5 builds it). A 1,400-byte datagram is relayed and a 1,514-byte frame is
mirrored whole, 100 of 100 each. Right after an overload of 1,400-byte datagrams, 200 of 200
unfragmented datagrams are relayed and 0 of 100 fragmented ones; `relay.health` counts the
failures; `ipfrag_time` plus 3 s later, 100 of 100 fragmented datagrams are relayed again.
Right after an overload of full-size frames, 200 of 200 small frames are mirrored; in that
run the collector's reassembly memory did not fill, and 100 of 100 full-size frames arrived
too.

## Kernel paths stay kernel paths

The remote mirror and the layer-2 lane are tc and bridge configurations: no frame of theirs
enters user space. The bench measured the mirror at the generator's limit for small frames.
They stay as ADR 0004 builds them.
