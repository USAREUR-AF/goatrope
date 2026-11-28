<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Performance of the data paths

Status: measured in network namespaces on one machine; no hardware link and no real mesh
measured. The numbers come from the `bench` phase of `tests/netns/test_tap.py`, which
records them and passes or fails nothing.

## Results

Host: AMD Ryzen 7 8845HS (8 cores, 16 threads), Linux 7.0.0-27-generic, a shared
workstation whose load average was 21 to 51 during the runs. Other jobs ran on it, so two
runs of the same path differ: by a factor of ten for goat-xf-pipe (load 23 on the 24.04 run,
47 on the 26.04 run). Each trial lasted 3 s and each ceiling took 7 search steps
(`GOATROPE_BENCH_SECONDS=3 GOATROPE_BENCH_STEPS=7`), on main at `f1a7bb7` with this phase.

### Relay UDP over WireGuard (rule `remote-to-link`, port 7002)

| Payload | Ubuntu 24.04: datagrams/s, loss under 0.1 % | Ubuntu 26.04 | Delivered/s when offered all it can take (24.04) | WireGuard alone, no relay (24.04) | Added latency p50 / p99 at 10,000/s (24.04) |
|---|---|---|---|---|---|
| 64 bytes | 21,509 | 54,388 | 62,881 | 283,022 | 33 µs / below the noise |
| 512 bytes | 44,931 | 53,756 | 58,904 | 262,743 | 94 µs / 239 µs |
| 1,400 bytes (two fragments in the tunnel) | 31,807 | 6,007 | 944 | 60,870 | below the noise / 102 µs |

### Remote mirror (tc `mirred` to an ERSPAN type II interface over WireGuard)

| Frame | Ubuntu 24.04: frames/s, none lost at the collector | Ubuntu 26.04 |
|---|---|---|
| 64 bytes | 238,555 (the generator's limit) | 211,540 (the generator's limit) |
| 512 bytes | 201,356 (the generator's limit) | 173,191 |
| 1,514 bytes (outer packet in two fragments) | 169,706 (the generator's limit) | 85,397 |

### Decode-and-send with a converter (Remote ID to Cursor on Target)

| Converter | Ubuntu 24.04: messages/s | Ubuntu 26.04 |
|---|---|---|
| goat-xf run once per message, as goatrope does now (the real goat-xf, goat-transformers `37d2430`, with every model module) | 0.5 | 0.4 |
| goat-xf-pipe, one long-lived process, outside goatrope, loss under 0.1 % | 32,395 | 2,849 |

### After ADR 0006

The same bench on `feat/data-path`, run twice on each version: the relay batched with each
rule's receive buffer at its default, 8 MiB; the tc prototype; and the engine linked into
goatrope, the only converter. In the second run the functional suite ran beside the bench
(load average 25 to 40); in the first, 14 to 35.

| Path | Run 1, 24.04 / 26.04 | Run 2, 24.04 / 26.04 | Before (24.04 / 26.04) |
|---|---|---|---|
| Relay UDP 64 B, datagrams/s, loss under 0.1 % | 135,612 / 157,750 | 97,260 / 111,552 | 21,509 / 54,388 |
| Relay UDP 512 B | 90,224 / 169,228 | 99,537 / 102,024 | 44,931 / 53,756 |
| Relay UDP 1,400 B (two fragments in the tunnel) | 69,202 / 129,292 | 66,502 / 36,265 | 31,807 / 6,007 |
| Relay UDP 64 B in a tc program (the C prototype, before the kernel path was built) | 214,501 / 297,510 | 193,668 / 173,274 | |
| Relay UDP 512 B in a tc program (the C prototype, before the kernel path was built) | 345,632 / 336,930 | 165,173 / 218,871 | |
| WireGuard alone, 64 B | 323,619 / 344,808 | 285,482 / 137,851 | 283,022 / 364,853 |
| WireGuard alone, 512 B | 321,755 / 343,431 | 257,005 / 295,927 | 262,743 / 329,822 |
| WireGuard alone, 1,400 B | 138,335 / 151,392 | 60,387 / 91,677 | 60,870 / 116,969 |
| Remote mirror 64 B, frames/s, none lost (unchanged path) | 230,694 (the generator's limit) / 204,061 | 209,296 / 216,173 (the generator's limit) | 238,555 / 211,540 |
| Remote mirror 1,514 B | 160,072 (the generator's limit) / 135,098 | 106,770 / 101,377 | 169,706 / 85,397 |
| Decode-and-send, engine linked into goatrope, messages/s, offered more than it takes | 52,666 / 45,090 | 22,768 / 22,581 | 0.5 / 0.4 (goat-xf once per message) |
| the same, at 90 % of that rate: share that arrived | 55 % / 93 % | 99.1 % / 99.1 % | |
| One conversion, p50 / p99 / max (run 2, timed in the send process) | | 28.6 µs / 51.0 µs / 30.4 ms and 28.1 µs / 51.1 µs / 70.4 ms | about 2 s each |
| Pack load at start: time, resident memory after, peak (run 2) | | 0.093 s, 3,400 KiB, 7,392 KiB and 0.101 s, 3,296 KiB, 7,288 KiB | 1.85 s per message (goatrope#29) |

An earlier run with the buffer fixed at 8 MiB gave 142,394 / 143,690 (64 B), 120,862 /
122,937 (512 B) and 106,942 / 70,993 (1,400 B) for the relay, 251,847 / 229,515 and
288,993 / 201,699 for the tc prototype, and 50,126 / 37,500 for the linked engine. Batching
with the default 208 KiB buffer (24.04 only) gave 59,890, 27,709 and 35,720.

The phase `linked-engine` times 10,000 conversions at 2,000 a second on amd64 and asserts p99
≤ 1 ms: over three runs p50 51 to 54 µs, p99 110 to 115 µs, max 433 µs to 16.3 ms, and the
pack load 0.11 to 0.40 s. Under overload in the bench, the maximum is the
send process waiting for a processor on the loaded host: the time is wall-clock around the
call.

Latency at 10,000 datagrams a second (run 1), relay path p50 / p99 against WireGuard alone:
24.04 64 B 157 µs / 2.5 ms against 151 µs / 2.9 ms; 512 B 163 µs / 2.9 ms against 153 µs /
3.0 ms; 1,400 B 511 µs / 21 ms against 428 µs / 3.6 ms; 26.04 64 B 320 µs / 3.0 ms against
198 µs / 2.8 ms; 512 B 195 µs / 2.7 ms against 147 µs / 2.7 ms.

### The relay's kernel path

The relay with `kernel_path = true` (ADR 0006), and the same relay without it, in the same
run. Load average 12 to 23.

| Path | Ubuntu 24.04 | Ubuntu 26.04 |
|---|---|---|
| Relay UDP 64 B, user space, datagrams/s, loss under 0.1 % | 77,126 | 169,871 |
| Relay UDP 64 B, kernel path | 355,614 | 290,137 |
| Relay UDP 512 B, user space | 166,602 | 178,466 |
| Relay UDP 512 B, kernel path | 333,509 | 307,289 |
| Relay UDP 1,400 B, user space (fragments) | 136,849 | 116,317 |
| Relay UDP 1,400 B, kernel path declared (fragments take the socket path) | 134,000 | 125,618 |
| WireGuard alone, 64 B / 512 B / 1,400 B, kernel-path run | 340,567 / 339,744 / 156,933 | 351,840 / 384,690 / 125,768 |
| Dropped at the relay's socket when offered all it can take, 64 B: user space / kernel path | 618,797 / 0 | 619,717 / 0 |
| Decode-and-send, linked engine, messages/s / one conversion p50, p99, max | 37,895 / 18.2 µs, 32.9 µs, 1,406 µs | 34,894 / 26.6 µs, 44.4 µs, 1,200 µs |

The kernel path carries 0.80 to 1.04 times what WireGuard alone carries; both are at the range
of the one-process generator and sink (about 400,000 datagrams a second offered unpaced). An
earlier run, of the program before the length, checksum and MTU checks and the `conf` map,
gave 352,596 / 321,924 (64 B) and 363,637 / 372,296 (512 B), with user space at 218,068 /
169,079 and 160,049 / 166,393.

## What the numbers say

- **Relay UDP, before.** The relay forwarded 20,000 to 54,000 datagrams a second without
  loss, and 60,000 to 94,000 a second when offered more, while WireGuard alone carries
  260,000 to 360,000 small datagrams a second on the same path. The relay's socket is where
  the loss happens (the drops are counted in `RcvbufErrors`): one system call per datagram
  received and one per datagram sent, in one thread, and a 208 KiB receive buffer that a
  burst overflows while the thread is not running.
- **Relay UDP, after.** Batched system calls and an 8 MiB receive buffer: 90,000 to 218,000
  small datagrams a second without loss; WireGuard alone carries 2.0 to 3.6 times as much in
  seven of eight rows of the first two runs. The kernel path carries 290,000 to 372,000, what
  WireGuard alone carries, and drops nothing at the relay's socket. The 1,400-byte rows vary most between runs (in one
  26.04 run the WireGuard-alone ceiling, 27,533, was below the relay's), because a trial that
  overloads the fragment path spoils reassembly for the trials near it.
- **Fragments.** A 1,400-byte payload does not fit the 1,420-byte WireGuard MTU, so each
  datagram crosses the tunnel as two fragments. Under overload, fragments of half-dropped
  datagrams fill the kernel's reassembly memory and almost nothing is reassembled (944 a
  second) and the rate without loss is low (6,000 to 32,000 a second). With the default `ipfrag_time` of 30 s, one overload stops every fragmented
  datagram for the next 30 s; the bench sets it to 2 s so one trial does not spoil the next.
- **Remote mirror.** The kernel path (no user space at all) mirrors 85,000 to 240,000 frames a
  second with none lost, 1,514-byte frames in fragmented outer packets included; in four of
  six runs it kept up with everything the generator sent.
- **Decode-and-send.** Running goat-xf once per message costs about 2 s each, because each run
  reads every model module (69 MB). One long-lived process converts 2,800 to 32,000 messages a
  second. The engine linked into goatrope loads the three model modules the two packs use, in
  about 0.1 s and 3.3 MiB, and converts 22,000 to 53,000 messages a second in the send process,
  one message in 51 to 115 µs at p99.

## What is measured, and how

All of it runs in one privileged container with systemd (the namespace test container),
on the host's kernel. The generator and the sink are `tests/netns/benchgen.py`: one Python
process each, using `sendmmsg` and `recvmmsg` through ctypes, so they offer and count
several hundred thousand datagrams a second. Each datagram carries a run number, a sequence
number and the `CLOCK_MONOTONIC` time it was sent; the sink counts only its own run.

| Path | Topology | Count |
|---|---|---|
| Relay UDP | the relay test's namespaces: a remote namespace whose WireGuard interface (`wga`, MTU 1,420) is a peer of the relay machine's `wg0`; the relay (`goatrope relay`, foreground) forwards rule port 7002 to a host on the link (`r0`, veth) | datagrams that reached the link host's socket |
| WireGuard alone | the same tunnel to a socket on the relay machine, no relay | the same |
| Remote mirror | the listen test's veth `tp0` with a clsact qdisc and a `matchall` filter whose action is `mirred egress mirror` to an ERSPAN type II interface (`seq key 1`, `nopmtudisc ignore-df`, MTU 9,000) from `10.99.0.1` to `10.99.0.2` over `wg0`, the settings of ADR 0004 module 5; the collector is an ERSPAN interface in the remote namespace | its `rx_packets` counter |
| Decode-and-send | a listen tap on `tp0` with one `[[send]]`: match UDP port 5000, `convert` Remote ID to Cursor on Target, destination `udp://127.0.0.1:9201`; frames of a 25-byte Remote ID message injected at the far end of `tp0`. Before ADR 0006 the convert named a pinned goat-xf `binary`, run once per message; after, it is the engine linked into goatrope, with `packs_sha256` from `goatrope packs-digest` | converted messages at the destination |
| Relay UDP, kernel path | the same relay with `kernel_path = true` (nothing in netfilter, so no acceptance needed), and without it for the user-space rows; before the kernel path was built, a C prototype compiled with clang was measured in its place | as for the relay |
| goat-xf-pipe | `goat-xf-pipe --packs-only --from-format remote-id --in udp://127.0.0.1:9210 --out udp://127.0.0.1:9211 --to-format cot-xml`, run by the bench beside the container's goatrope | converted messages at the destination |

- **A ceiling** is found in one trial with the generator unpaced, then a binary search
  between 0 and that offered rate: a rate passes when the loss is at most 0.1 % (relay,
  goat-xf-pipe) or 0 (mirror). The table gives the highest offered rate that passed. "The
  generator's limit" means the unpaced trial already lost nothing.
- **Added latency** is the relay path's one-way latency minus the WireGuard-alone path's, at
  10,000 datagrams a second, one datagram per system call, p50 and p99 over the trial. On a
  loaded workstation the p99 of both paths is about 3 ms, so a p99 difference that is
  negative, or a p50 difference smaller than its run-to-run spread, is reported as below the
  noise.
- **Decode-and-send** is measured by offering far more than the converter takes for 12 s;
  the rate is the messages that arrived, from the first to the last, over the time between
  them. A second trial at 90 % of that rate gives the share that arrived.
- The packs are those of the goat-transformers commit goatrope links (run.sh copies them from
  Cargo's checkout), or those given in `GOATROPE_TEST_COMPONENTS`, which also gives
  `goat-xf-pipe`; without it, goat-xf-pipe is left out.

## Run it

```console
GOATROPE_BENCH_SECONDS=3 GOATROPE_BENCH_STEPS=7 GOATROPE_TEST_COMPONENTS=<dir> tests/netns/run.sh 24.04 26.04
```

`run.sh` runs `bench` last, in its own container, with 0.5 s trials and 4 search steps by
default (a quick run, as in CI); `GOATROPE_BENCH=0` leaves it out. Each result is a line
beginning `bench -` in the log and a record with `"result": "bench"`, its values and the
host in `ubuntu-<version>.results.jsonl`.
