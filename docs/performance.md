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

## What the numbers say

- **Relay UDP.** The relay forwards 20,000 to 54,000 datagrams a second without loss, and
  60,000 to 94,000 a second when offered more, while WireGuard alone carries 260,000 to
  360,000 small datagrams a second on the same path. The relay's socket is where the loss
  happens (the drops are counted in `RcvbufErrors`): one system call per datagram received
  and one per datagram sent, in one thread.
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
  second.

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
| Decode-and-send | a listen tap on `tp0` with one `[[send]]`: match UDP port 5000, `convert` Remote ID to Cursor on Target, destination `udp://127.0.0.1:9201`; frames of a 25-byte Remote ID message injected at the far end of `tp0` | converted messages at the destination |
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
- **A converter run once per message** is measured by offering far more than it can take for
  12 s; the rate is the messages that arrived, from the first to the last, over the time
  between them.
- The bench uses `GOATROPE_TEST_COMPONENTS` for the real `goat-xf` and `goat-xf-pipe`.
  Without them it measures the stand-in converter (a shell script running `tr`) and leaves
  goat-xf-pipe out, and says so in its result line.

## Run it

```console
GOATROPE_BENCH_SECONDS=3 GOATROPE_BENCH_STEPS=7 GOATROPE_TEST_COMPONENTS=<dir> tests/netns/run.sh 24.04 26.04
```

`run.sh` runs `bench` last, in its own container, with 0.5 s trials and 4 search steps by
default (a quick run, as in CI); `GOATROPE_BENCH=0` leaves it out. Each result is a line
beginning `bench -` in the log and a record with `"result": "bench"`, its values and the
host in `ubuntu-<version>.results.jsonl`.
