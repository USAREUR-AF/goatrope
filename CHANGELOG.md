# Changelog

## Unreleased

- tests: `tests/netns/run.sh` and `tests/arm64/run.sh` name their images by a hash of the
  Dockerfile (`goatrope-netns-<hash>`, `goatrope-qemu-arm64-<hash>`), so runs from trees whose
  Dockerfiles differ no longer overwrite each other's image on a shared host.
- namespace phase `bench` and docs/performance.md: the sustained rate of relay UDP over WireGuard
  (64, 512 and 1,400-byte payloads, loss under 0.1 %, added latency), of the remote mirror
  (frames with none lost at the collector) and of decode-and-send with a converter run once per
  message. Measurements only; run.sh runs it in its own container.
- relay address proxy (ADR 0004 module 4): `[[relay.proxy]]` gives a remote machine an IPv4 address
  of its own on the link, and a rule's `link_address` (any protocol or direction) uses it there. The
  relay adds it as a /32 (`noprefixroute`) only after an RFC 5227 ARP probe finds no other holder,
  announces it, holds it while the remote's WireGuard peer has a handshake younger than 180 s, and
  removes it when the handshake is stale, another machine claims it, or the relay stops. `check`,
  `status` and `relay.health` report it. Namespace phase `proxy`.
- relay TCP and link-initiated traffic (ADR 0004 module 2): `protocol = "tcp"` rules (accepted only
  from the rule's remote, a connection opened from the link address, copied both ways with
  half-close, `max_connections`, default 64); `direction = "link-to-remote"` for UDP and TCP, with a
  required `sources` list and `remote_port`; `both` refused for TCP. A dead peer frees its slot
  within 2 minutes (keepalive 60 s idle, 6 probes 10 s apart, and `TCP_USER_TIMEOUT` 120 s);
  `TCP_NODELAY` on both sockets. relay.health counts connections, bytes each way, denials and
  broken connections per rule. Namespace phase `relay-tcp`.
- relay service (ADR 0004 module 1): `goatrope install` writes and starts `goatrope-relay.service`
  for a declaration with `[relay]`, which may now be the only role; a refusal is not restarted.
  `check` reads the unit and the age of `relay.health` (stale after 10 s); `status` shows the rules
  and counters; `uninstall` removes the unit, `relay.health` and a boundary interface. `wip` is no
  longer required (`wip = true` is accepted and does nothing). Namespace phase `relay-service`.
- ADR 0004 (Accepted): the relay reaches 1.0 in six modules: a service, TCP and link-initiated
  traffic, multicast, an address proxy, a remote mirror over ERSPAN, and an opt-in layer-2 lane.

## 0.2.0 (2026-11-25)

- listen source `erspan`: goatrope makes an `erspan` interface for one declared mirror session
  arriving on an underlay address, and records and decodes from it (ADR 0003 step 5).
- goatrope is one static Rust binary for amd64 and arm64 (ADR 0003): the declaration,
  commands, exit codes, installed files and state file are unchanged, and a machine installed
  by 0.1.0 is checked, upgraded and removed by this release. The release archive holds both
  binaries and `bin/goatrope`, which runs the one for the machine.
- relay boundary transport: keys and the peer are set through netlink; the `wg` tool is not needed.
- ADR 0003 (Accepted): goatrope is written in Rust; the declaration, commands, exit codes,
  release shape and namespace tests stay as they are.
- landing page (site/) and its Pages workflow.
- relay: `transport = "mesh"` (default) uses the site's existing WireGuard mesh and creates no tunnel;
  `transport = "boundary"` reaches a site outside the deployment through a dedicated WireGuard
  interface with exactly one peer, the declared boundary point, checked at start and while running.
- `goatrope boundary key|sheet|up|check|down`.

## 0.1.0 (2026-11-24)

- tap: inline and listen modes; install, status, check (exit 0 / 3), uninstall.
- decode-and-send: UDP, TCP, HTTP and file destinations; pinned goat-transformers
  convert; pinned first-bite decoder unit.
- relay: WIP fixed-port UDP forwarder through WireGuard (ADR 0002).
- release: exactly the archive, SHA256SUMS and SHA256SUMS.cosign-bundle, signed keylessly at the tag.
- deploy: `goatrope deploy` and an Ansible play that installs the tap from a verified release file.
- network-namespace tests on Ubuntu 24.04 and 26.04; the same tests in an emulated
  arm64 VM (`tests/arm64/run.sh`); NetworkManager and the real goat-xf and mind
  binaries in their own phases.
