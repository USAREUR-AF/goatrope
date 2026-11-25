# Changelog

## Unreleased

- ADR 0003 (Proposed): goatrope is written in Rust; the declaration, commands, exit codes,
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
