<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to goatrope

Every commit on `main` is signed (SSH or GPG) and carries a Developer Certificate
of Origin sign-off (`git commit -S -s`).

Before a pull request:

```
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
tools/build-bin.sh              # the static binary, bin/<arch>/goatrope (needs musl-tools)
for f in examples/*.toml; do ./bin/goatrope validate --config "$f"; done
tests/netns/run.sh              # needs Docker on Linux; runs Ubuntu 24.04 and 26.04
```

goatrope is one statically linked Rust binary ([ADR 0003](docs/adr/0003-goatrope-is-written-in-rust.md)),
so it installs on a stock Ubuntu Server with no package beyond tcpdump and ethtool. Keep it
that way: a dependency that needs a library at run time is refused. The namespace tests and
`site/` stay Python scripts.

Never put a real address, port number, host name, site, unit, partner or message
format of a real deployment in a file, a test or a commit message. Examples use
placeholder interface names and documentation addresses.
