#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Build the static goatrope binary for this machine's architecture (or the one named)
# into bin/<arch>/goatrope, where bin/goatrope finds it.
#
#   tools/build-bin.sh            this machine's architecture
#   tools/build-bin.sh aarch64    another, when a linker for it is installed
#
# Needs rustup (the toolchain is pinned in rust-toolchain.toml). Without cargo on the
# machine, GOATROPE_BUILD_IN_DOCKER=1 builds in the rust image instead.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-$(uname -m)}"
case "$arch" in x86_64|aarch64) ;; *) echo "unsupported architecture $arch" >&2; exit 2 ;; esac
target="$arch-unknown-linux-musl"
if [ "${GOATROPE_BUILD_IN_DOCKER:-0}" = 1 ]; then
    toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
    docker run --rm -u "$(id -u):$(id -g)" -e CARGO_HOME=/work/target/cargo-home -v "$repo:/work" -w /work \
        "rust:$toolchain" sh -c "rustup target add $target >/dev/null && cargo build --release --locked --target $target"
else
    rustup target add "$target" >/dev/null
    cargo build --manifest-path "$repo/Cargo.toml" --release --locked --target "$target"
fi
mkdir -p "$repo/bin/$arch"
install -m 0755 "$repo/target/$target/release/goatrope" "$repo/bin/$arch/goatrope"
echo "built $repo/bin/$arch/goatrope ($("$repo/bin/goatrope" --version 2>/dev/null || echo "for $arch"))"
