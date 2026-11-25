#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Build the static goatrope binary for this machine's architecture (or the one named)
# into bin/<arch>/goatrope, where bin/goatrope finds it.
#
#   tools/build-bin.sh            this machine's architecture
#   tools/build-bin.sh aarch64    another, when a linker for it is installed
#
# Needs rustup (the toolchain is pinned in rust-toolchain.toml) and musl-tools. Without them
# on the machine, GOATROPE_BUILD_IN_DOCKER=1 builds in the rust image instead.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-$(uname -m)}"
case "$arch" in x86_64|aarch64) ;; *) echo "unsupported architecture $arch" >&2; exit 2 ;; esac
target="$arch-unknown-linux-musl"
# ring (the TLS library's cryptography) compiles some C: musl-gcc from musl-tools builds it.
cc_var="CC_${arch}_unknown_linux_musl"
if [ "${GOATROPE_BUILD_IN_DOCKER:-0}" = 1 ]; then
    toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
    docker run --rm -e CARGO_HOME=/work/target/cargo-home -e "$cc_var=musl-gcc" -v "$repo:/work" -w /work \
        "rust:$toolchain" sh -c "apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null \
            && rustup target add $target >/dev/null && cargo build --release --locked --target $target; \
            rc=\$?; chown -R $(id -u):$(id -g) target; exit \$rc"
else
    command -v musl-gcc >/dev/null || { echo "musl-gcc is missing: sudo apt-get install -y musl-tools" >&2; exit 1; }
    rustup target add "$target" >/dev/null
    env "$cc_var=musl-gcc" cargo build --manifest-path "$repo/Cargo.toml" --release --locked --target "$target"
fi
mkdir -p "$repo/bin/$arch"
install -m 0755 "$repo/target/$target/release/goatrope" "$repo/bin/$arch/goatrope"
# GOATROPE_BUILD_UNITS=1: also the unit-test binary the namespace tests run as root (never released).
if [ "${GOATROPE_BUILD_UNITS:-0}" = 1 ]; then
    units_cmd="cargo test --release --locked --target $target --no-run 2>&1 | sed -n 's/.*Executable unittests src\/main.rs (\(.*\))/\1/p'"
    if [ "${GOATROPE_BUILD_IN_DOCKER:-0}" = 1 ]; then
        exe=$(docker run --rm -e CARGO_HOME=/work/target/cargo-home -e "$cc_var=musl-gcc" -v "$repo:/work" -w /work \
            "rust:$toolchain" sh -c "apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null \
                && rustup target add $target >/dev/null && $units_cmd; chown -R $(id -u):$(id -g) target")
    else
        exe=$(cd "$repo" && env "$cc_var=musl-gcc" sh -c "$units_cmd")
    fi
    [ -n "$exe" ] || { echo "the unit-test binary was not built" >&2; exit 1; }
    install -m 0755 "$repo/$exe" "$repo/bin/$arch/goatrope-units"
fi
echo "built $repo/bin/$arch/goatrope ($("$repo/bin/goatrope" --version 2>/dev/null || echo "for $arch"))"
