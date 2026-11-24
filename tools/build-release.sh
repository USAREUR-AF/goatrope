#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Build the release archive and SHA256SUMS into dist/.
#
#   tools/build-release.sh <version>
#
# The archive is architecture-independent (Python 3 standard library only), so one
# archive serves arm64 and amd64. VERSION must equal <version>.
set -euo pipefail
v="${1:?usage: build-release.sh <version>}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(cat "$repo/VERSION")" = "$v" ] || { echo "VERSION is $(cat "$repo/VERSION"), not $v" >&2; exit 1; }
dist="$repo/dist"
rm -rf "$dist"
mkdir -p "$dist"
name="goatrope-$v"
# git archive: exactly the committed tree, with a fixed mtime from the commit.
git -C "$repo" archive --format=tar --prefix="$name/" HEAD \
    bin goatrope examples docs LICENSE LICENSES NOTICE INTENT.md README.md VERSION CHANGELOG.md \
    | gzip -n -9 > "$dist/$name.tar.gz"
(cd "$dist" && sha256sum "$name.tar.gz" > SHA256SUMS)
cat "$dist/SHA256SUMS"
