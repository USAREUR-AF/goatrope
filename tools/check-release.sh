#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# The release is exactly three files, as a verifier that knows only the pin expects them:
# SHA256SUMS (listing the archive and nothing else), SHA256SUMS.cosign-bundle (cosign's legacy
# bundle: base64Signature, cert, rekorBundle) and the archive. Signatures are cosign's to check.
#
#   tools/check-release.sh <version> [directory, default dist]
set -euo pipefail
v="${1:?usage: check-release.sh <version> [directory]}"
cd "${2:-dist}"
a="goatrope-$v.tar.gz"
want=$(printf '%s\n' SHA256SUMS SHA256SUMS.cosign-bundle "$a" | LC_ALL=C sort)
have=$(find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort)
[ "$have" = "$want" ] || { printf 'the release holds:\n%s\nnot:\n%s\n' "$have" "$want" >&2; exit 1; }
grep -qxE "[0-9a-f]{64}  $a" SHA256SUMS && [ "$(wc -l < SHA256SUMS)" = 1 ] || { echo "SHA256SUMS does not list $a alone" >&2; exit 1; }
sha256sum --quiet -c SHA256SUMS
python3 -I - <<'PY'
import base64, json
b = json.load(open("SHA256SUMS.cosign-bundle"))
assert set(b) == {"base64Signature", "cert", "rekorBundle"}, sorted(b)
base64.b64decode(b["base64Signature"], validate=True)
assert base64.b64decode(b["cert"], validate=True).startswith(b"-----BEGIN CERTIFICATE-----"), "cert"
assert set(b["rekorBundle"]["Payload"]) == {"body", "integratedTime", "logIndex", "logID"}, "Payload"
assert b["rekorBundle"]["SignedEntryTimestamp"], "SignedEntryTimestamp"
PY
echo "release shape: ok (SHA256SUMS sha256:$(sha256sum < SHA256SUMS | cut -d' ' -f1))"
