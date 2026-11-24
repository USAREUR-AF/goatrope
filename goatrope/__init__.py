# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""goatrope: one small machine on an Ethernet link, in declared roles (tap, decode-and-send, relay)."""
import os as _os


def _version() -> str:
    here = _os.path.dirname(_os.path.abspath(__file__))
    for path in (_os.path.join(here, "VERSION"), _os.path.join(here, "..", "VERSION")):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            continue
    return "unknown"


VERSION = _version()
