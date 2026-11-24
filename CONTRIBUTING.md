<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to goatrope

Every commit on `main` is signed (SSH or GPG) and carries a Developer Certificate
of Origin sign-off (`git commit -S -s`).

Before a pull request:

```
python3 -m py_compile goatrope/*.py bin/goatrope tests/netns/test_tap.py
for f in examples/*.toml; do ./bin/goatrope validate --config "$f"; done
tests/netns/run.sh              # needs Docker on Linux; runs Ubuntu 24.04 and 26.04
```

goatrope uses the Python 3 standard library only, so it installs on a stock Ubuntu
Server with no package beyond tcpdump and ethtool. Keep it that way.

Never put a real address, port number, host name, site, unit, partner or message
format of a real deployment in a file, a test or a commit message. Examples use
placeholder interface names and documentation addresses.
