<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

goatrope changes a machine's network interfaces, and in inline and relay modes it
transmits on a link. Security reports come before feature work.

Report a vulnerability privately through the repository's GitHub private
vulnerability reporting (the **Security** tab, **Report a vulnerability**), never
in a public issue. Include what the issue is, how to reproduce it, and the affected
versions or configurations. Use documentation addresses (RFC 5737, RFC 3849), not
real ones.

Known limits, not vulnerabilities: inline mode is fail-closed by design; a root
process that sends with `PACKET_QDISC_BYPASS` skips the listen-mode egress drop
([hardware.md](docs/hardware.md)).
