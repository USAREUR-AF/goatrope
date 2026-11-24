<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Deploying goatrope from its release

A deploy driver that keeps release files at `/opt/goat/releases/<component>/<sha256>/<name>`,
with `current` and `previous` links beside them, installs the tap with
`deploy/ansible/goatrope-deploy.yml`. Putting the file in place starts nothing; this play does.

## The release

A tag `goatrope-v<version>` publishes exactly three files, checked by `tools/check-release.sh`:

| File | Holds |
|---|---|
| `goatrope-<version>.tar.gz` | the software; one archive for arm64 and amd64 |
| `SHA256SUMS` | the archive's SHA-256. The pin's digest is this file's SHA-256 |
| `SHA256SUMS.cosign-bundle` | the keyless signature over `SHA256SUMS`, cosign's legacy bundle |

The signer is `https://github.com/<owner>/goatrope/.github/workflows/release.yml` at the tag.
`<owner>` is not decided. A component declaration:

```yaml
goatrope:
  var: goatrope_release
  artifact_type: release
  deploy_playbook: goatrope-deploy.yml
  fleet: "<owner>/goatrope@goatrope-v<version>@sha256:<SHA-256 of SHA256SUMS>"
  release:
    checksums: SHA256SUMS
    files: {amd64: goatrope-<version>.tar.gz, arm64: goatrope-<version>.tar.gz}
    signer: https://github.com/<owner>/goatrope/.github/workflows/release.yml
```

The archive's name carries the version, so `files` changes with the pin.

## The play

Copy `goatrope-deploy.yml` and `roles/goatrope-tap` beside the driver's `release-file` role, which
the play calls. It takes the driver's variables unchanged (`release_file_files`,
`release_file_rollback` and the rest) and handles one machine at a time:

1. **Preflight.** goatrope, from the verified archive, makes every refusal `install` makes and
   changes nothing. A refused machine keeps its `current`, its ledger and its running tap.
2. **`release-file`** puts the archive in place, or goes back to `previous`.
3. **`goatrope deploy`**, from the archive `current` names and only if its SHA-256 is its
   directory's, installs the tap. A machine that already has this software and declaration, and
   matches it, is left alone: no recorder restarts and no port is reconfigured.

| `goatrope deploy` | Exit |
|---|---|
| prints `unchanged`, `changed` or, with `--dry-run`, `would-change` | 0 |
| refused; nothing was changed | 2 |
| installed, and the machine does not match the declaration | 3 |

## The machine's declaration

In the machine's host_vars. Nothing here has a default, and a missing value is refused.

```yaml
tap:
  mode: listen              # listen | inline
  source: copper-tap        # listen only: copper-tap | bypass-relay | mirror-port
  ports: [enxPORTA, enxPORTB]
  management: eth0
goatrope_record:
  ports: [enxPORTA, enxPORTB]   # inline: one port
  filter: ""                    # a BPF filter, or "" for every frame
  file_mb: 50
  files: 40
goatrope_speed_mbps: 100        # only for a copper tap, or to force a speed
goatrope_extra_toml: ""         # [[send]] and [[decode]] sections, as TOML
```

The play writes `/etc/goatrope/goatrope.toml` from these; the declaration before is kept as
`goatrope.toml.prev`. The machine needs `tcpdump` and `ethtool` already: the play installs no
package, and goatrope refuses without them.

A failure after preflight (exit 3, or the machine lost during the install) fails the play with
`current` already at the new release. Run the play again, or roll back.
