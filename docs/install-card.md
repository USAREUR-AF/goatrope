<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# Install card: a goatrope tap on a Raspberry Pi

One page, in order. Every name in angle brackets is yours to fill in.

**Before you start.** Ubuntu Server 24.04 or 26.04 is installed, you can log in
over the **management** interface (Wi-Fi or a third Ethernet port), and the Pi has
internet access for the packages. Decide the mode:

- **inline**: the Pi sits in the link. **The link is down whenever the Pi is off,
  restarting or hung.**
- **listen**: a tap device or a switch mirror port carries the link and hands the
  Pi a copy. The link does not depend on the Pi.

1. **Packages.**
   `sudo apt-get install -y tcpdump ethtool`

2. **Unpack and verify the release.**
   ```
   sha256sum -c --ignore-missing SHA256SUMS
   tar -xzf goatrope-<version>.tar.gz && cd goatrope-<version>
   ```

3. **Find the ports.** `ip -br link`. The two tap ports have no address and are not
   the interface you are logged in over. USB adapters are named `enx<mac>`.

4. **Write the declaration** at `/etc/goatrope/goatrope.toml`, starting from
   `examples/inline.toml` or `examples/listen-copper-tap.toml`. Fill in `ports`,
   `management`, the recording `filter` (`""` for every frame), `file_mb` and
   `files`. Check it: `./bin/goatrope validate --config /etc/goatrope/goatrope.toml`

5. **Cable the link** (inline: one side of the link to each tap port; listen: the
   tap device's outputs or the mirror port to the tap ports).

6. **Install.** `sudo ./bin/goatrope install --config /etc/goatrope/goatrope.toml`
   It refuses, changing nothing, if a port carries your session, the default route
   or an address. It prints the mode, the ports, the recorder and the result of
   the check.

7. **Check.** `sudo goatrope check` prints `result: matches the declaration` and
   exits 0. Exit 3 means something differs; each `DIFF` line says what.

8. **Prove it.** Inline: traffic passes between the two sides. Both modes:
   `sudo goatrope status` shows the recorder active and files growing in
   `/var/lib/goatrope/record`.

9. **Restart test.** `sudo reboot`. Inline: the link is down until the Pi is back.
   Then `sudo goatrope check` exits 0 with no one touching it.

**Remove.** `sudo goatrope uninstall` restores the ports and removes everything
goatrope wrote; the declaration and recordings are kept. `sudo goatrope uninstall
--purge` removes those too.
