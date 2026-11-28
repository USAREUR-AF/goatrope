#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Run the namespace tests (tests/netns/test_tap.py) in an emulated arm64 Ubuntu VM: the
# Ubuntu arm64 cloud image, booted by qemu-system-aarch64 (TCG, no KVM) inside a container.
# The VM has an emulated i6300esb watchdog, so check reads a real /dev/watchdog device.
#
#   tests/arm64/run.sh 24.04|26.04
#   IMAGES=<dir>  where the cloud images are kept (default ~/.cache/goatrope-arm64)
#   OUT=<dir>     where the logs go (default ./test-results)
#   GOATROPE_ARM64_CONTAINER=<name>  the VM's container is <name>-<version> (default goatrope-arm64)
#   GOATROPE_ARM64_PHASES="<phase> ..."  run only these phases, with no reboot (default: every phase below)
#   WATCHDOG_ACTION=none|reset  what qemu does when the watchdog expires (default none: it is
#                 logged to ubuntu-<v>-arm64.qemu.log; emulated daemon-reloads can take over 10 s)
#
# Slow: emulation runs several times slower than the hardware. It shows that the arm64
# packages (Python, tcpdump, iproute2, systemd) behave as the amd64 ones do; it does not
# show the timing of a Raspberry Pi or its USB adapters.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
v="${1:?usage: run.sh 24.04|26.04}"
case "$v" in 24.04|26.04) ;; *) echo "unknown version $v" >&2; exit 2 ;; esac
images="${IMAGES:-$HOME/.cache/goatrope-arm64}"
out="${OUT:-$repo/test-results}"
mkdir -p "$images" "$out"
img="$images/ubuntu-$v-server-cloudimg-arm64.img"
[ -f "$img" ] || curl -fsSL -o "$img" "https://cloud-images.ubuntu.com/releases/$v/release/ubuntu-$v-server-cloudimg-arm64.img"

w="$(mktemp -d "$out/arm64-$v.XXXX")"
c="${GOATROPE_ARM64_CONTAINER:-goatrope-arm64}-$v"   # another name lets two VMs share a host
log="$out/ubuntu-$v-arm64.log"
: > "$log"
trap 'cp "$w/console.log" "$out/ubuntu-$v-arm64.console.log" 2>/dev/null; docker logs "$c" > "$out/ubuntu-$v-arm64.qemu.log" 2>&1; docker rm -f "$c" >/dev/null 2>&1 || true; rm -rf "$w"' EXIT

ssh-keygen -q -t ed25519 -N '' -f "$w/key"
cat > "$w/meta-data" <<EOF
instance-id: goatrope-arm64-$v
local-hostname: goatrope-arm64
EOF
cat > "$w/network-config" <<'EOF'
version: 2
ethernets:
  mgmt:
    match: {name: "en*"}
    dhcp4: true
EOF
cat > "$w/user-data" <<EOF
#cloud-config
disable_root: false
users:
  - name: root
    ssh_authorized_keys: ["$(cat "$w/key.pub")"]
package_update: true
packages: [tcpdump, ethtool, python3, iputils-ping, iputils-arping, wireguard-tools, dbus, nftables]
bootcmd:
  # sshd as a plain service: socket activation stops accepting after a burst of early connections
  # (enable only: starting a unit from inside cloud-init waits on cloud-init itself)
  - [sh, -c, "systemctl disable ssh.socket; systemctl enable ssh.service || true"]
runcmd:
  - [sh, -c, "systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer || true"]
  # the module does not load by itself after a reboot, so a unit loads it at every boot
  - [sh, -c, "modprobe -n i6300esb || apt-get install -y linux-modules-extra-\$(uname -r) || true"]
  - [sh, -c, "printf '[Service]\\nType=oneshot\\nExecStart=/sbin/modprobe i6300esb\\n[Install]\\nWantedBy=sysinit.target\\n[Unit]\\nDefaultDependencies=no\\n' > /etc/systemd/system/test-watchdog.service && systemctl daemon-reload && systemctl enable --now test-watchdog.service || echo watchdog module not loaded"]
  - [touch, /root/ready]
  - [sh, -c, "echo GOATROPE-VM-READY > /dev/console"]
EOF

# named by a hash of the Dockerfile, so runs from trees whose Dockerfiles differ never share an image
image="goatrope-qemu-arm64-$(sha256sum "$here/Dockerfile" | cut -c1-12)"
docker build -q -t "$image" "$here" >/dev/null
docker run -d --name "$c" -e WATCHDOG_ACTION="${WATCHDOG_ACTION:-none}" --user "$(id -u):$(id -g)" -v "$w:/w" -v "$img:/base.img:ro" "$image" sh -c '
  set -e
  qemu-img create -q -f qcow2 -F qcow2 -b /base.img /w/disk.qcow2 16G
  cloud-localds --network-config /w/network-config /w/seed.img /w/user-data /w/meta-data
  cp /usr/share/AAVMF/AAVMF_VARS.fd /w/vars.fd
  exec qemu-system-aarch64 -M virt -accel tcg,thread=multi -cpu cortex-a72 -smp 4 -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/w/vars.fd \
    -drive if=virtio,file=/w/disk.qcow2 -drive if=virtio,format=raw,file=/w/seed.img \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0,romfile= \
    -device i6300esb -watchdog-action "$WATCHDOG_ACTION" -trace watchdog_perform_action \
    -display none -serial file:/w/console.log' >/dev/null

vm() { docker exec -i "$c" ssh -o LogLevel=ERROR -i /w/key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=120 -o ServerAliveInterval=30 root@127.0.0.1 "$@"; }
wait_vm() { # seconds; the console marker first, so ssh is not tried while the guest is still booting
    for _ in $(seq 1 $(($1 / 10))); do
        grep -aq GOATROPE-VM-READY "$w/console.log" 2>/dev/null && break
        sleep 10
    done
    for _ in $(seq 1 180); do  # a reboot under emulation on a busy host takes many minutes
        if vm sh -s 2>/dev/null <<'EOF'
test -f /root/ready || exit 1
s=$(systemctl is-system-running)
[ "$s" = running ] || [ "$s" = degraded ]
EOF
        then
            return 0
        fi
        sleep 10
    done
    echo "VM did not come up; console:" >&2; vm 'systemctl list-jobs --no-pager; systemctl is-system-running' >&2 || true; tail -30 "$w/console.log" >&2; return 1
}
rc=0
phase() { vm "GOATROPE_TEST_REAL_WATCHDOG=1 GOATROPE_TEST_MGMT=\$(ip -o route show default | awk '{print \$5; exit}') python3 -I /src/tests/netns/test_tap.py $*" 2>&1 | tee -a "$log" || rc=1; }

wait_vm 2400
tar -C "$repo" --exclude=.git --exclude=test-results --exclude=__pycache__ --exclude=./target -cf - . | vm 'mkdir -p /src && tar -C /src --no-same-owner -xf - && chmod -R go+rX /src'
vm sh -s <<'EOF' | tee -a "$log"
. /etc/os-release
echo "### Ubuntu $VERSION $(uname -m), emulated (qemu TCG); kernel $(uname -r); $(systemctl --version | head -1);" \
     "$(python3 --version); $(tcpdump --version 2>&1 | head -1); watchdog: $(ls /dev/watchdog* 2>/dev/null | tr '\n' ' ')"
EOF
if [ -n "${GOATROPE_ARM64_PHASES:-}" ]; then
    # shellcheck disable=SC2086  # a list of phase names, split on purpose
    phase $GOATROPE_ARM64_PHASES
    vm 'cat /root/gt/results.jsonl' > "$out/ubuntu-$v-arm64.results.jsonl" 2>/dev/null || true
    echo "log: $log"
    exit $rc
fi
phase refusals inline

# A reboot: the namespaces and veths are gone, as a USB adapter is absent early in boot.
vm 'systemctl reboot' || true
sleep 30
wait_vm 1200
vm 'systemctl show -p RuntimeWatchdogUSec --value; ls /dev/watchdog* ; cat /sys/class/watchdog/watchdog0/state 2>/dev/null || true' | sed 's/^/    after reboot: /' | tee -a "$log"
for _ in 1 2 3 4 5; do  # the guest may still be finishing its boot under emulation
    vm 'python3 -I /src/tests/netns/test_tap.py topo-inline' >/dev/null && break
    sleep 30
done
phase reboot-verify uninstall
phase listen uninstall send relay boundary uninstall units erspan relay-filter l2
vm 'cat /root/gt/results.jsonl' > "$out/ubuntu-$v-arm64.results.jsonl" 2>/dev/null || true
echo "log: $log"
exit $rc
