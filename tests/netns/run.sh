#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Run the network-namespace tests in a privileged container with systemd as PID 1,
# once per Ubuntu version.
#
#   tests/netns/run.sh                 both versions (24.04 and 26.04)
#   tests/netns/run.sh 26.04           one version
#   OUT=<dir> tests/netns/run.sh       where the logs go (default ./test-results)
#   GOATROPE_TEST_COMPONENTS=<dir>     real component binaries for the "components" phase: goat-xf,
#                                      packs/, model/, mind, dictionaries/ntp (otherwise not run)
#
# Needs Docker on a Linux host. The container is privileged because it creates veth
# pairs and namespaces; it uses the host kernel, so the kernel under test is the host's.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${OUT:-$repo/test-results}"
mkdir -p "$out"
versions=("$@")
[ "${#versions[@]}" -gt 0 ] || versions=(24.04 26.04)
rc=0

wait_systemd() {
    local c=$1 s
    for _ in $(seq 1 120); do
        s=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
        case "$s" in running|degraded) return 0 ;; esac
        sleep 1
    done
    echo "systemd in $c did not start (state: $s)" >&2
    return 1
}

start() { # container, image tag
    local c=$1 v=$2
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock "goatrope-netns:$v" >/dev/null
    wait_systemd "$c"
    docker exec "$c" mkdir -p /src
    tar -C "$repo" --exclude=.git --exclude=test-results --exclude=__pycache__ -cf - . | docker exec -i "$c" tar -C /src --no-same-owner -xf -
    docker exec "$c" chmod -R go+rX /src
    if [ -n "${GOATROPE_TEST_COMPONENTS:-}" ]; then
        docker exec "$c" mkdir -p /opt/gt-components
        tar -C "$GOATROPE_TEST_COMPONENTS" -cf - . | docker exec -i "$c" tar -C /opt/gt-components --no-same-owner -xf -
    fi
}

phase() { # container, log, phases...
    local c=$1 log=$2
    shift 2
    docker exec "$c" python3 -I /src/tests/netns/test_tap.py "$@" 2>&1 | tee -a "$log" || rc=1
}

for v in "${versions[@]}"; do
    log="$out/ubuntu-$v.log"
    : > "$log"
    echo "### Ubuntu $v  (host kernel $(uname -r), $(uname -m))" | tee -a "$log"
    docker build -q --build-arg "UBUNTU=$v" -t "goatrope-netns:$v" "$here" >/dev/null
    docker build -q --build-arg "UBUNTU=$v" --build-arg NM=1 -t "goatrope-netns:$v-nm" "$here" >/dev/null
    c="goatrope-netns-$v"

    start "$c" "$v"
    docker exec "$c" sh -c 'echo "# image: $(. /etc/os-release; echo $PRETTY_NAME), $(systemctl --version | head -1), $(python3 --version), $(tcpdump --version 2>&1 | head -1)"' | tee -a "$log"
    phase "$c" "$log" refusals inline

    # A restart: the namespaces and veths are gone, as a USB adapter is absent early in boot.
    # They are recreated after systemd is up; goatrope-ports waits up to 60 s for them.
    docker restart "$c" >/dev/null
    wait_systemd "$c"
    docker exec "$c" python3 -I /src/tests/netns/test_tap.py topo-inline >/dev/null
    phase "$c" "$log" reboot-verify uninstall
    docker exec "$c" cat /root/gt/results.jsonl > "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null

    start "$c" "$v"
    phase "$c" "$log" listen uninstall send components relay uninstall units
    docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null

    # NetworkManager installed and managing the wired ports, as on a desktop image.
    start "$c" "$v-nm"
    phase "$c" "$log" networkmanager
    docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null
done
echo "logs in $out"
exit $rc
