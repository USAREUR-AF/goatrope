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
#   GOATROPE_TEST_ARCHIVE=<file>   "deploy" phase: an archive tools/build-release.sh built (default: the test makes one)
#   GOATROPE_TEST_ROLES=<dir>      "deploy" phase: the driver's real release-file role (default: a stand-in)
#   GOATROPE_BENCH_SECONDS=<s>     "bench" phase, in a container of its own after the others: seconds per trial
#                                  (default 0.5, a quick run; docs/performance.md used 3). GOATROPE_BENCH=0 skips it.
#   GOATROPE_BENCH_STEPS=<n>       "bench": binary-search steps per ceiling (default 4; docs/performance.md used 7)
#
# Needs Docker on a Linux host. The container is privileged because it creates veth
# pairs and namespaces; it uses the host kernel, so the kernel under test is the host's.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${OUT:-$repo/test-results}"
mkdir -p "$out"
versions=("$@")
# The binary under test: built here unless it is already there (tools/build-bin.sh; without cargo
# on the host, GOATROPE_BUILD_IN_DOCKER=1 builds it in the rust image).
if [ ! -x "$repo/bin/$(uname -m)/goatrope" ] || [ ! -x "$repo/bin/$(uname -m)/goatrope-units" ]; then
    GOATROPE_BUILD_UNITS=1 "$repo/tools/build-bin.sh"
fi

# The packs and model modules of the goat-transformers commit the linked engine is built from
# (docs/adr/0006-data-path.md), from Cargo's checkout of it: the "linked-engine" phase and the bench use them.
rev=$(sed -n 's/^pub const COMMIT: &str = "\(.*\)";/\1/p' "$repo/src/engine.rs")
engine_tree=""
for d in "${CARGO_HOME:-$HOME/.cargo}" "$repo/target/cargo-home"; do
    for t in "$d"/git/checkouts/goat-transformers-*/"${rev:0:7}"; do
        [ -f "$t/packs/remote-id/pack.def" ] && engine_tree=$t
    done
done
[ -n "$engine_tree" ] || echo "no checkout of goat-transformers ${rev:0:7}: the linked-engine phase will not run" >&2
# The tc prototype the bench measures (docs/adr/0006-data-path.md), when clang is here.
mkdir -p "$here/build"
if command -v clang >/dev/null; then
    clang -O2 -target bpf -I"/usr/include/$(uname -m)-linux-gnu" -c "$here/relay_tc.c" -o "$here/build/relay_tc.o" \
        || echo "relay_tc.c did not compile: the bench leaves the tc prototype out" >&2
fi

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

# The image name carries a hash of the Dockerfile, so runs from trees whose Dockerfiles differ
# never overwrite each other's image on a shared host; runs from the same Dockerfile share it.
image="goatrope-netns-$(sha256sum "$here/Dockerfile" | cut -c1-12)"

start() { # container, image tag
    local c=$1 v=$2
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock "$image:$v" >/dev/null
    wait_systemd "$c"
    docker exec "$c" mkdir -p /src
    tar -C "$repo" --exclude=.git --exclude=test-results --exclude=__pycache__ --exclude=./target -cf - . | docker exec -i "$c" tar -C /src --no-same-owner -xf -
    docker exec "$c" chmod -R go+rX /src
    if [ -n "${GOATROPE_TEST_COMPONENTS:-}" ]; then
        docker exec "$c" mkdir -p /opt/gt-components
        tar -C "$GOATROPE_TEST_COMPONENTS" -cf - . | docker exec -i "$c" tar -C /opt/gt-components --no-same-owner -xf -
    fi
}

engine_packs() { # container: the pinned commit's two test packs and its model modules, at /opt/gt-engine
    [ -n "$engine_tree" ] || return 0
    docker exec "$1" mkdir -p /opt/gt-engine
    tar -C "$engine_tree" -cf - model packs/remote-id/pack.def packs/cot-xml/pack.def | docker exec -i "$1" tar -C /opt/gt-engine --no-same-owner -xf -
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
    docker build -q --build-arg "UBUNTU=$v" -t "$image:$v" "$here" >/dev/null
    docker build -q --build-arg "UBUNTU=$v" --build-arg NM=1 -t "$image:$v-nm" "$here" >/dev/null
    docker build -q --build-arg "UBUNTU=$v" --build-arg ANSIBLE=1 -t "$image:$v-ansible" "$here" >/dev/null
    c="${GOATROPE_TEST_CONTAINER:-goatrope-netns}-$v"   # another name lets two runs share a host

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
    engine_packs "$c"
    phase "$c" "$log" listen uninstall send linked-engine send-capture components relay boundary uninstall relay-service relay-recreate relay-tcp units erspan proxy fragments l2 relay-recreate-l2
    docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null

    # NetworkManager installed and managing the wired ports, as on a desktop image.
    start "$c" "$v-nm"
    phase "$c" "$log" networkmanager
    docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null

    # The deploy play, with Ansible in the container.
    start "$c" "$v-ansible"
    [ -z "${GOATROPE_TEST_ROLES:-}" ] || tar -C "$GOATROPE_TEST_ROLES" -cf - --transform 's,^\.,gt-roles,' . | docker exec -i "$c" tar -C /opt --no-same-owner -xf -
    if [ -n "${GOATROPE_TEST_ARCHIVE:-}" ]; then
        docker exec "$c" mkdir -p /opt/gt-dist
        docker cp -q "$GOATROPE_TEST_ARCHIVE" "$c:/opt/gt-dist/"
    fi
    phase "$c" "$log" deploy
    docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
    docker rm -f "$c" >/dev/null

    # Data-path ceilings: measurements, never a pass or a failure of a number (docs/performance.md).
    if [ "${GOATROPE_BENCH:-1}" != 0 ]; then
        start "$c" "$v"
        engine_packs "$c"
        docker exec -e "GOATROPE_BENCH_SECONDS=${GOATROPE_BENCH_SECONDS:-0.5}" -e "GOATROPE_BENCH_STEPS=${GOATROPE_BENCH_STEPS:-4}" \
            "$c" python3 -I /src/tests/netns/test_tap.py bench 2>&1 | tee -a "$log" || rc=1
        docker exec "$c" cat /root/gt/results.jsonl >> "$out/ubuntu-$v.results.jsonl" 2>/dev/null || true
        docker rm -f "$c" >/dev/null
    fi
done
echo "logs in $out"
exit $rc
