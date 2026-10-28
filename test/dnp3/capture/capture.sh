#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Headless independent endpoints. Only this invocation's named resources change.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: capture.sh ABSOLUTE_NEW_OUTPUT_DIRECTORY}"
[[ "$out" = /* && ! -e "$out" ]] || { echo 'output must be a new absolute directory' >&2; exit 2; }
mkdir -p "$out/logs"
run="containd-corpus-dnp3-$(date +%s)-$$"
image="$run:3.1.2"
network="$run-net"
containers=()
network_created=0
cleanup() {
    local result=$? id
    for id in "${containers[@]}"; do
        if ! docker rm -f "$id" > /dev/null; then result=1; fi
    done
    if [[ "$network_created" = 1 ]]; then
        if ! docker network rm "$network" > /dev/null; then result=1; fi
    fi
    exit "$result"
}
trap cleanup EXIT

docker build --pull=false -f "$here/generator.Dockerfile" -t "$image" "$here" > "$out/logs/build.log" 2>&1
docker image inspect "$image" > "$out/logs/image.json"
docker run --rm --name "$run-packages" "$image" dpkg-query -W > "$out/logs/packages.txt"
docker network create "$network" > /dev/null
network_created=1

wait_log() {
    local container="$1" text="$2" i log
    for ((i = 0; i < 100; i++)); do
        log="$(docker logs "$container" 2>&1)"
        if [[ "$log" == *"$text"* ]]; then return 0; fi
        [[ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ]] || { printf '%s\n' "$log" >&2; return 1; }
        sleep 0.1
    done
    printf 'timeout waiting for %s in %s\n' "$text" "$container" >&2
    return 1
}
for scenario in link-only startup-integrity class-range unsolicited crob iin-error large-response; do
    server="$run-$scenario-server"
    capture="$run-$scenario-capture"
    client="$run-$scenario-client"
    docker run -d --name "$server" --network "$network" "$image" /outstation "$scenario" > /dev/null
    containers+=("$server")
    wait_log "$server" READY
    docker run -d --name "$capture" --network "container:$server" --cap-add NET_RAW --cap-add NET_ADMIN \
        -v "$out:/evidence" "$image" tcpdump -i eth0 -U -s 0 -w "/evidence/$scenario.pcap" 'tcp port 20000' > /dev/null
    containers+=("$capture")
    wait_log "$capture" 'listening on eth0'
    containers+=("$client")
    docker run --name "$client" --network "$network" "$image" /master "$server" "$scenario" > "$out/logs/$scenario-master.log" 2>&1
    docker kill --signal INT "$capture" > /dev/null
    [[ "$(docker wait "$capture")" = 0 ]]
    docker logs "$capture" > "$out/logs/$scenario-tcpdump.log" 2>&1
    docker stop "$server" > /dev/null
    [[ "$(docker wait "$server")" = 0 ]]
    docker logs "$server" > "$out/logs/$scenario-outstation.log" 2>&1
done
python3 "$here/mutate.py" "$out/class-range.pcap" "$out/crc-flip.pcap"
python3 "$here/mutate.py" "$out/class-range.pcap" "$out/header-crc.pcap" header-crc
python3 "$here/mutate.py" "$out/class-range.pcap" "$out/qualifier-tail.pcap" qualifier
bash "$here/export-oracle.sh" "$out"
python3 "$here/finalize.py" "$out" "$here"
(cd "$out" && shasum -a 256 -c SHA256SUMS)
