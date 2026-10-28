#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One fresh endpoint pair per scenario. A failed driver remains a failed run;
# its pcap and logs survive for independent diagnosis, not positive claims.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: capture.sh NEW_ABSOLUTE_DIRECTORY explicit|connected|io|msp|msp32}"
scenario="${2:?missing scenario}"
[[ "$out" = /* && ! -e "$out" ]] || { echo 'output must be a new absolute directory' >&2; exit 2; }
case "$scenario" in explicit|connected|io|msp|msp32) ;; *) exit 2 ;; esac
mkdir -p "$out/logs"
run="containd-corpus-cip-$(date +%s)-$$"
image="${CIP_IMAGE:-containd-corpus-cip-reference}"
network="$run-net"
containers=()
network_created=0
# Called indirectly by the EXIT trap, including on failed endpoint runs.
# shellcheck disable=SC2329
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
trap 'cleanup' EXIT

docker build --pull=false -f "$here/generator.Dockerfile" -t "$image" "$here" > "$out/logs/build.log" 2>&1
docker image inspect "$image" > "$out/logs/image.json"
docker run --rm --name "$run-packages" "$image" dpkg-query -W > "$out/logs/packages.txt"
docker network create "$network" > /dev/null
network_created=1
server="$run-server"
capture="$run-capture"
client="$run-client"
docker run -d --name "$server" --network "$network" "$image" /src/opener-build/src/ports/POSIX/OpENer eth0 > /dev/null
containers+=("$server")
# Readiness without opening an extra protocol session in the capture.
ready=0
for ((i = 0; i < 100; i++)); do
    [[ "$(docker inspect -f '{{.State.Running}}' "$server")" = true ]]
    if docker exec "$server" sh -c 'ss -lnt | grep -q :44818'; then ready=1; break; fi
    sleep 0.1
done
[[ "$ready" = 1 ]]
server_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")"
docker run -d --name "$capture" --network "container:$server" --cap-add NET_RAW \
    -v "$out:/evidence" "$image" tcpdump -i eth0 --immediate-mode -U -s 0 -w "/evidence/$scenario.pcap" \
    'tcp port 44818 or udp port 2222' > /dev/null
containers+=("$capture")
ready=0
for ((i = 0; i < 100; i++)); do
    log="$(docker logs "$capture" 2>&1)"
    if [[ "$log" == *'listening on eth0'* ]]; then ready=1; break; fi
    [[ "$(docker inspect -f '{{.State.Running}}' "$capture")" = true ]]
    sleep 0.1
done
[[ "$ready" = 1 ]]
containers+=("$client")
result=0
docker run --name "$client" --network "$network" "$image" /scanner "$server_ip" "$scenario" > "$out/logs/scanner.log" 2>&1 || result=$?
printf '%s\n' "$result" > "$out/logs/scanner.exit"
docker kill --signal INT "$capture" > /dev/null
[[ "$(docker wait "$capture")" = 0 ]]
[[ "$(wc -c < "$out/$scenario.pcap")" -gt 24 ]]
docker logs "$capture" > "$out/logs/tcpdump.log" 2>&1
# OpENer's POSIX main returns RET_SHOW_SIGNAL (200) plus the caught signal.
docker kill --signal INT "$server" > /dev/null
[[ "$(docker wait "$server")" = 202 ]]
docker logs "$server" > "$out/logs/adapter.log" 2>&1
cat "$out/logs/scanner.log"
exit "$result"
