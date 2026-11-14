#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
HERE=$(dirname "$(realpath "$0")")
OUT=${1:?usage: run.sh ABSOLUTE_EMPTY_OUTPUT_DIRECTORY}
[[ "$OUT" == /* ]] || { echo "output path must be absolute" >&2; exit 2; }
mkdir -p "$OUT"
[[ -z "$(ls -A "$OUT")" ]] || { echo "output directory must be empty" >&2; exit 2; }
COMPOSE_PROJECT_NAME="pairingpeer-$(date +%s)-$$"
export COMPOSE_PROJECT_NAME
IMAGE="$COMPOSE_PROJECT_NAME:local"
NETWORK="$COMPOSE_PROJECT_NAME-net"
CONTAINERS=()
NETWORK_CREATED=0
IMAGE_CREATED=0
cleanup() {
    local result=$?
    trap - EXIT
    local failed=0
    for container in "${CONTAINERS[@]-}"; do
        [[ -n "$container" ]] || continue
        docker logs "$container" > "$OUT/${container##*-}.station.log" 2>&1 || failed=1
        docker container rm -f "$container" || failed=1
    done
    if [[ "$NETWORK_CREATED" == 1 ]]; then
        docker network rm "$NETWORK" || failed=1
    fi
    if [[ "$IMAGE_CREATED" == 1 ]]; then
        docker image rm "$IMAGE" || failed=1
    fi
    if [[ "$failed" == 1 ]]; then
        echo "cleanup incomplete for $COMPOSE_PROJECT_NAME" >&2
        result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker network ls -q > "$OUT/network-ids"
python3 - "$OUT/network-ids" > "$OUT/subnet" <<'PY'
import ipaddress
from pathlib import Path
import json
import subprocess
import sys
ids = Path(sys.argv[1]).read_text().split()
nets = json.loads(subprocess.check_output(["docker", "network", "inspect", *ids])) if ids else []
used = [ipaddress.ip_network(c["Subnet"]) for n in nets for c in (n["IPAM"]["Config"] or []) if c.get("Subnet")]
for index in range(256):
    candidate = ipaddress.ip_network(f"10.252.{index}.0/24")
    if not any(candidate.overlaps(n) for n in used if n.version == 4):
        print(candidate)
        break
else:
    raise SystemExit("no free private subnet")
PY
docker build --label pairingpeer=true --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    -t "$IMAGE" "$HERE"
IMAGE_CREATED=1
docker network create --internal --label pairingpeer=true \
    --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    --subnet "$(cat "$OUT/subnet")" "$NETWORK"
NETWORK_CREATED=1
for stack in lib60870 j60870 c104; do
    name="$COMPOSE_PROJECT_NAME-$stack"
    if [[ "$stack" == lib60870 ]]; then
        command=(/sources/lib60870-2.4.1/lib60870-C/examples/cs104_server/simple_server)
    elif [[ "$stack" == j60870 ]]; then
        command=(java -cp /opt/j60870 org.openmuc.j60870.app.SampleServer -a 0.0.0.0)
    else
        command=(python3 /opt/c104_points.py)
    fi
    docker run -d --name "$name" --network "$NETWORK" --label pairingpeer=true \
        --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
        "$IMAGE" "${command[@]}"
    CONTAINERS+=("$name")
    docker exec "$name" python3 -c '
import time
for _ in range(100):
    if any(line.split()[1].endswith(":0964") and line.split()[3] == "0A"
           for path in ("/proc/net/tcp", "/proc/net/tcp6")
           for line in open(path).readlines()[1:]):
        break
    time.sleep(.1)
else:
    raise SystemExit("station did not listen")
'
    docker exec "$name" sh -c \
        'tcpdump --immediate-mode -U -i lo -w /tmp/peer.pcap "tcp port 2404" >/tmp/capture.log 2>&1 & echo $! >/tmp/capture.pid'
    docker exec "$name" python3 -c '
import time
for _ in range(100):
    if "listening on lo" in open("/tmp/capture.log").read():
        break
    time.sleep(.1)
else:
    raise SystemExit("capture did not start")
'
    docker exec "$name" /opt/master "$stack" > "$OUT/$stack.master.log"
    docker exec "$name" sh -c 'kill -INT "$(cat /tmp/capture.pid)"'
    docker exec "$name" python3 -c '
import time
for _ in range(100):
    if "packets captured" in open("/tmp/capture.log").read():
        break
    time.sleep(.1)
else:
    raise SystemExit("capture did not finish")
'
    docker cp "$name:/tmp/peer.pcap" "$OUT/$stack.pcap"
    docker cp "$name:/tmp/capture.log" "$OUT/$stack.capture.log"
    docker logs "$name" > "$OUT/$stack.station.log" 2>&1
    docker exec "$name" tshark -r /tmp/peer.pcap -Y tcp.payload -T fields \
        -e frame.number -e tcp.srcport -e tcp.seq_raw -e tcp.payload > "$OUT/$stack.tcp.tsv"
    [[ "$(wc -c < "$OUT/$stack.pcap")" -gt 24 ]]
done
python3 "$HERE/analyze.py" "$OUT"
echo "Stage table, oracle.json and captures: $OUT"
