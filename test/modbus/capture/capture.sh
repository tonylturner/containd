#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel)
ADAPTER="$ROOT/test/modbus/capture"
OUT=${1:?usage: capture.sh output-directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TOOLS=modbusspan-tools@sha256:2bbeea56d58c5192ebda1d8314637c3c9995341df21e733110405040bae77fbc
IMAGE=containd-corpus-modbus-generator
PREFIX="containd-corpus-modbus-$$"
NET="$PREFIX-net"
SERVER="$PREFIX-server"
CAP="$PREFIX-capture"
CLIENT="$PREFIX-client"
cleanup() {
    # Named resources belong exclusively to this invocation. No broad pruning.
    for name in "$CLIENT" "$CAP" "$SERVER"; do
        if docker container inspect "$name" >/dev/null 2>&1; then
            docker rm -f "$name" >/dev/null
        fi
    done
    if docker network inspect "$NET" >/dev/null 2>&1; then
        docker network rm "$NET" >/dev/null
    fi
}
trap cleanup EXIT
docker build --pull=false -f "$ADAPTER/generator.Dockerfile" -t "$IMAGE" "$ADAPTER"
docker image inspect "$TOOLS" "$IMAGE" > "$OUT/images.json"
docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --pull=never --network "$NET" "$IMAGE" server >/dev/null
IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")
docker run --rm --name "$CLIENT" --pull=never --network "$NET" --entrypoint /venv/bin/python "$IMAGE" -c \
    'import socket,sys,time
for attempt in range(100):
    try:
        socket.create_connection((sys.argv[1],502),timeout=1).close()
        break
    except OSError:
        time.sleep(.1)
else:
    raise RuntimeError("server not ready")' "$IP"
for scenario in operations diagnostics source502; do
    docker run -d --name "$CAP" --pull=never --network "container:$SERVER" \
        -v "$OUT:/out" "$TOOLS" tcpdump -i eth0 -s 0 -U -w "/out/$scenario.pcap" 'tcp port 502' >/dev/null
    ready=0
    for ((i=0; i<100; i++)); do
        if docker logs "$CAP" 2>&1 | grep -q 'listening on eth0'; then
            ready=1
            break
        fi
        sleep 0.1
    done
    test "$ready" = 1
    docker run --rm --name "$CLIENT" --pull=never --network "$NET" "$IMAGE" client "$IP" "$scenario" > "$OUT/$scenario.client.log" 2>&1
    sleep 1
    docker kill --signal=SIGINT "$CAP" >/dev/null
    status=$(docker wait "$CAP")
    test "$status" = 0
    docker logs "$CAP" > "$OUT/$scenario.capture.log" 2>&1
    docker rm "$CAP" >/dev/null
done
docker logs "$SERVER" > "$OUT/server.log" 2>&1
echo "Captures and endpoint evidence: $OUT"
