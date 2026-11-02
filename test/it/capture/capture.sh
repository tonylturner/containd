#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
ADAPTER="$ROOT/test/it/capture"
OUT=${1:-"$ROOT/test/it/testdata"}
mkdir -p "$OUT" "$ADAPTER/LICENSES"
OUT=$(cd "$OUT" && pwd)

RUN_ID="$(date +%s)-$$-${RANDOM}"
# The disposable lab account gets a fresh random password per run.
LAB_PASSWORD=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
export LAB_PASSWORD
IMAGE="o1cap-$RUN_ID-tools"
NET="o1cap-$RUN_ID-net"
PACKAGE_CONTAINER="o1cap-$RUN_ID-packages"
LICENSE_CONTAINER="o1cap-$RUN_ID-licenses"
SERVER=""
CAP=""
CLIENT=""

cleanup() {
    status=$?
    trap - EXIT
    if (( status != 0 )); then
        for name in "$CAP" "$SERVER"; do
            if [[ -n "$name" ]] && docker container inspect "$name" >/dev/null 2>&1; then
                printf '%s logs:\n' "$name" >&2
                docker container logs "$name" >&2 || true
            fi
        done
    fi
    for name in "$CLIENT" "$CAP" "$SERVER"; do
        if [[ -n "$name" ]] && docker container inspect "$name" >/dev/null 2>&1; then
            docker container rm -f "$name" >/dev/null
        fi
    done
    for name in "$PACKAGE_CONTAINER" "$LICENSE_CONTAINER"; do
        if docker container inspect "$name" >/dev/null 2>&1; then
            docker container rm -f "$name" >/dev/null
        fi
    done
    if docker network inspect "$NET" >/dev/null 2>&1; then
        docker network rm "$NET" >/dev/null
    fi
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        docker image rm "$IMAGE" >/dev/null
    fi
    exit "$status"
}
trap cleanup EXIT

docker build --pull=false --tag "$IMAGE" --file "$ADAPTER/Dockerfile" "$ADAPTER"
IMAGE_ID=$(docker image inspect "$IMAGE" --format '{{.Id}}')
PACKAGES=$(docker run --rm --name "$PACKAGE_CONTAINER" "$IMAGE" package-inventory)
docker run --rm --name "$LICENSE_CONTAINER" \
    -v "$ADAPTER/LICENSES:/licenses" "$IMAGE" license-notices

docker network create --driver bridge --subnet 198.51.100.0/24 "$NET" >/dev/null

capture_one() {
    protocol=$1
    port=$2
    SERVER="o1cap-$RUN_ID-server-$protocol"
    CAP="o1cap-$RUN_ID-tcpdump-$protocol"
    CLIENT="o1cap-$RUN_ID-client-$protocol"

    docker run --detach --name "$SERVER" --network "$NET" --ip 198.51.100.10 \
        -e LAB_PASSWORD "$IMAGE" serve "$protocol" >/dev/null
    sleep 2
    if [[ $(docker container inspect "$SERVER" --format '{{.State.Running}}') != true ]]; then
        docker logs "$SERVER" >&2
        printf '%s server stopped during startup\n' "$protocol" >&2
        return 1
    fi
    docker run --detach --name "$CAP" --network "container:$SERVER" \
        -v "$OUT:/out" "$IMAGE" tcpdump --immediate-mode -i eth0 -s 0 -U \
        -w "/out/$protocol.pcap" "port $port" >/dev/null
    ready=0
    for ((attempt=0; attempt<100; attempt++)); do
        if docker logs "$CAP" 2>&1 | grep -q 'listening on eth0'; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ $ready != 1 ]]; then
        docker logs "$CAP" >&2
        printf 'tcpdump failed to start for %s\n' "$protocol" >&2
        return 1
    fi

    case "$protocol" in
        dns)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                dig +tries=1 +time=2 @198.51.100.10 www.example.test A >/dev/null
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                dig +tries=1 +time=2 @198.51.100.10 www.example.test AAAA >/dev/null
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                dig +tries=1 +time=2 @198.51.100.10 www.example.test TXT >/dev/null
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                dig +tries=1 +time=2 @198.51.100.10 missing.example.test A >/dev/null
            ;;
        tls)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                openssl s_client -connect 198.51.100.10:443 -servername tls12.example.test \
                -tls1_2 -alpn h2 -brief </dev/null >/dev/null 2>&1
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                openssl s_client -connect 198.51.100.10:443 -servername tls13.example.test \
                -tls1_3 -alpn http/1.1 -brief </dev/null >/dev/null 2>&1
            ;;
        http)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                curl --fail --silent --show-error http://198.51.100.10/index.html?source=demo \
                -H 'Host: www.example.test' -H 'User-Agent: containd-it-capture/1.0' >/dev/null
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                curl --silent --show-error -X POST http://198.51.100.10/submit \
                -H 'Host: www.example.test' -H 'User-Agent: containd-it-capture/1.0' \
                -H 'Content-Type: application/json' --data '{"capture":"example"}' >/dev/null
            ;;
        ssh)
            docker run --rm --name "$CLIENT" --network "$NET" -e SSHPASS="$LAB_PASSWORD" "$IMAGE" \
                sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 \
                demo@198.51.100.10 'printf "ssh capture ok\n"' >/dev/null 2>&1
            ;;
        ntp)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                ntpdig -4 -p 1 198.51.100.10 >/dev/null
            ;;
        snmp)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                snmpget -v2c -c public -t 1 -r 0 198.51.100.10 \
                1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.3.0 >/dev/null
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                snmpwalk -v2c -c public -t 1 -r 0 198.51.100.10 1.3.6.1.2.1.1.5 >/dev/null
            ;;
        rdp)
            if docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                timeout 10s xvfb-run -a xfreerdp /v:198.51.100.10 /u:demo "/p:$LAB_PASSWORD" \
                /cert:ignore /sec:tls /auth-only; then
                :
            else
                client_status=$?
                printf 'FreeRDP closed after initial RDP negotiation (exit %s)\n' "$client_status" >&2
            fi
            ;;
        smb)
            docker run --rm --name "$CLIENT" --network "$NET" "$IMAGE" \
                smbclient -m SMB3 //198.51.100.10/share -N -c 'ls; get fixture.txt /dev/null' >/dev/null
            ;;
        *)
            printf 'unknown protocol %s\n' "$protocol" >&2
            return 2
            ;;
    esac

    sleep 1
    docker kill --signal=SIGINT "$CAP" >/dev/null
    capture_status=$(docker wait "$CAP")
    if [[ "$capture_status" != 0 ]]; then
        docker logs "$CAP" >&2
        printf 'tcpdump exited %s for %s\n' "$capture_status" "$protocol" >&2
        return 1
    fi
    docker logs "$CAP" >/dev/null 2>&1
    docker container rm "$CAP" >/dev/null
    docker container rm -f "$SERVER" >/dev/null
    CAP=""
    SERVER=""
}

for spec in dns:53 tls:443 http:80 ssh:22 ntp:123 snmp:161 rdp:3389 smb:445; do
    capture_one "${spec%%:*}" "${spec#*:}"
done

python3 "$ADAPTER/finalize.py" "$OUT" "$IMAGE_ID" <<<"$PACKAGES"
printf 'Captured eight IT protocol exchanges in %s\n' "$OUT"
