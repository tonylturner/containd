#!/usr/bin/env bash
set -euo pipefail

# Regenerate the IEC 60870-5-104 reference pcaps under test/iec104/testdata/.
#
# These are Apache-2.0 test data: packet captures of lib60870 (and the pure-Go
# malformer) traffic on a throwaway Docker network. The pcaps carry protocol
# bytes only, no lib60870 code. They seed the IEC104 decoder and engine tests;
# the Go unit tests derive byte fixtures from them and never need tshark at run
# time. The capture runs the RTU and a control-centre/command client directly
# (no firewall) so the fixtures are clean lib60870 wire traffic.
#
# For each pcap it also writes NAME.expected.tsv: Wireshark's independent
# decode of each TCP payload record (one row per record, multi-valued APDU and
# object fields comma-separated), so the containd decoder can be checked
# against a second parser. tshark runs only here, at regeneration time; Go
# tests never need it.
#
# Requirements: docker, Go (to build the malformer), tshark (TSHARK). Nothing
# is published to a host port; containers and the throwaway network are removed
# on exit. Build/capture scratch is retained under build/ for inspection.
#
# Usage: test/iec104/capture/capture.sh [OUT_DIR]   (default test/iec104/testdata)

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/test/iec104/capture"
OUT=${1:-$ROOT/test/iec104/testdata}
mkdir -p "$ROOT/build"
WORK=$(mktemp -d "$ROOT/build/iec104-capture.XXXXXX")

ENDPOINT_IMAGE=${IEC104_ENDPOINT_IMAGE:-containd-corpus-iec104-endpoint:lib60870-2.4.1}
CAPTURE_IMAGE=${IEC104_CAPTURE_IMAGE:-containd-corpus-iec104-capture:alpine321}
STAMP=$(date -u +%Y%m%d-%H%M%S)
NET="containd-corpus-iec104-net-${STAMP}-$$"
SUBNET=${IEC104_CAPTURE_SUBNET:-10.235.0}
RTU_IP=${SUBNET}.10
CLIENT_IP=${SUBNET}.20
CC_IP=${SUBNET}.21
RTU=""
CC=""
CAP=""
NET_ID=""
CLIENT_COUNT=0

ALLOWED_CA=1
AUX_CA=2
IOA_BREAKER=2001
IOA_ISOLATOR=2002
DCS_OPEN=1
DCS_CLOSE=2

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT
  if [[ -n "$CAP" ]]; then docker rm -f "$CAP" >/dev/null || cleanup_status=$?; fi
  if [[ -n "$CC" ]]; then docker rm -f "$CC" >/dev/null || cleanup_status=$?; fi
  if [[ -n "$RTU" ]]; then docker rm -f "$RTU" >/dev/null || cleanup_status=$?; fi
  if [[ -n "$NET_ID" ]]; then docker network rm "$NET" >/dev/null || cleanup_status=$?; fi
  if (( status != 0 )); then return "$status"; fi
  return "$cleanup_status"
}
trap cleanup EXIT

container_running() {
  [[ $(docker inspect --format '{{.State.Running}}' "$1") == true ]]
}

container_exit_successfully() {
  local code
  code=$(docker inspect --format '{{.State.ExitCode}}' "$1")
  [[ "$code" == 0 ]]
}

stop_container() {
  local name=$1 timeout=$2
  docker stop -t "$timeout" "$name" >/dev/null
  container_exit_successfully "$name"
  docker rm "$name" >/dev/null
}

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo "go not found" >&2; exit 2; }
TSHARK=${TSHARK:-tshark}
command -v "$TSHARK" >/dev/null 2>&1 || { echo "tshark not found (set TSHARK)" >&2; exit 2; }

log "Building images and the Go malformer..."
docker build -q -t "$ENDPOINT_IMAGE" "$ROOT/test/iec104/endpoint" >/dev/null
docker build -q -t "$CAPTURE_IMAGE" -f "$HERE/capture.Dockerfile" "$HERE" >/dev/null
( cd "$ROOT" && GOFLAGS=-mod=mod GOOS=linux GOARCH="$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')" \
  go build -o "$WORK/malformer" ./test/iec104/malformer )

NET_ID=$(docker network create --subnet "${SUBNET}.0/24" "$NET")
BRIDGE="br-${NET_ID:0:12}"

# start_rtu [PERIODIC_MS]: RTU with the cyclic measurement period (0 = off).
start_rtu() {
  RTU="containd-corpus-iec104-rtu-${STAMP}-$$"
  docker run -d --name "$RTU" --network "$NET" --ip "$RTU_IP" \
    -e PERIODIC_MS="${1:-2000}" --cap-add NET_ADMIN "$ENDPOINT_IMAGE" rtu >/dev/null
  sleep 1
  if ! container_running "$RTU"; then
    echo "RTU container $RTU exited before capture" >&2
    return 1
  fi
}

stop_rtu() {
  [[ -n "$RTU" ]] || return 0
  stop_container "$RTU" 5
  RTU=""
}

# run_capture NAME CMD... : start tcpdump to OUT/NAME.pcap, run CMD, stop.
run_capture() {
  local name=$1
  shift
  log "capture $name"
  CAP="containd-corpus-iec104-capture-${name}-${STAMP}-$$"
  docker run -d --name "$CAP" --net host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$WORK:/out" "$CAPTURE_IMAGE" -i "$BRIDGE" -U -w "/out/$name.pcap" 'tcp port 2404' >/dev/null
  sleep 1
  if ! container_running "$CAP"; then
    echo "capture container $CAP exited before client traffic" >&2
    return 1
  fi
  "$@"
  sleep 1
  if ! container_running "$CAP"; then
    echo "capture container $CAP exited during client traffic" >&2
    return 1
  fi
  # SIGTERM lets tcpdump flush and close the file (a SIGKILL can lose the tail).
  stop_container "$CAP" 10
  CAP=""
}

ep_cmd_status() {
  local expected=$1 status=0
  shift
  CLIENT_COUNT=$((CLIENT_COUNT + 1))
  if docker run --rm --name "containd-corpus-iec104-client-${STAMP}-$$-$CLIENT_COUNT" \
    --network "$NET" --ip "$CLIENT_IP" "$ENDPOINT_IMAGE" cmd "$RTU_IP" 2404 "$@"; then
    status=0
  else
    status=$?
  fi
  if (( status != expected )); then
    echo "IEC104 client exited $status, expected $expected: $*" >&2
    return 1
  fi
  if (( status != 0 )); then
    log "client returned the expected negative-response status $status: $*"
  fi
}

ep_cmd() { ep_cmd_status 0 "$@"; }
ep_cmd_negative() { ep_cmd_status 1 "$@"; }

malform() {
  CLIENT_COUNT=$((CLIENT_COUNT + 1))
  docker run --rm --name "containd-corpus-iec104-client-${STAMP}-$$-$CLIENT_COUNT" \
    --network "$NET" --ip "$CLIENT_IP" -v "$WORK/malformer:/malformer:ro" \
    --entrypoint /malformer "$ENDPOINT_IMAGE" -addr "$RTU_IP:2404" "$@"
}

# --- startup-gi-monitor: a long-lived control-centre session (handshake,
# STARTDT, station GI on CA 1, periodic COT 1 data, spontaneous type 31 after a
# breaker change, S-frames on t2, TESTFR on t3 = 20 s, then FIN on close).
scenario_startup() {
  CC="containd-corpus-iec104-cc-${STAMP}-$$"
  docker run -d --name "$CC" --network "$NET" --ip "$CC_IP" "$ENDPOINT_IMAGE" cc "$RTU_IP" 2404 >/dev/null
  sleep 4
  if ! container_running "$CC"; then
    echo "control-centre container $CC exited before client traffic" >&2
    return 1
  fi
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  sleep 2
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_CLOSE"
  sleep 22
  stop_container "$CC" 5
  CC=""
}

# --- session-management: no cyclic data, so an idle control centre with
# t3 = 3 s exchanges TESTFR act/con; a second session runs STOPDT then STARTDT;
# both sessions close with FIN.
scenario_session() {
  CC="containd-corpus-iec104-cc-${STAMP}-$$"
  docker run -d --name "$CC" --network "$NET" --ip "$CC_IP" -e IEC104_T3=3 "$ENDPOINT_IMAGE" cc "$RTU_IP" 2404 >/dev/null
  sleep 9
  if ! container_running "$CC"; then
    echo "control-centre container $CC exited before client traffic" >&2
    return 1
  fi
  ep_cmd stopstart
  sleep 1
  stop_container "$CC" 5
  CC=""
}

# --- sbo-command: select/execute, direct execute (negative), value mismatch
scenario_sbo() {
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_CLOSE"
  ep_cmd_negative direct "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  ep_cmd sbo "$ALLOWED_CA" "$IOA_ISOLATOR" "$DCS_OPEN"
}

# --- edge-addressing: GI on CA 1 and CA 2, unassigned command IOA
scenario_edge() {
  ep_cmd gi "$ALLOWED_CA"
  ep_cmd gi "$AUX_CA"
  ep_cmd_negative direct "$ALLOWED_CA" 65535 "$DCS_OPEN"
}

# --- malformed: layout and profile violations, split and coalesced APDUs
scenario_malformed() {
  malform -scenario truncated-apdu -ca "$ALLOWED_CA" -ioa "$IOA_BREAKER"
  malform -scenario bad-length       -ca "$ALLOWED_CA" -ioa "$IOA_BREAKER"
  malform -scenario malformed-dcs    -ca "$ALLOWED_CA" -ioa "$IOA_BREAKER"
  malform -scenario unsupported-type -ca "$ALLOWED_CA" -ioa "$IOA_BREAKER"
  malform -scenario dc-split         -ca "$ALLOWED_CA" -ioa "$IOA_ISOLATOR" -dcs "$DCS_OPEN"
  malform -scenario coalesced        -ca "$ALLOWED_CA" -ioa "$IOA_ISOLATOR" -dcs "$DCS_OPEN"
}

start_rtu
run_capture startup-gi-monitor scenario_startup
stop_rtu
start_rtu
run_capture sbo-command scenario_sbo
stop_rtu
start_rtu
run_capture edge-addressing scenario_edge
stop_rtu
start_rtu
run_capture malformed scenario_malformed
stop_rtu
start_rtu 0
run_capture session-management scenario_session
stop_rtu

mkdir -p "$OUT"
for f in startup-gi-monitor sbo-command edge-addressing malformed session-management; do
  [[ -s "$WORK/$f.pcap" ]] || { echo "capture $f produced no data" >&2; exit 1; }
  cp "$WORK/$f.pcap" "$OUT/$f.pcap"
done

# expected_decode NAME: one TSV row per TCP record from Wireshark's IEC 104 dissector.
# Multi-valued fields (several APDUs in one segment, several objects in one
# ASDU) are comma-separated in segment order.
expected_decode() {
  local name=$1
  {
    "$TSHARK" -r "$OUT/$name.pcap" -Y iec60870_104 \
      -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:FALSE \
      -o tcp.analyze_sequence_numbers:TRUE \
      -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=, \
      -e frame.number -e ip.src -e tcp.srcport -e tcp.seq -e tcp.len \
      -e iec60870_104.apdulen -e iec60870_104.type -e iec60870_104.utype -e iec60870_104.tx -e iec60870_104.rx \
      -e iec60870_asdu.typeid -e iec60870_asdu.sq -e iec60870_asdu.numix -e iec60870_asdu.causetx \
      -e iec60870_asdu.nega -e iec60870_asdu.test -e iec60870_asdu.oa -e iec60870_asdu.addr -e iec60870_asdu.ioa \
      -e iec60870_asdu.diq -e iec60870_asdu.qds -e iec60870_asdu.float -e iec60870_asdu.dco -e iec60870_asdu.dco.se \
      -e iec60870_asdu.qoi -e iec60870_asdu.cp56time -e tcp.payload
  } >"$OUT/$name.expected.tsv"
}

for f in startup-gi-monitor sbo-command edge-addressing malformed session-management; do
  expected_decode "$f"
done

ARCH=$(docker image inspect "$ENDPOINT_IMAGE" --format '{{.Architecture}}')
SUM_FILES=(
  edge-addressing.pcap edge-addressing.expected.tsv edge-addressing.expectations.json
  malformed.pcap malformed.expected.tsv malformed.expectations.json
  sbo-command.pcap sbo-command.expected.tsv sbo-command.expectations.json
  session-management.pcap session-management.expected.tsv session-management.expectations.json
  startup-gi-monitor.pcap startup-gi-monitor.expected.tsv startup-gi-monitor.expectations.json
)
for f in "${SUM_FILES[@]}"; do
  [[ -s "$OUT/$f" ]] || { echo "missing generated corpus artifact $OUT/$f" >&2; exit 1; }
done
( cd "$OUT" && shasum -a 256 -- "${SUM_FILES[@]}" > SHA256SUMS )
log "Captures written to $OUT (lib60870 2.4.1, alpine arch $ARCH)"
cat "$OUT/SHA256SUMS"
