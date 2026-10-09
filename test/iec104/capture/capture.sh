#!/usr/bin/env bash
set -euo pipefail

# Regenerate the IEC 60870-5-104 reference pcaps under test/iec104/testdata/.
#
# These are Apache-2.0 test data: packet captures of lib60870 (and the pure-Go
# malformer) traffic on a throwaway Docker network. The pcaps carry protocol
# bytes only, no lib60870 code. They seed the L1 decoder and L4 engine tests;
# the Go unit tests derive byte fixtures from them and never need tshark at run
# time. The capture runs the RTU and a control-centre/command client directly
# (no firewall) so the fixtures are clean lib60870 wire traffic.
#
# For each pcap it also writes NAME.expected.tsv: Wireshark's independent
# decode of every APDU (one row per APDU), so the containd decoder can be
# checked against a second parser. tshark runs only here, at regeneration
# time; Go tests never need it.
#
# Requirements: docker, Go (to build the malformer), tshark (TSHARK). Nothing
# is published to a host port; everything runs on a throwaway network torn
# down on exit.
#
# Usage: test/iec104/capture/capture.sh [OUT_DIR]   (default test/iec104/testdata)

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/test/iec104/capture"
OUT=${1:-$ROOT/test/iec104/testdata}
WORK=$(mktemp -d)

ENDPOINT_IMAGE=${IEC104_ENDPOINT_IMAGE:-containd-iec104-endpoint:capture}
CAPTURE_IMAGE=${IEC104_CAPTURE_IMAGE:-containd-iec104-capture:capture}
STAMP=$(date -u +%Y%m%d-%H%M%S)
NET="iec104-capture-${STAMP}-$$"
SUBNET=${IEC104_CAPTURE_SUBNET:-10.235.0}
RTU_IP=${SUBNET}.10
CLIENT_IP=${SUBNET}.20
CC_IP=${SUBNET}.21
RTU=""
CC=""
CAP=""
NET_ID=""

ALLOWED_CA=1
AUX_CA=2
IOA_BREAKER=2001
IOA_ISOLATOR=2002
DCS_OPEN=1
DCS_CLOSE=2

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

cleanup() {
  set +e
  [[ -n "$CAP" ]] && docker rm -f "$CAP" >/dev/null 2>&1
  [[ -n "$CC" ]] && docker rm -f "$CC" >/dev/null 2>&1
  [[ -n "$RTU" ]] && docker rm -f "$RTU" >/dev/null 2>&1
  [[ -n "$NET_ID" ]] && docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo "go not found" >&2; exit 2; }
TSHARK=${TSHARK:-tshark}
command -v "$TSHARK" >/dev/null 2>&1 || { echo "tshark not found (set TSHARK)" >&2; exit 2; }

log "Building images and the Go malformer..."
docker build -q -t "$ENDPOINT_IMAGE" "$ROOT/test/iec104/endpoint" >/dev/null
docker build -q -t "$CAPTURE_IMAGE" -f "$HERE/capture.Dockerfile" "$HERE" >/dev/null
GOFLAGS=-mod=mod GOOS=linux GOARCH="$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')" \
  go build -o "$WORK/malformer" "$ROOT/test/iec104/malformer"

NET_ID=$(docker network create --subnet "${SUBNET}.0/24" "$NET")
BRIDGE="br-${NET_ID:0:12}"

# start_rtu [PERIODIC_MS]: RTU with the cyclic measurement period (0 = off).
start_rtu() {
  RTU=$(docker run -d --rm --name "iec104-cap-rtu-$$" --network "$NET" --ip "$RTU_IP" \
    -e PERIODIC_MS="${1:-2000}" --cap-add NET_ADMIN "$ENDPOINT_IMAGE" rtu)
  sleep 1
}

stop_rtu() {
  [[ -n "$RTU" ]] && docker rm -f "$RTU" >/dev/null 2>&1
  RTU=""
}

# run_capture NAME CMD... : start tcpdump to OUT/NAME.pcap, run CMD, stop.
run_capture() {
  local name=$1
  shift
  log "capture $name"
  CAP=$(docker run -d --rm --name "iec104-cap-cap-$$" --net host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$WORK:/out" "$CAPTURE_IMAGE" -i "$BRIDGE" -U -w "/out/$name.pcap" 'tcp port 2404')
  sleep 1
  "$@"
  sleep 1
  # SIGTERM lets tcpdump flush and close the file (a SIGKILL can lose the tail).
  docker stop -t 10 "$CAP" >/dev/null 2>&1
  CAP=""
}

ep_cmd() {
  docker run --rm --network "$NET" --ip "$CLIENT_IP" "$ENDPOINT_IMAGE" cmd "$RTU_IP" 2404 "$@" || true
}

malform() {
  docker run --rm --network "$NET" --ip "$CLIENT_IP" -v "$WORK/malformer:/malformer:ro" \
    --entrypoint /malformer "$ENDPOINT_IMAGE" -addr "$RTU_IP:2404" "$@" || true
}

# --- startup-gi-monitor: a long-lived control-centre session (handshake,
# STARTDT, station GI on CA 1, periodic COT 1 data, spontaneous type 31 after a
# breaker change, S-frames on t2, TESTFR on t3 = 20 s, then FIN on close).
scenario_startup() {
  CC=$(docker run -d --rm --network "$NET" --ip "$CC_IP" "$ENDPOINT_IMAGE" cc "$RTU_IP" 2404)
  sleep 4
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  sleep 2
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_CLOSE"
  sleep 22
  docker stop -t 5 "$CC" >/dev/null 2>&1
  CC=""
}

# --- session-management: no cyclic data, so an idle control centre with
# t3 = 3 s exchanges TESTFR act/con; a second session runs STOPDT then STARTDT;
# both sessions close with FIN.
scenario_session() {
  CC=$(docker run -d --rm --network "$NET" --ip "$CC_IP" -e IEC104_T3=3 "$ENDPOINT_IMAGE" cc "$RTU_IP" 2404)
  sleep 9
  ep_cmd stopstart
  sleep 1
  docker stop -t 5 "$CC" >/dev/null 2>&1
  CC=""
}

# --- sbo-command: select/execute, direct execute (negative), value mismatch
scenario_sbo() {
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  ep_cmd sbo "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_CLOSE"
  ep_cmd direct "$ALLOWED_CA" "$IOA_BREAKER" "$DCS_OPEN"
  ep_cmd sbo "$ALLOWED_CA" "$IOA_ISOLATOR" "$DCS_OPEN"
}

# --- edge-addressing: GI on CA 1 and CA 2, unassigned command IOA
scenario_edge() {
  ep_cmd gi "$ALLOWED_CA"
  ep_cmd gi "$AUX_CA"
  ep_cmd direct "$ALLOWED_CA" 65535 "$DCS_OPEN"
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

# expected_decode NAME: one TSV row per APDU from Wireshark's IEC 104 dissector.
# Multi-valued fields (several APDUs in one segment, several objects in one
# ASDU) are comma-separated in segment order.
expected_decode() {
  local name=$1
  {
    printf '# %s decode of %s.pcap; one row per TCP segment carrying APDUs.\n' "$("$TSHARK" -v | head -n 1)" "$name"
    printf '# apci_type: 0x0=I 0x1=S 0x3=U. utype: 0x01 STARTDT act, 0x02 con, 0x04 STOPDT act, 0x08 con, 0x10 TESTFR act, 0x20 con.\n'
    "$TSHARK" -r "$OUT/$name.pcap" -Y iec60870_104 -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=, \
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
( cd "$OUT" && shasum -a 256 -- *.pcap > SHA256SUMS )
log "Captures written to $OUT (lib60870 2.4.1, alpine arch $ARCH)"
cat "$OUT/SHA256SUMS"
