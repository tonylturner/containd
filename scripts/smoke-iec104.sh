#!/usr/bin/env bash
set -euo pipefail

# containd IEC 60870-5-104 Linux truth harness.
#
# Brings up the two-endpoint compose (lib60870 RTU + control centre on two
# disposable networks, locally built containd firewall routing between them,
# loopback-only management), routes the endpoints through the firewall, and
# runs every enforcement assertion. The proof of plant state is the RTU's own
# state file and command confirmations, never a timeout.
#
# Every assertion is a real check; nothing is hard-coded to pass or fail.
# Results carry one of four statuses:
#   PASS             the assertion held.
#   FAIL             a baseline (non-gated) assertion failed: a harness,
#                    routing or monitoring defect that is independent of IEC
#                    enforcement.
#   GATE-FAIL        an assertion that needs IEC104 enforcement failed:
#                    forbidden commands or malformed traffic were
#                    not prevented as required.
#   NOT-IMPLEMENTED  the requested freshness window is too short for acceptance.
# Exit status: 0 every assertion passed (acceptance); 1 a FAIL (or a fatal
# setup error); 3 the baseline passed but GATE-FAIL or NOT-IMPLEMENTED remain.
# "Passed with skips" is not acceptance.
#
# The telemetry freshness check runs for IEC104_FRESHNESS_SECONDS (default
# 660, more than 10 minutes); a value below 600 records NOT-IMPLEMENTED.
#
# Requirements: docker compose, jq, curl, python3. Builds the local firewall
# image and the GPLv3 endpoint image if they are absent. The default endpoint
# tag hashes its build context, including the Dockerfile's pinned dependencies.
# Uses a unique compose project and ephemeral loopback ports, so it never
# touches another smoke stack's containers, networks or volumes. Its containers,
# networks and volumes are removed on exit; built images remain for reuse.

endpoint_source_hash() {
  python3 - "$ROOT/test/iec104/endpoint" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if path.is_file():
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
PY
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILE="$ROOT/test/iec104/compose.yml"
TOKEN=${IEC104_ADMIN_TOKEN:-devtoken}
STAMP=$(date -u +%Y%m%d-%H%M%S)
PROJECT=${IEC104_PROJECT:-iec104-smoke-${STAMP}-$$}
FIREWALL_IMAGE=${IEC104_FIREWALL_IMAGE:-containd/containd:iec104-smoke}
ENDPOINT_IMAGE=${IEC104_ENDPOINT_IMAGE:-containd-iec104-endpoint:iec104-smoke-$(endpoint_source_hash)}
RESULTS_DIR=${IEC104_RESULTS_DIR:-$ROOT/build/iec104-smoke}
RESULTS_FILE="$RESULTS_DIR/results.json"
WORK_DIR=$(mktemp -d)
CURL="curl -sf --max-time 10 --connect-timeout 5"
AUTH_HEADER="Authorization: Bearer ${TOKEN}"

CC_SUBNET=${IEC104_CC_SUBNET:-10.233.0}
RTU_SUBNET=${IEC104_RTU_SUBNET:-10.234.0}
export IEC104_CC_SUBNET="$CC_SUBNET" IEC104_RTU_SUBNET="$RTU_SUBNET"
CC_IP=${CC_SUBNET}.10
RTU_IP=${RTU_SUBNET}.10
FW_CC_IP=${CC_SUBNET}.2
FW_RTU_IP=${RTU_SUBNET}.2
RTU_PORT=2404

# Point map (test/iec104/README.md). The policy allows only the double command
# (type 46) at CA 1 / IOA 2001.
ALLOWED_CA=1
ALLOWED_IOA=2001
# A second device the RTU actuates but the policy forbids: a true firewall gate,
# not an address the RTU would reject on its own.
FORBIDDEN_IOA=2002
FORBIDDEN_CA=2
DCS_OPEN=1
DCS_CLOSE=2

STACK_UP=0
PASS_COUNT=0
FAIL_COUNT=0
GATE_FAIL_COUNT=0
NOT_IMPL_COUNT=0
ABORTED=0
BASE=""
ENGINE=""
CC_LAST_POLICY_COT3=0

export IEC104_FIREWALL_IMAGE="$FIREWALL_IMAGE"
export IEC104_ENDPOINT_IMAGE="$ENDPOINT_IMAGE"

compose() {
  docker compose --project-name "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "[$(timestamp)] $*"; }

# now_s prints a sub-second monotonic-ish wall time in seconds (float). Python 3
# is already a harness dependency and gives the same resolution on macOS and
# Linux, unlike `date +%N` (not on macOS) or EPOCHREALTIME (bash 5 only).
now_s() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
elapsed_s() { python3 -c 'import sys,time; print(f"{time.time()-float(sys.argv[1]):.3f}")' "$1"; }
within_budget() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' "$1" "$2"; }

record() {
  local name=$1 status=$2 detail=$3 gate=${4:-false}
  local tmp="$RESULTS_FILE.tmp"
  jq --arg name "$name" --arg status "$status" --arg detail "$detail" --argjson gate "$gate" \
    '.assertions += [{name:$name,status:$status,detail:$detail,gate:$gate}]' \
    "$RESULTS_FILE" >"$tmp"
  mv "$tmp" "$RESULTS_FILE"
}

pass() {
  local name=$1 detail=${2:-}
  PASS_COUNT=$((PASS_COUNT + 1))
  log "PASS  $name${detail:+ — $detail}"
  record "$name" PASS "$detail"
}

# fail records a non-gated failure (a harness defect on this branch).
fail() {
  local name=$1 detail=${2:-}
  FAIL_COUNT=$((FAIL_COUNT + 1))
  log "FAIL  $name${detail:+ — $detail}"
  record "$name" FAIL "$detail"
}

# gate_fail records an assertion requiring IEC104 enforcement that did not
# pass. Any occurrence means acceptance has not been met.
gate_fail() {
  local name=$1 detail=${2:-}
  GATE_FAIL_COUNT=$((GATE_FAIL_COUNT + 1))
  log "GATE  $name${detail:+ — $detail}  (IEC104 enforcement assertion failed)"
  record "$name" GATE-FAIL "$detail" true
}

# gate_pass records an IEC104 enforcement assertion that passed.
gate_pass() {
  local name=$1 detail=${2:-}
  PASS_COUNT=$((PASS_COUNT + 1))
  log "PASS  $name${detail:+ — $detail}  (gated assertion)"
  record "$name" PASS "$detail" true
}

# not_implemented records an enforcement assertion the harness cannot drive yet.
not_implemented() {
  local name=$1 detail=${2:-}
  NOT_IMPL_COUNT=$((NOT_IMPL_COUNT + 1))
  log "TODO  $name${detail:+ — $detail}"
  record "$name" NOT-IMPLEMENTED "$detail" true
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
finish() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ "$STACK_UP" -eq 1 ]]; then
    compose logs --no-color >"$RESULTS_DIR/compose.log" 2>&1
    compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1
    local remaining
    remaining=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT}_" || true)
    [[ -n "$remaining" ]] && log "WARNING: harness networks remain: $remaining"
  fi
  rm -rf "$WORK_DIR"
  if [[ -f "$RESULTS_FILE" ]]; then
    local tmp="$RESULTS_FILE.tmp"
    jq --argjson pass "$PASS_COUNT" --argjson fail "$FAIL_COUNT" --argjson gate "$GATE_FAIL_COUNT" \
      --argjson todo "$NOT_IMPL_COUNT" --argjson rc "$rc" \
      '.summary = {passed:$pass, failed:$fail, gate_failed:$gate, not_implemented:$todo, exit_status:$rc}' \
      "$RESULTS_FILE" >"$tmp" && mv "$tmp" "$RESULTS_FILE"
  fi
  exit "$rc"
}
trap finish EXIT

fatal() {
  log "FATAL: $*"
  exit 1
}

ensure_tools() {
  local bin
  for bin in docker jq curl python3; do
    command -v "$bin" >/dev/null 2>&1 || fatal "missing required tool: $bin"
  done
}

ensure_images() {
  if ! docker image inspect "$FIREWALL_IMAGE" >/dev/null 2>&1; then
    log "Building firewall image $FIREWALL_IMAGE from the branch..."
    docker build -f "$ROOT/build/Dockerfile.mgmt" -t "$FIREWALL_IMAGE" "$ROOT" >"$WORK_DIR/fw-build.log" 2>&1 ||
      { cat "$WORK_DIR/fw-build.log"; fatal "firewall image build failed"; }
  fi
  if ! docker image inspect "$ENDPOINT_IMAGE" >/dev/null 2>&1; then
    log "Building endpoint image $ENDPOINT_IMAGE (lib60870, GPLv3, harness only)..."
    docker build -t "$ENDPOINT_IMAGE" "$ROOT/test/iec104/endpoint" >"$WORK_DIR/ep-build.log" 2>&1 ||
      { cat "$WORK_DIR/ep-build.log"; fatal "endpoint image build failed"; }
  fi
}

wait_http() {
  local url=$1
  for _ in $(seq 1 60); do
    $CURL "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

discover_iface() {
  local state=$1 ip=$2
  echo "$state" | jq -r --arg ip "$ip" 'map(select(.addrs[]? | contains($ip))) | .[0].name // empty'
}

rtu_state() {
  compose exec -T rtu cat /state/rtu.json 2>/dev/null
}

# rtu_field reads one key from the RTU state JSON, empty if unavailable.
rtu_field() {
  rtu_state | jq -r --arg k "$1" '.[$k] // empty' 2>/dev/null
}

# run_cmd runs the lib60870 command client from the cc container and returns
# its exit code (0 positive confirmation, 1 negative/absent, 2 error).
run_cmd() {
  compose exec -T cc iec104ep cmd "$RTU_IP" "$RTU_PORT" "$@"
}

# ---- bring-up ---------------------------------------------------------------

ensure_tools
ensure_images
mkdir -p "$RESULTS_DIR"
# Remove only what this script writes; a caller may keep its own console log
# in the same directory.
rm -f "$RESULTS_DIR/compose.log" "$RESULTS_DIR/cc.log"
printf '{"schema_version":1,"project":"%s","assertions":[],"summary":{}}\n' "$PROJECT" >"$RESULTS_FILE"

log "Building the Go malformer client (Apache-2.0, for malformed/split cases)..."
DOCKER_ARCH=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')
GOFLAGS=-mod=mod GOOS=linux GOARCH="$DOCKER_ARCH" go build -o "$WORK_DIR/malformer" "$ROOT/test/iec104/malformer" ||
  fatal "could not build the malformer client"
log "Building the queueholder (NFQUEUE bind-contention tool)..."
GOFLAGS=-mod=mod GOOS=linux GOARCH="$DOCKER_ARCH" go build -o "$WORK_DIR/queueholder" "$ROOT/test/iec104/queueholder" ||
  fatal "could not build the queueholder"

log "Bringing up the harness (project $PROJECT)..."
compose up -d --wait --wait-timeout 120 >"$WORK_DIR/up.log" 2>&1 || { cat "$WORK_DIR/up.log"; fatal "compose up failed"; }
STACK_UP=1

# Copy the malformer binary into the cc container for the split/malformed cases.
compose cp "$WORK_DIR/malformer" cc:/usr/local/bin/malformer >/dev/null 2>&1 ||
  log "WARNING: could not install the malformer in the cc container"

BASE="http://127.0.0.1:$(compose port firewall 18080 | awk -F: '{print $NF}')/api/v1"
ENGINE="http://127.0.0.1:$(compose port firewall 8081 | awk -F: '{print $NF}')"
log "Management on $BASE, engine on $ENGINE (loopback only)"

wait_http "${BASE}/health" || fatal "management plane did not become ready"

# ---- preflight --------------------------------------------------------------

if compose exec -T firewall sh -c 'command -v nft >/dev/null && nft list ruleset >/dev/null 2>&1'; then
  pass "preflight: firewall container can read nftables (NET_ADMIN present)"
else
  fail "preflight: firewall cannot use nftables"
fi

# shellcheck disable=SC2016  # expansion happens inside the container shell
if compose exec -T firewall sh -c '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]'; then
  pass "preflight: IPv4 forwarding enabled on the firewall"
else
  fail "preflight: IPv4 forwarding not enabled"
fi

# ---- configuration ----------------------------------------------------------

log "Discovering firewall interfaces..."
STATE=""
for _ in $(seq 1 15); do
  STATE=$($CURL -H "$AUTH_HEADER" "${BASE}/interfaces/state" || true)
  [[ -n "$STATE" && "$STATE" != "[]" ]] && break
  sleep 2
done
CC_DEV=$(discover_iface "$STATE" "$FW_CC_IP")
RTU_DEV=$(discover_iface "$STATE" "$FW_RTU_IP")
[[ -n "$CC_DEV" && -n "$RTU_DEV" ]] || fatal "could not find firewall interfaces for $FW_CC_IP / $FW_RTU_IP: $STATE"
log "Firewall interfaces: cc=$CC_DEV ($FW_CC_IP), rtu=$RTU_DEV ($FW_RTU_IP)"

# cc_count PATTERN FILE: lines matching PATTERN in the cc container's /tmp/FILE.
cc_count() {
  compose exec -T cc sh -c "grep -c \"$1\" /tmp/$2 2>/dev/null || true" | tr -d '\r'
}

# wait_cc_settled: wait up to 20 s for an active connection, stable
# close/connect counts for 3 s, and a spontaneous update after the latest
# policy apply. A live but stalled session must not pass as settled.
wait_cc_settled() {
  local prev="" cur stable=0 cot3
  for _ in $(seq 1 40); do
    cur="$(cc_count 'CONN closed' cc.log)/$(cc_count 'CC connected' cc.log)"
    cot3=$(cc_count 'cot=3 ' cc.log)
    if [[ "$cur" == "$prev" && "${cur#*/}" -gt "${cur%/*}" &&
      "$cot3" -gt "$CC_LAST_POLICY_COT3" ]]; then
      stable=$((stable + 1))
      ((stable >= 6)) && return 0
    else
      stable=0
    fi
    prev=$cur
    sleep 0.5
  done
  return 1
}

apply_config() {
  local cfg=$1 label=$2 resp code
  resp="$WORK_DIR/cfg-resp.json"
  code=$(echo "$cfg" | $CURL -w "%{http_code}" -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    -X POST "${BASE}/config" --data-binary @- -o "$resp" 2>/dev/null || true)
  if [[ "$code" != "200" ]]; then
    log "config POST for $label rejected (HTTP $code): $(cat "$resp" 2>/dev/null)"
    return 1
  fi
  local ruleset snap
  ruleset="$WORK_DIR/ruleset.json"
  $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" -o "$ruleset" || return 1
  snap=$(jq -c '.snapshot' "$ruleset")
  code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/config" \
    --data "$(echo "$cfg" | jq -c '.dataPlane')" -o /dev/null 2>/dev/null || true)
  [[ "$code" == "200" ]] || { log "engine config for $label failed (HTTP $code)"; return 1; }
  code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/apply_rules" \
    --data "$snap" -o /dev/null 2>/dev/null || true)
  [[ "$code" == "200" ]] || { log "engine apply_rules for $label failed (HTTP $code)"; return 1; }
  CC_LAST_POLICY_COT3=$(cc_count 'cot=3 ' cc.log)
  return 0
}

CFG=$($CURL -H "$AUTH_HEADER" "${BASE}/config")

# L4 baseline: zones for the two sides and a plain tcp/2404 allow both ways, so
# monitoring works and the harness routing is provable even before IEC
# enforcement exists.
BASELINE=$(echo "$CFG" | jq \
  --arg ccDev "$CC_DEV" --arg rtuDev "$RTU_DEV" --arg ccIp "$CC_IP" --arg rtuIp "$RTU_IP" '
  .zones = ((.zones // []) + [{name:"lan4",description:"control centre"},{name:"lan1",description:"station"}]
    | unique_by(.name))
  | .interfaces = [
      {name:"cc",   device:$ccDev,  zone:"lan4"},
      {name:"rtu",  device:$rtuDev, zone:"lan1"}
    ]
  | .system.mgmt.httpListenAddr=":18080"
  | .system.mgmt.listenAddr=":18080"
  | .dataPlane.enforcement = true
  | .dataPlane.enforceTable = "containd"
  | .firewall.defaultAction = "DENY"
  | .firewall.rules = [
      {id:"cc-rtu-2404", sourceZones:["lan4"], destZones:["lan1"],
       sources:[($ccIp + "/32")], destinations:[($rtuIp + "/32")],
       protocols:[{name:"tcp", port:"2404"}], action:"ALLOW", log:true},
      {id:"rtu-cc-2404", sourceZones:["lan1"], destZones:["lan4"],
       sources:[($rtuIp + "/32")], destinations:[($ccIp + "/32")],
       protocols:[{name:"tcp", port:"2404"}], action:"ALLOW", log:true}
    ]
')

if apply_config "$BASELINE" "L4 baseline"; then
  pass "L4 baseline policy applied (tcp/2404 allowed both ways through the firewall)"
else
  fatal "could not apply the L4 baseline policy"
fi

log "Programming endpoint routes through the firewall..."
{
  set +e
  compose exec -T cc ip route replace default via "$FW_CC_IP"
  compose exec -T rtu ip route replace default via "$FW_RTU_IP"
  set -e
} >"$WORK_DIR/routes.log" 2>&1 || true

CC_ROUTE=$(compose exec -T cc ip route get "$RTU_IP" | tr -d '\r')
if echo "$CC_ROUTE" | grep -q "via $FW_CC_IP"; then
  pass "control-centre route to the RTU goes via the firewall" "$CC_ROUTE"
else
  fail "control-centre route does not use the firewall" "$CC_ROUTE"
fi

# ---- EU enforce policy probe ------------------------------------------------

# EU policy with the harness addresses. Strict ICS decoding preserves the
# typeIds/classes/ca/ioa predicates for semantic enforcement.
EU_POLICY=$(echo "$BASELINE" | jq \
  --arg ccIp "$CC_IP" --arg rtuIp "$RTU_IP" --argjson ca "$ALLOWED_CA" --argjson ioa "$ALLOWED_IOA" '
  .dataPlane.dpiEnabled = true
  | .dataPlane.dpiMode = "enforce"
  | .dataPlane.nfqueueGroup = 101
  | .dataPlane.nflogGroup = 100
  | .dataPlane.dpiIcsProtocols = {"iec104": true}
  | .firewall.rules = [
      {id:"cc-rtu-iec104-session", sourceZones:["lan4"], destZones:["lan1"],
       sources:[($ccIp + "/32")], destinations:[($rtuIp + "/32")],
       protocols:[{name:"tcp", port:"2404"}],
       ics:{protocol:"iec104", readOnly:true, mode:"enforce"}, action:"ALLOW", log:true},
      {id:"cc-rtu-breaker-command", sourceZones:["lan4"], destZones:["lan1"],
       sources:[($ccIp + "/32")], destinations:[($rtuIp + "/32")],
       protocols:[{name:"tcp", port:"2404"}],
       ics:{protocol:"iec104", typeIds:[46], classes:["control"], direction:"request",
            ca:[$ca], ioa:[{start:$ioa, end:$ioa}], mode:"enforce"}, action:"ALLOW", log:true},
      {id:"rtu-cc-command-confirm", sourceZones:["lan4"], destZones:["lan1"],
       sources:[($ccIp + "/32")], destinations:[($rtuIp + "/32")],
       protocols:[{name:"tcp", port:"2404"}],
       ics:{protocol:"iec104", classes:["control"], direction:"response", mode:"enforce"},
       action:"ALLOW", log:true},
      {id:"deny-other-iec104", sourceZones:["lan4"], destZones:["lan1"],
       protocols:[{name:"tcp", port:"2404"}],
       ics:{protocol:"iec104", mode:"enforce"}, action:"DENY", log:true}
    ]
')

EU_APPLIED=0
if apply_config "$EU_POLICY" "EU enforce policy"; then
  EU_APPLIED=1
  gate_pass "Scoped IEC104 enforce policy is accepted and applied"
else
  gate_fail "Scoped IEC104 enforce policy is accepted and applied" "management API or engine rejected it"
  # Fall back to the L4 baseline so the remaining assertions still run.
  apply_config "$BASELINE" "L4 baseline (restore)" || fatal "could not restore the L4 baseline"
  compose exec -T cc ip route replace default via "$FW_CC_IP" >/dev/null 2>&1 || true
  compose exec -T rtu ip route replace default via "$FW_RTU_IP" >/dev/null 2>&1 || true
fi

health_json() {
  $CURL -H "$AUTH_HEADER" "${BASE}/health" 2>/dev/null || echo '{}'
}

if [[ "$EU_APPLIED" -eq 1 ]] && health_json | jq -e '.iec104Enforcement.active == true and .iec104Enforcement.healthy == true' >/dev/null 2>&1; then
  gate_pass "health reports IEC104 enforcement active and healthy after the EU policy" "$(health_json | jq -c '.iec104Enforcement')"
else
  gate_fail "health reports IEC104 enforcement active and healthy after the EU policy" "health: $(health_json | jq -c '.iec104Enforcement // "no iec104Enforcement object"')"
fi

# The engine binds the NFQUEUE group from the EU policy; the kernel lists bound
# queues in /proc/net/netfilter/nfnetlink_queue (first column = queue number).
if compose exec -T firewall sh -c "awk '\$1 == 101' /proc/net/netfilter/nfnetlink_queue | grep -q ." 2>/dev/null; then
  pass "preflight: NFQUEUE group 101 is bound in the firewall's kernel"
else
  fail "preflight: NFQUEUE group 101 is not bound (kernel or engine cannot queue)" \
    "$(compose exec -T firewall cat /proc/net/netfilter/nfnetlink_queue 2>&1 | tr '\n' ' ' | head -c 160)"
fi

# Reset injection needs CAP_NET_RAW (bit 13) in the firewall's effective set.
CAP_EFF=$(compose exec -T firewall sh -c "awk '/^CapEff/ {print \$2}' /proc/1/status" | tr -d '\r')
if [[ -n "$CAP_EFF" ]] && (((16#$CAP_EFF >> 13) & 1)); then
  pass "preflight: firewall holds CAP_NET_RAW for reset injection" "CapEff=$CAP_EFF"
else
  fail "preflight: firewall lacks CAP_NET_RAW" "CapEff=${CAP_EFF:-unknown}"
fi

# ---- helpers for the hard assertions ----------------------------------------

HOLD=${IEC104_HOLD:-5s}
FRESHNESS_SECONDS=${IEC104_FRESHNESS_SECONDS:-660}

# malformer runs the pure-Go client from the cc container and prints its last
# line (which ends with client_socket=reset|eof|open|error:...).
malformer() {
  compose exec -T cc /usr/local/bin/malformer -addr "$RTU_IP:$RTU_PORT" "$@" 2>&1 | tr -d '\r' | tail -n 1
}

socket_of() {
  sed -n 's/.*client_socket=\([^ ]*\).*/\1/p' <<<"$1"
}

# iec_event_since TS: true if the event ring holds an IEC104 malformed or
# unsupported event at or after TS (UTC, second resolution).
iec_event_since() {
  local since=$1
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=200" 2>/dev/null | jq -e --arg since "$since" '
    any(.[]; .proto == "iec104" and (.kind == "malformed" or .kind == "unsupported")
      and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= ($since | fromdateiso8601)))' >/dev/null 2>&1
}

# assert_not_received NAME COUNTER CMD...: run CMD and assert the RTU counter
# (commands_received or gi_requests) did not advance and no write was applied.
# These must be prevented by the active IEC104 enforcement policy.
assert_not_received() {
  local name=$1 counter=$2 rc=0 before after writes_before writes_after out detail
  shift 2
  before=$(rtu_field "$counter")
  writes_before=$(rtu_field writes_applied)
  out=$("$@" 2>&1) || rc=$?
  sleep 1
  after=$(rtu_field "$counter")
  writes_after=$(rtu_field writes_applied)
  detail="exit $rc; $counter $before -> $after; writes $writes_before -> $writes_after; last_command '$(rtu_field last_command)'; $(tr '\n' ' ' <<<"$out" | head -c 100)"
  if [[ -n "$before" && "$after" == "$before" && "$writes_after" == "$writes_before" ]]; then
    gate_pass "$name" "$detail"
  else
    gate_fail "$name" "$detail"
  fi
}

# ---- monitoring (passes on the L4 path) -------------------------------------

# shellcheck source=scripts/smoke-iec104-observe.sh
source "$ROOT/scripts/smoke-iec104-observe.sh"

log "Starting a long-lived control-centre session (STARTDT + station GI)..."
compose exec -T cc pkill -f 'iec104ep cc' >/dev/null 2>&1 || true
compose exec -d cc sh -c "iec104ep cc $RTU_IP $RTU_PORT >/tmp/cc.log 2>&1" >/dev/null 2>&1 || true
sleep 3

if compose exec -T cc grep -q 'CC connected' /tmp/cc.log 2>/dev/null; then
  pass "monitoring: control centre established an IEC104 session through the firewall"
else
  fail "monitoring: control centre could not connect through the firewall" "$(compose exec -T cc cat /tmp/cc.log 2>/dev/null | tr '\n' ' ' | head -c 160)"
fi

rc=0
run_cmd gi "$ALLOWED_CA" >"$WORK_DIR/gi.out" 2>&1 || rc=$?
if grep -q 'type=100 cot=7 negative=0' "$WORK_DIR/gi.out" &&
  grep -q 'type=1 cot=20 .*ioa=1002' "$WORK_DIR/gi.out" &&
  grep -q 'cot=20' "$WORK_DIR/gi.out" &&
  grep -q 'type=100 cot=10' "$WORK_DIR/gi.out"; then
  pass "monitoring: station GI Type 1 IOA 1002, COT 20 data and termination pass server -> client"
else
  fail "monitoring: station GI did not complete" "exit $rc; $(tr '\n' ' ' <"$WORK_DIR/gi.out" | head -c 200)"
fi

if compose exec -T cc grep -q 'type=1 cot=20 .*ioa=1002' /tmp/cc.log 2>/dev/null &&
  compose exec -T cc grep -q 'type=30 cot=3 .*ioa=1002' /tmp/cc.log 2>/dev/null; then
  pass "monitoring: Type 1 GI and spontaneous Type 30 for trip IOA 1002 reach the control centre"
else
  fail "monitoring: Type 1 or Type 30 trip telemetry was not decoded" \
    "$(compose exec -T cc grep -E 'type=(1|30) ' /tmp/cc.log 2>/dev/null | tr '\n' ' ' | head -c 200)"
fi

CC_SPONT_START=$(cc_count 'cot=3 ' cc.log)

observe_clean
observe_apci
observe_inventory before-deny

# ---- Enforcement assertions --------------------------------------------------

# 1. First forbidden select and first forbidden execute are dropped; RTU point
#    state unchanged. IOA 2002 is a real RTU command point the policy forbids.
assert_not_received "first forbidden select is dropped before the RTU" commands_received \
  run_cmd select "$ALLOWED_CA" "$FORBIDDEN_IOA" "$DCS_OPEN"
observe_denied
assert_not_received "first forbidden execute is dropped before the RTU" commands_received \
  run_cmd direct "$ALLOWED_CA" "$FORBIDDEN_IOA" "$DCS_OPEN"

# 2. The right CA + IOA is allowed (select, execute, confirmations both ways);
#    each wrong dimension (IOA, CA, type) is denied.
rc=0
breaker_before=$(rtu_field breaker_state)
run_cmd sbo "$ALLOWED_CA" "$ALLOWED_IOA" "$DCS_OPEN" >"$WORK_DIR/allow.out" 2>&1 || rc=$?
breaker_after=$(rtu_field breaker_state)
if [[ "$rc" == 0 && "$breaker_after" == "open" ]] && grep -q 'type=46 cot=10' "$WORK_DIR/allow.out"; then
  pass "allowed CA+IOA command and its confirmations pass both ways and actuate" "breaker $breaker_before -> $breaker_after"
else
  fail "allowed CA+IOA command did not complete" "exit $rc; breaker $breaker_before -> $breaker_after; $(tr '\n' ' ' <"$WORK_DIR/allow.out" | head -c 160)"
fi
observe_allowed
run_cmd sbo "$ALLOWED_CA" "$ALLOWED_IOA" "$DCS_CLOSE" >/dev/null 2>&1 || true

assert_not_received "wrong IOA (CA 1 / IOA $FORBIDDEN_IOA) is denied" commands_received \
  run_cmd sbo "$ALLOWED_CA" "$FORBIDDEN_IOA" "$DCS_CLOSE"
assert_not_received "wrong CA (CA $FORBIDDEN_CA / IOA $ALLOWED_IOA) is denied" commands_received \
  run_cmd sbo "$FORBIDDEN_CA" "$ALLOWED_IOA" "$DCS_CLOSE"
assert_not_received "wrong type (type 45 at CA 1 / IOA $ALLOWED_IOA) is denied" commands_received \
  run_cmd single "$ALLOWED_CA" "$ALLOWED_IOA" 1

# 3. Benign + forbidden in one packet: the whole packet is dropped, so the
#    benign GI in it never reaches the RTU either.
gi_before=$(rtu_field gi_requests)
assert_not_received "benign + forbidden APDUs in one packet: forbidden never arrives" commands_received \
  malformer -scenario coalesced -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN"
gi_after=$(rtu_field gi_requests)
if [[ "$gi_after" == "$gi_before" ]]; then
  gate_pass "benign + forbidden APDUs in one packet: the benign GI is dropped with it" "gi_requests $gi_before -> $gi_after"
else
  gate_fail "benign + forbidden APDUs in one packet: the benign GI is dropped with it" "gi_requests $gi_before -> $gi_after"
fi

# 4. A split forbidden APDU never completes at the RTU.
assert_not_received "split forbidden APDU (4-byte segments) never completes at the RTU" commands_received \
  malformer -scenario dc-split -chunk 4 -gap-ms 20 -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN"

# 5. Both endpoint sockets are reset (socket state, not only "RST seen"). The
#    malformer holds its socket open after a forbidden select; the client side
#    must read ECONNRESET, and the RTU must record a closed connection while
#    the client is still holding (only a reset can close it in that window).
closed_before=$(rtu_field connections_closed)
compose exec -T cc /usr/local/bin/malformer -addr "$RTU_IP:$RTU_PORT" -scenario dc-select \
  -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN" -hold 8s >"$WORK_DIR/reset.out" 2>&1 &
RESET_PID=$!
sleep 4
closed_mid=$(rtu_field connections_closed)
wait "$RESET_PID" || true
RESET_SOCKET=$(socket_of "$(tr -d '\r' <"$WORK_DIR/reset.out" | tail -n 1)")
RESET_DETAIL="client_socket=${RESET_SOCKET:-none}; RTU connections_closed $closed_before -> $closed_mid while the client held its socket"
if [[ "$RESET_SOCKET" == reset && -n "$closed_mid" && "$closed_mid" -gt "$closed_before" ]]; then
  ABORTED=1
  gate_pass "both endpoint sockets are reset after a denied command" "$RESET_DETAIL"
else
  ABORTED=0
  gate_fail "both endpoint sockets are reset after a denied command" "$RESET_DETAIL"
fi

# 6. The same client reconnects and completes GI within the 5 s budget (new
#    session + GI complete <= 5 s), with no IEC entry in block_flows.
rc=0
GI_START=$(now_s)
run_cmd gi "$ALLOWED_CA" >"$WORK_DIR/regi.out" 2>&1 || rc=$?
GI_ELAPSED=$(elapsed_s "$GI_START")
if [[ "$ABORTED" -eq 1 && "$rc" == 0 ]] && grep -q 'type=100 cot=10' "$WORK_DIR/regi.out" && within_budget "$GI_ELAPSED" 5.0; then
  gate_pass "the same client reconnects after the abort and completes GI within 5 s" "${GI_ELAPSED}s"
else
  gate_fail "the same client reconnects after the abort and completes GI within 5 s" \
    "aborted=$ABORTED; exit $rc; ${GI_ELAPSED}s (budget 5.0 s); GI termination seen: $(grep -c 'type=100 cot=10' "$WORK_DIR/regi.out" || true)"
fi

BLOCK_FLOWS=$(compose exec -T firewall nft list set inet containd block_flows 2>&1 | tr -d '\r')
if [[ "$BLOCK_FLOWS" == *"set block_flows"* && "$BLOCK_FLOWS" != *"$CC_IP"* ]]; then
  pass "no IEC104 session entry in nft block_flows"
else
  fail "nft block_flows holds the control centre or could not be read" "$(tr '\n' ' ' <<<"$BLOCK_FLOWS" | head -c 200)"
fi

# 7. An unrelated allowed session survives: the long-lived control centre
#    started before the denials keeps its connection and its spontaneous data.
CC_CLOSED=$(cc_count 'CONN closed' cc.log)
CC_SPONT_NOW=$(cc_count 'cot=3 ' cc.log)
SURVIVE_DETAIL="cc closed events=$CC_CLOSED; spontaneous updates $CC_SPONT_START -> $CC_SPONT_NOW"
if [[ "$CC_CLOSED" == 0 && "$CC_SPONT_NOW" -gt "$CC_SPONT_START" ]]; then
  if [[ "$ABORTED" -eq 1 ]]; then
    gate_pass "an unrelated allowed session survives the denials and abort" "$SURVIVE_DETAIL"
  else
    gate_fail "an unrelated allowed session survives the denials and abort" "no abort happened, so survival was not tested; $SURVIVE_DETAIL"
  fi
else
  fail "the long-lived control-centre session lost its connection or telemetry" "$SURVIVE_DETAIL"
fi

# 8. Same-5-tuple reuse and stale retransmits cannot bypass. Reuse: abort a
#    forbidden session from a fixed source port, reconnect from the same port
#    (same 5-tuple, new ISN): a forbidden command must still not arrive, and an
#    allowed GI on that 5-tuple must work.
REUSE_PORT=${IEC104_REUSE_PORT:-40404}
malformer -scenario dc-select -lport "$REUSE_PORT" -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN" -hold 2s >/dev/null
sleep 1
assert_not_received "same-5-tuple reconnect cannot deliver a forbidden command" commands_received \
  malformer -scenario dc-select -lport "$REUSE_PORT" -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN" -hold 2s
sleep 1
gi_before=$(rtu_field gi_requests)
REUSE_GI=$(malformer -scenario gi -lport "$REUSE_PORT" -ca "$ALLOWED_CA" -hold 2s)
gi_after=$(rtu_field gi_requests)
if [[ -n "$gi_after" && "$gi_after" -gt "$gi_before" ]]; then
  pass "an allowed GI on a reused 5-tuple reaches the RTU" "gi_requests $gi_before -> $gi_after"
else
  fail "an allowed GI on a reused 5-tuple did not reach the RTU" "gi_requests $gi_before -> $gi_after; $REUSE_GI"
fi
# Stale retransmit: the malformer opens a raw session (port 40405) that sends a
# forbidden command to IOA 2002, opens a second session from port 40406 (the
# "new handshake"), then injects a later segment of the first session carrying a
# forbidden command to IOA 2003. If that stale segment reaches the RTU, its
# double command handler records ioa=2003 in last_command.
STALE_IOA=$((FORBIDDEN_IOA + 1))
received_before=$(rtu_field commands_received)
STALE_OUT=$(compose exec -T cc /usr/local/bin/malformer -addr "$RTU_IP:$RTU_PORT" \
  -scenario stale-retransmit -lport 40405 -ca "$ALLOWED_CA" -ioa "$FORBIDDEN_IOA" -dcs "$DCS_OPEN" 2>&1 | tr -d '\r' | tail -n 1)
sleep 1
last_cmd=$(rtu_field last_command)
received_after=$(rtu_field commands_received)
STALE_DETAIL="malformer: $STALE_OUT; RTU last_command '$last_cmd'; commands_received $received_before -> $received_after"
if [[ "$STALE_OUT" == *FAILED* ]]; then
  fail "stale retransmit after a new handshake cannot bypass" "raw replay could not run: $STALE_OUT"
elif [[ "$last_cmd" != *"ioa=$STALE_IOA"* ]]; then
  gate_pass "stale retransmit after a new handshake cannot bypass" "$STALE_DETAIL"
else
  gate_fail "stale retransmit after a new handshake cannot bypass" "the stale segment reached the RTU: $STALE_DETAIL"
fi

# 9. Malformed/unknown: reset in enforce, alert (event) and pass in learn.
for scen in bad-length malformed-dcs unsupported-type; do
  since=$(timestamp)
  out=$(malformer -scenario "$scen" -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -hold "$HOLD")
  sock=$(socket_of "$out")
  sleep 1
  if [[ "$sock" == reset ]] && iec_event_since "$since"; then
    gate_pass "enforce: $scen resets the session and raises an IEC104 event" "client_socket=$sock"
  else
    gate_fail "enforce: $scen resets the session and raises an IEC104 event" \
      "client_socket=${sock:-none}; IEC104 malformed/unsupported event: $(iec_event_since "$since" && echo yes || echo no)"
  fi
done

LEARN_POLICY=$(echo "$EU_POLICY" | jq '.dataPlane.dpiMode = "learn" | .firewall.rules |= map(.ics.mode = "learn")')
if apply_config "$LEARN_POLICY" "EU learn policy"; then
  sleep 2
  for scen in bad-length malformed-dcs unsupported-type; do
    since=$(timestamp)
    out=$(malformer -scenario "$scen" -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -hold 2s)
    sock=$(socket_of "$out")
    sleep 1
    if [[ "$sock" != reset ]] && iec_event_since "$since"; then
      gate_pass "learn: $scen raises an IEC104 event and is not reset" "client_socket=$sock"
    else
      gate_fail "learn: $scen raises an IEC104 event and is not reset" \
        "client_socket=${sock:-none}; IEC104 malformed/unsupported event: $(iec_event_since "$since" && echo yes || echo no)"
    fi
  done
  apply_config "$EU_POLICY" "EU enforce policy (restore)" || fail "could not restore the EU enforce policy"
else
  fail "could not apply the EU learn policy"
fi

# 10. Decoder off or capture not NFQUEUE: enforce is refused before save.
#     Queue failure at start: enforcement health reports unhealthy.
reject_check() {
  local name=$1 cfg=$2 code
  # Expected HTTP errors are data here: -f can discard their response body.
  code=$(echo "$cfg" | curl -sS --max-time 10 --connect-timeout 5 -w "%{http_code}" \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    -X POST "${BASE}/config" --data-binary @- -o "$WORK_DIR/reject.json" || true)
  if [[ "$code" == "400" && -s "$WORK_DIR/reject.json" ]]; then
    gate_pass "$name" "HTTP $code: $(head -c 160 "$WORK_DIR/reject.json")"
  else
    gate_fail "$name" "HTTP ${code:-none}: expected 400 with a validation error body"
  fi
}
reject_check "IEC enforce with the iec104 decoder off is refused before save" \
  "$(echo "$EU_POLICY" | jq '.dataPlane.dpiIcsProtocols.iec104 = false')"
reject_check "IEC enforce without NFQUEUE capture (nfqueueGroup 0) is refused before save" \
  "$(echo "$EU_POLICY" | jq 'del(.dataPlane.nfqueueGroup)')"
apply_config "$EU_POLICY" "EU enforce policy (restore after rejection checks)" || fail "could not restore the EU enforce policy"

# Capture policy-reset recoveries before the deliberately held queue starts.
# While the holder owns NFQUEUE, the expected fail-closed outage can delay a
# reconnect beyond the 5 s budget; the post-check liveness check below proves
# that telemetry resumes once the queue is restored.
PRE_QUEUE_SETTLED=0
if wait_cc_settled; then PRE_QUEUE_SETTLED=1; else log "control centre not settled before queue-bind check"; fi
compose exec -T cc cat /tmp/cc.log >"$RESULTS_DIR/cc-pre-queue.log" 2>/dev/null || true
PRE_QUEUE_GAPS=$(awk '
  / CONN closed/ { if (open) print -1; open = 1; t0 = substr($1, 3) + 0; next }
  / RCVD type=100 cot=10 / { if (open) { print substr($1, 3) - t0; open = 0 } }
  END { if (open) print -1 }
' "$RESULTS_DIR/cc-pre-queue.log")
PRE_QUEUE_RESETS=$(grep -c . <<<"$PRE_QUEUE_GAPS" || true)
PRE_QUEUE_BAD=$(awk '$1 < 0 || $1 > 5000' <<<"$PRE_QUEUE_GAPS" | grep -c . || true)

# Queue bind failure at start: a second binder holds NFQUEUE 101
# before the engine binds it, so the engine's bind fails. The config is kept,
# enforce envelopes fail closed, and health reports unhealthy with a queue-bind
# reason. Drop the engine's binding first (L4 baseline), take the queue, then
# re-apply the enforce policy so the engine binds into a held queue.
if compose cp "$WORK_DIR/queueholder" firewall:/usr/local/bin/queueholder >/dev/null 2>&1; then
  apply_config "$BASELINE" "L4 baseline (free NFQUEUE 101)" || fail "could not drop the enforce policy before the queue-bind check"
  # apply_config waits for the old NFQUEUE run to stop. Hold the queue
  # immediately so the control centre cannot reconnect under this temporary
  # L4-only policy before the IEC envelope is restored.
  compose exec -d firewall sh -c "/usr/local/bin/queueholder -queue 101 >/tmp/queueholder.log 2>&1" >/dev/null 2>&1 || true
  QH_READY=0
  for _ in $(seq 1 20); do
    if compose exec -T firewall grep -q 'bound queue 101' /tmp/queueholder.log 2>/dev/null; then QH_READY=1; break; fi
    sleep 0.5
  done
  if [[ "$QH_READY" -eq 1 ]]; then
    apply_config "$EU_POLICY" "EU enforce policy (into a held queue)" || log "engine apply reported an error with the queue held (expected)"
    sleep 2
    QH_HEALTH=$(health_json | jq -c '.iec104Enforcement // "no iec104Enforcement object"')
    # Fail closed: a normally allowed command must not reach the RTU while the
    # engine cannot bind its queue.
    received_before=$(rtu_field commands_received)
    run_cmd sbo "$ALLOWED_CA" "$ALLOWED_IOA" "$DCS_OPEN" >/dev/null 2>&1 || true
    received_after=$(rtu_field commands_received)
    if health_json | jq -e '.iec104Enforcement.active == true and .iec104Enforcement.healthy == false
        and (.iec104Enforcement.reason | ascii_downcase | test("queue|bind"))' >/dev/null 2>&1 &&
      [[ "$received_after" == "$received_before" ]]; then
      gate_pass "queue bind failure at start keeps the config, fails closed and reports unhealthy" \
        "health $QH_HEALTH; commands_received $received_before -> $received_after (fail closed)"
    else
      gate_fail "queue bind failure at start keeps the config, fails closed and reports unhealthy" \
        "health $QH_HEALTH; commands_received $received_before -> $received_after"
    fi
  else
    fail "queue bind failure at start keeps the config, fails closed and reports unhealthy" \
      "could not bind the holder on NFQUEUE 101: $(compose exec -T firewall cat /tmp/queueholder.log 2>&1 | tr '\n' ' ' | head -c 160)"
  fi
  compose exec -T firewall sh -c 'pkill -f "queueholder -queue 101"' >/dev/null 2>&1 || true
  apply_config "$EU_POLICY" "EU enforce policy (restore after queue-bind check)" || fail "could not restore the EU enforce policy"
else
  fail "queue bind failure at start keeps the config, fails closed and reports unhealthy" \
    "could not install the queueholder in the firewall container"
fi

POST_QUEUE_SETTLED=0
if wait_cc_settled; then POST_QUEUE_SETTLED=1; else log "control centre not settled after queue recovery"; fi
compose exec -T cc cat /tmp/cc.log >"$RESULTS_DIR/cc.log" 2>/dev/null || true
RECOVERY="pre-queue resets=$PRE_QUEUE_RESETS; close->GI ms: $(tr '\n' ' ' <<<"$PRE_QUEUE_GAPS"); live telemetry after queue recovery=$POST_QUEUE_SETTLED"
if [[ "$PRE_QUEUE_SETTLED" == 1 && "$PRE_QUEUE_BAD" == 0 && "$POST_QUEUE_SETTLED" == 1 ]]; then
  pass "the long-lived control centre recovers from policy resets within 5 s and resumes telemetry after queue recovery" "$RECOVERY"
else
  fail "the long-lived control centre missed policy-reset recovery or post-queue liveness" "$RECOVERY"
fi

if ((FRESHNESS_SECONDS < 600)); then
  not_implemented "spontaneous telemetry stays fresh for more than 10 minutes" \
    "IEC104_FRESHNESS_SECONDS=$FRESHNESS_SECONDS is shorter than the required 10-minute telemetry window; rerun with the default"
else
  log "Watching control-centre telemetry freshness for ${FRESHNESS_SECONDS}s..."
  stale=""
  closed_start=$(cc_count 'CONN closed' cc.log)
  last=$(cc_count 'cot=3 ' cc.log)
  elapsed=0
  while ((elapsed < FRESHNESS_SECONDS)); do
    sleep 30
    elapsed=$((elapsed + 30))
    now=$(cc_count 'cot=3 ' cc.log)
    if [[ "$now" -le "$last" ]]; then
      stale+="no spontaneous update in the 30 s before t=${elapsed}s; "
    fi
    last=$now
  done
  closed_end=$(cc_count 'CONN closed' cc.log)
  compose exec -T cc cat /tmp/cc.log >"$RESULTS_DIR/cc.log" 2>/dev/null || true
  if [[ -z "$stale" && "$closed_end" == "$closed_start" ]]; then
    pass "spontaneous telemetry stays fresh for ${FRESHNESS_SECONDS}s on the long-lived session" \
      "$last updates; no session drop in the window (closes before it: $closed_start)"
  else
    fail "telemetry went stale or the session dropped" "${stale}closes during the window: $closed_start -> $closed_end"
  fi
fi

observe_final

# ---- summary ----------------------------------------------------------------

log "---------------------------------------------------------------"
log "IEC104 harness: $PASS_COUNT passed, $FAIL_COUNT failed, $GATE_FAIL_COUNT gate-failed, $NOT_IMPL_COUNT not implemented"
log "Full results: $RESULTS_FILE"
if [[ "$GATE_FAIL_COUNT" -gt 0 ]]; then
  log "Failed IEC104 enforcement assertions:"
  jq -r '.assertions[] | select(.status=="GATE-FAIL") | "  - " + .name' "$RESULTS_FILE"
fi
if [[ "$NOT_IMPL_COUNT" -gt 0 ]]; then
  log "Hard assertions the harness does not run yet:"
  jq -r '.assertions[] | select(.status=="NOT-IMPLEMENTED") | "  - " + .name + " (" + .detail + ")"' "$RESULTS_FILE"
fi
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  log "Non-gated failures (harness or baseline defects):"
  jq -r '.assertions[] | select(.status=="FAIL") | "  - " + .name + " (" + .detail + ")"' "$RESULTS_FILE"
  exit 1
fi
if [[ "$GATE_FAIL_COUNT" -gt 0 || "$NOT_IMPL_COUNT" -gt 0 ]]; then
  log "ACCEPTANCE NOT MET: baseline passed; gate or unimplemented assertions remain."
  exit 3
fi
log "ACCEPTANCE MET: every IEC104 traffic, enforcement and telemetry assertion passed."
exit 0
