#!/usr/bin/env bash
set -euo pipefail

# Smoke-test live ICS DPI with deterministic Modbus/TCP and DNP3 traffic
# to check protocol enforcement. Requirements: docker compose, jq, curl.
#
# Both capture modes assert: Modbus FC 3 reads pass, including a read split
# across two TCP segments and two reads coalesced into one; DNP3 FC 1 reads
# pass, the outstation's response and unsolicited data reach the master, and
# DPI decodes the read; a Modbus write matches its deny rule; the candidate
# preview, the applied engine status and /health report the ICS rules'
# coverage.
#
# SMOKE_DPI_CAPTURE=afpacket (default) observes copies of the traffic on the
# interfaces, which cannot stop a command. It asserts that management
# refuses the ICS rules in enforce mode without an inline path, then runs
# the traffic with the rules in learn mode: they report monitoring, denied
# writes reach the server, and nothing is blocked.
#
# SMOKE_DPI_CAPTURE=nfqueue steers ICS traffic through NFQUEUE
# (nfqueueGroup SMOKE_NFQUEUE_GROUP, default 101) in enforce mode. The rules
# report enforcing; a deny resets only that TCP session and installs no
# dynamic block. It also asserts
# first-actuation prevention, from server state: the
# first Modbus FC 6 write on a fresh connection and after a read on a
# persistent connection, the first Modbus FC 8, and the first complete DNP3
# FC 5 and FC 6 never reach the server. Each probe uses its own client
# address to keep receiver-side evidence independent.
# Fixture and isolation setup: test/data-smoke/README.md.

COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.smoke.yml}
# Compose project and harness subnets. When another smoke stack owns the
# default networks, set a unique project, list an override file that moves
# the subnets in COMPOSE_FILE, and set the matching prefixes here
# (see test/data-smoke/README.md).
SMOKE_PROJECT=${SMOKE_PROJECT:-deploy}
WAN_NET=${SMOKE_WAN_NET:-172.30.0}
LAN_NET=${SMOKE_LAN_NET:-172.31.0}
BASE=${BASE:-http://localhost:18080/api/v1}
TOKEN=${TOKEN:-devtoken}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10 --connect-timeout 5"
SMOKE_SKIP_UP=${SMOKE_SKIP_UP:-0}
SMOKE_BUILD=${SMOKE_BUILD:-1}
SMOKE_DPI_CAPTURE=${SMOKE_DPI_CAPTURE:-afpacket}
NFQUEUE_GROUP=${SMOKE_NFQUEUE_GROUP:-101}
TESTS_PASSED=0
TESTS_EXPECTED=22
FAILURES=()
case "$SMOKE_DPI_CAPTURE" in
  afpacket) ;;
  nfqueue) TESTS_EXPECTED=28 ;;
  *)
    echo "SMOKE_DPI_CAPTURE must be afpacket or nfqueue, got: $SMOKE_DPI_CAPTURE" >&2
    exit 2
    ;;
esac

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() { echo "[$(timestamp)] $*"; }
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); log "PASS: $*"; }
# check_fail records a failed assertion and lets the run continue, so one
# run reports every assertion.
check_fail() { FAILURES+=("$*"); log "FAIL: $*"; }

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# shellcheck source=scripts/smoke-engine-api.sh
source "$(dirname "${BASH_SOURCE[0]}")/smoke-engine-api.sh"

# COMPOSE_FILE is a colon-separated list, as in docker compose itself, so an
# override file can follow the base harness file.
compose() {
  local files=() args=() file
  IFS=: read -r -a files <<<"$COMPOSE_FILE"
  for file in "${files[@]}"; do
    args+=(-f "$file")
  done
  docker compose --project-name "$SMOKE_PROJECT" "${args[@]}" "$@"
}

ensure_tools() {
  for bin in docker jq curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "missing required tool: $bin" >&2
      exit 1
    fi
  done
}

wait_for_http() {
  local url=$1
  for _ in $(seq 1 30); do
    if $CURL "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for $url" >&2
  return 1
}

discover_iface() {
  local state=$1 ip=$2
  echo "$state" | jq -r --arg ip "$ip" '
    map(select(.addrs[]? | contains($ip))) | .[0].name // empty
  '
}

wait_for_jq() {
  local url=$1 filter=$2
  for _ in $(seq 1 20); do
    if $CURL -H "$AUTH_HEADER" "$url" | jq -e "$filter" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

apply_snapshot() {
  local ruleset_file snap ruleset_head code tmp_apply_resp
  ruleset_file=$(mktemp)
  if ! $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" -o "$ruleset_file"; then
    log "failed to fetch ruleset preview"
    rm -f "$ruleset_file"
    exit 1
  fi
  snap=$(jq -c '.snapshot' "$ruleset_file")
  ruleset_head=$(jq -r '.ruleset' "$ruleset_file" | head -n 20)
  log "Compiled ruleset (first 20 lines):"
  echo "$ruleset_head"
  rm -f "$ruleset_file"

  log "Applying dataplane configuration to engine..."
  code=$(engine_post engine /internal/config "$WORK_DIR/smoke-dpi-engine-config.out" <<<"$DATAPLANE_CFG")
  if [[ "$code" != "200" ]]; then
    log "engine config failed (HTTP $code): $(cat "$WORK_DIR/smoke-dpi-engine-config.out")"
    exit 1
  fi

  log "Applying snapshot to engine..."
  tmp_apply_resp=$(mktemp)
  code=$(engine_post engine /internal/apply_rules "$tmp_apply_resp" <<<"$snap")
  if [[ "$code" != "200" ]]; then
    log "engine apply_rules failed (HTTP $code): $(cat "$tmp_apply_resp")"
    rm -f "$tmp_apply_resp"
    exit 1
  fi
  rm -f "$tmp_apply_resp"
}

server_state() {
  compose exec -T modbus_server cat /tmp/modbus-state.json
}

# server_fc6_requests counts every FC 6 request the server decoded. It does
# not filter by peer: with NAT enabled in the stored config the server sees
# the engine address, not the client.
server_fc6_requests() {
  compose exec -T modbus_server sh -c 'cat /tmp/modbus-requests.jsonl 2>/dev/null || true' |
    jq -s '[.[] | select(.function_code == 6)] | length'
}

# probe_first_write sends a write that the deny rule matches from a source
# address with no earlier write, on a fresh connection (mode write) or after
# an allowed read on the same connection (mode readwrite), and asserts that
# the server never saw it and its register did not change.
probe_first_write() {
  local mode=$1 source=$2 label state_before state_after register_before register_after
  local writes_before writes_after requests_before requests_after value status=0 want_status evidence
  # Exit 3 means the TCP connection was established and the write was sent
  # but got no response, so an L4 block cannot pass for an inline drop.
  want_status=3
  if [[ "$mode" == "readwrite" ]]; then
    label="first write after a read on a persistent connection ($source)"
  else
    label="first write on a fresh connection ($source)"
  fi
  state_before=$(server_state)
  register_before=$(jq -er '.registers[1]' <<<"$state_before")
  writes_before=$(jq -er '.writes' <<<"$state_before")
  requests_before=$(server_fc6_requests)
  value=$(((register_before + 4097) % 65536))
  compose exec -T ot_client python /opt/modbus/client.py "$mode" "$MODBUS_DST" 502 \
    --source "$source" --value "$value" >"$WORK_DIR/probe-$mode.out" 2>"$WORK_DIR/probe-$mode.err" || status=$?
  state_after=$(server_state)
  register_after=$(jq -er '.registers[1]' <<<"$state_after")
  writes_after=$(jq -er '.writes' <<<"$state_after")
  requests_after=$(server_fc6_requests)
  if [[ "$mode" == "readwrite" ]]; then
    if grep -q '^READ_OK' "$WORK_DIR/probe-$mode.out"; then
      pass "Modbus read allowed on the persistent connection before the write ($source)"
    else
      check_fail "Modbus read on the persistent connection failed (exit $status): $(tr -d '\r' <"$WORK_DIR/probe-$mode.err")"
    fi
  fi
  evidence="client exit $status (want $want_status): $(tr -d '\r' <"$WORK_DIR/probe-$mode.out" | tr '\n' ' ')$(tr -d '\r' <"$WORK_DIR/probe-$mode.err" | tr '\n' ' ');"
  evidence+=" register 1 $register_before -> $register_after (written value $value);"
  evidence+=" server writes applied $writes_before -> $writes_after; FC 6 requests seen $requests_before -> $requests_after"
  if [[ "$status" -eq "$want_status" && "$register_after" == "$register_before" &&
    "$writes_after" == "$writes_before" && "$requests_after" == "$requests_before" ]]; then
    pass "Inline DROP: $label never reached the server ($evidence)"
  else
    check_fail "Inline DROP: $label reached the server or was not dropped ($evidence)"
  fi
}

# server_fc_requests FC: every request with that function code the Modbus
# server decoded.
server_fc_requests() {
  compose exec -T modbus_server sh -c 'cat /tmp/modbus-requests.jsonl 2>/dev/null || true' |
    jq -s --argjson fc "$1" '[.[] | select(.function_code == $fc)] | length'
}

# probe_modbus_diag sends a Modbus FC 8 (denied) from a fresh source and
# asserts the server never decoded it.
probe_modbus_diag() {
  local source=$1 status=0 before after evidence
  before=$(server_fc_requests 8)
  compose exec -T ot_client python /opt/modbus/client.py diag "$MODBUS_DST" 502 --source "$source" \
    >"$WORK_DIR/diag.out" 2>"$WORK_DIR/diag.err" || status=$?
  after=$(server_fc_requests 8)
  evidence="client exit $status (want 3); FC 8 requests seen $before -> $after; $(cat "$WORK_DIR/diag.out" "$WORK_DIR/diag.err" | tr -d '\r' | tr '\n' ' ')"
  if [[ "$status" -eq 3 && "$after" == "$before" ]]; then
    pass "Inline DROP: first Modbus FC 8 never reached the server ($source; $evidence)"
  else
    check_fail "Inline DROP: first Modbus FC 8 reached the server or was not dropped ($source; $evidence)"
  fi
}

dnp3_state() {
  compose exec -T modbus_server cat /tmp/dnp3-state.json
}

dnp3_fc_requests() {
  compose exec -T modbus_server sh -c 'cat /tmp/dnp3-requests.jsonl 2>/dev/null || true' |
    jq -s --argjson fc "$1" '[.[] | select(.function_code == $fc)] | length'
}

# probe_dnp3_control MODE FC SOURCE WANT: a denied DNP3 control (operate =
# FC 5, operate-nr = FC 6) as the first complete message from SOURCE must
# not reach the outstation: no request with that FC logged and no operation
# applied. WANT is the client exit code when the request is dropped.
probe_dnp3_control() {
  local mode=$1 fc=$2 source=$3 want=$4 status=0 ops_before ops_after req_before req_after evidence
  ops_before=$(dnp3_state | jq -er '.operations')
  req_before=$(dnp3_fc_requests "$fc")
  compose exec -T ot_client python /tmp/dnp3.py "$mode" "$MODBUS_DST" --source "$source" \
    >"$WORK_DIR/dnp3-$mode.out" 2>"$WORK_DIR/dnp3-$mode.err" || status=$?
  sleep 1
  ops_after=$(dnp3_state | jq -er '.operations')
  req_after=$(dnp3_fc_requests "$fc")
  evidence="client exit $status (want $want); FC $fc requests seen $req_before -> $req_after; operations $ops_before -> $ops_after"
  if [[ "$status" -eq "$want" && "$req_after" == "$req_before" && "$ops_after" == "$ops_before" ]]; then
    pass "Inline DROP: first complete DNP3 FC $fc never reached the outstation ($source; $evidence)"
  else
    check_fail "Inline DROP: first complete DNP3 FC $fc reached the outstation or was not dropped ($source; $evidence)"
  fi
}

# assert_enforce_refused CFG: without an inline path, saving the ICS rules in
# enforce mode must fail validation with an error that names a rule and the
# fix.
assert_enforce_refused() {
  local code body
  body="$WORK_DIR/enforce-refused.json"
  code=$(curl -s --max-time 10 --connect-timeout 5 -w "%{http_code}" -o "$body" -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- <<<"$1" || true)
  if [[ "$code" == "400" ]] && jq -e '.error | contains("rule smoke-") and contains("dataplane.nfqueueGroup")' "$body" >/dev/null 2>&1; then
    pass "Enforce without NFQUEUE refused: $(jq -r '.error' "$body")"
  else
    check_fail "Enforce without NFQUEUE was not refused (HTTP $code): $(head -c 300 "$body")"
  fi
}

# assert_ics_coverage STATE: every ICS rule reports STATE in the candidate
# preview and in the applied engine status, and /health summarizes it. The
# NFQUEUE bind is asynchronous, so the applied state is awaited.
assert_ics_coverage() {
  local state=$1 filter
  # shellcheck disable=SC2016 # $s is a jq variable
  filter='(.icsCoverage | length) == 5 and all(.icsCoverage[]; .state == $s)
    and (.engineStatus.icsCoverage | length) == 5 and all(.engineStatus.icsCoverage[]; .state == $s)'
  for _ in $(seq 1 20); do
    if $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" | jq -e --arg s "$state" "$filter" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" | jq -e --arg s "$state" "$filter" >/dev/null 2>&1; then
    pass "Candidate and applied ICS coverage: every rule $state"
  else
    check_fail "ICS coverage is not $state: $($CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" | jq -c '{icsCoverage, applied: .engineStatus.icsCoverage}' | head -c 600)"
  fi
  if $CURL "${BASE}/health" | jq -e --arg s "$state" '.icsEnforcement.state == $s' >/dev/null 2>&1; then
    pass "Health icsEnforcement reports $state"
  else
    check_fail "Health icsEnforcement is not $state: $($CURL "${BASE}/health" | jq -c '.icsEnforcement')"
  fi
}

# assert_no_dynamic_block SRC PORT: DPI never installs a block.
assert_no_dynamic_block() {
  local src=$1 port=$2 set
  set=$(compose exec -T engine nft list set inet containd block_flows 2>&1 | tr -d '\r')
  if grep -Fq "$src . $MODBUS_DST . tcp . $port" <<<"$set"; then
    check_fail "DPI installed a dynamic block for $src -> $MODBUS_DST:$port"
  else
    pass "DPI installed no dynamic block for $src -> $MODBUS_DST:$port"
  fi
}

# Keep one allowed connection open while another connection from the same
# address is denied. Capture the server-directed reset independently; the
# client must receive ECONNRESET (a timeout is not success), then reconnect
# from both its old port and a new port without waiting for a block TTL.
probe_reset_isolation() {
  local capture_pid status=0 denied_port
  compose exec -T modbus_server python -u - >"$WORK_DIR/reset-server.out" 2>"$WORK_DIR/reset-server.err" <<'PY' &
import socket
import struct
import time

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(0.2)
print("READY", flush=True)
end = time.monotonic() + 8
while time.monotonic() < end:
    try:
        b = s.recv(65535)
    except socket.timeout:
        continue
    ihl = (b[0] & 15) * 4
    if len(b) < ihl + 20 or not b[ihl + 13] & 4:
        continue
    sport, dport = struct.unpack_from("!HH", b, ihl)
    if dport == 502:
        print("RST", sport, flush=True)
PY
  capture_pid=$!
  for _ in $(seq 1 30); do
    if grep -q '^READY$' "$WORK_DIR/reset-server.out"; then
      break
    fi
    sleep 0.1
  done
  if ! grep -q '^READY$' "$WORK_DIR/reset-server.out"; then
    wait "$capture_pid" || true
    check_fail "Server reset capture did not start"
    return
  fi
  compose exec -T ot_client python - "$MODBUS_DST" "$MODBUS_SRC" \
    >"$WORK_DIR/reset-isolation.out" 2>"$WORK_DIR/reset-isolation.err" <<'PY' || status=$?
import errno
import socket
import sys

sys.path.insert(0, "/opt/modbus")
from client import exchange

host, source = sys.argv[1:]

def connect(port=0):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(3)
    s.bind((source, port))
    s.connect((host, 502))
    return s

with connect() as other:
    assert exchange(other, "read", 1, 0).startswith("READ_OK")
    with connect() as denied:
        port = denied.getsockname()[1]
        print("DENIED_PORT", port, flush=True)
        try:
            exchange(denied, "write", 2, 0x1234)
        except OSError as exc:
            assert exc.errno == errno.ECONNRESET, repr(exc)
        else:
            raise AssertionError("denied write was answered")
    assert exchange(other, "read", 3, 0).startswith("READ_OK")
with connect(port) as same_port:
    assert exchange(same_port, "read", 4, 0).startswith("READ_OK")
with connect() as fresh:
    assert exchange(fresh, "read", 5, 0).startswith("READ_OK")
PY
  if ! wait "$capture_pid"; then
    status=1
  fi
  denied_port=$(awk '$1 == "DENIED_PORT" {print $2}' "$WORK_DIR/reset-isolation.out")
  if [[ "$status" -eq 0 && -n "$denied_port" ]] &&
    grep -qx "RST $denied_port" "$WORK_DIR/reset-server.out"; then
    pass "Both peers reset; immediate same/new-port reconnect and concurrent session survive"
  else
    check_fail "Reset isolation failed: $(cat "$WORK_DIR/reset-isolation.err" "$WORK_DIR/reset-server.err")"
  fi
}

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  # Recreate the containers: a stack left by an earlier run still holds its
  # 10-minute dynamic blocks and retrying clients, which then block this run.
  log "Recreating smoke harness ($COMPOSE_FILE)..."
  if [[ "$SMOKE_BUILD" == "1" ]]; then
    compose up -d --build --force-recreate
  else
    compose up -d --force-recreate
  fi
fi

log "Waiting for management plane..."
wait_for_http "${BASE}/health"

log "Fetching interface state..."
STATE=""
for _ in $(seq 1 10); do
  STATE=$($CURL -H "$AUTH_HEADER" "${BASE}/interfaces/state" || true)
  if [[ -n "$STATE" && "$STATE" != "[]" ]]; then
    break
  fi
  sleep 2
done
WAN_DEV=$(discover_iface "$STATE" "${WAN_NET}.2")
LAN_DEV=$(discover_iface "$STATE" "${LAN_NET}.2")
if [[ -z "$WAN_DEV" || -z "$LAN_DEV" ]]; then
  echo "failed to discover wan/lan devices from interface state:" >&2
  echo "$STATE" >&2
  exit 1
fi
log "Detected wan=${WAN_DEV}, lan=${LAN_DEV}"

log "Fetching current config..."
CFG=$($CURL -H "$AUTH_HEADER" "${BASE}/config")

# The nfqueue variant uses extra client addresses (.6-.10) so each
# first-actuation probe has no dynamic block (src, dst, dport) from another.
PROBE_HOSTS=(6 7 8 9 10)
if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  CLIENT_SOURCES=$(jq -cn --arg net "$LAN_NET" '[$net + ".5/32", $net + ".6/32", $net + ".7/32", $net + ".8/32", $net + ".9/32", $net + ".10/32"]')
else
  CLIENT_SOURCES=$(jq -cn --arg net "$LAN_NET" '[$net + ".5/32"]')
fi

UPDATED_CFG=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" \
  --argjson clients "$CLIENT_SOURCES" --arg server "${WAN_NET}.4/32" \
  --arg capture "$SMOKE_DPI_CAPTURE" --argjson queue "$NFQUEUE_GROUP" '
  # Own the test policy, including zones and NAT. A previously imported
  # policy may have no lan zone or may contain conflicting IEC envelopes.
  {schema_version:.schema_version, system:.system,
   zones:[{name:"wan"},{name:"lan"}],
   interfaces:[{name:"wan",device:$wan,zone:"wan"},
               {name:"lan1",device:$lan,zone:"lan"}],
   dataPlane:{}, ids:{enabled:true},
   firewall:{defaultAction:"DENY",rules:[],nat:{enabled:true,egressZone:"wan",sourceZones:["lan"]}}}
  | .system.mgmt.httpListenAddr=":18080"
  | .system.mgmt.listenAddr=":18080"
  | if $capture == "nfqueue"
    then .dataPlane.nfqueueGroup = $queue | del(.dataPlane.captureInterfaces)
    else .dataPlane.captureInterfaces = [$wan, $lan] | del(.dataPlane.nfqueueGroup)
    end
  | .dataPlane.enforcement = true
  | .dataPlane.enforceTable = "containd"
  | .dataPlane.dpiEnabled = true
  | .dataPlane.dpiMode = "enforce"
  | .dataPlane.dpiMock = false
  | .dataPlane.dpiIcsProtocols = ((.dataPlane.dpiIcsProtocols // {}) + {"modbus": true, "dnp3": true})
  | .firewall.rules = [
        {
          id:"smoke-modbus-read",
          description:"Smoke harness allow Modbus reads",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:$clients,
          destinations:[$server],
          protocols:[{"name":"tcp","port":"502"}],
          ics:{
            protocol:"modbus",
            functionCode:[3],
            readOnly:true
          },
          action:"ALLOW",
          log:true
        },
        {
          id:"smoke-modbus-write-deny",
          description:"Smoke harness deny Modbus writes",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:$clients,
          destinations:[$server],
          protocols:[{"name":"tcp","port":"502"}],
          ics:{
            protocol:"modbus",
            functionCode:[6],
            writeOnly:true
          },
          action:"DENY",
          log:true
        },
        {
          id:"smoke-modbus-diag-deny",
          description:"Smoke harness deny Modbus FC 8 diagnostics",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:$clients,
          destinations:[$server],
          protocols:[{"name":"tcp","port":"502"}],
          ics:{protocol:"modbus", functionCode:[8]},
          action:"DENY",
          log:true
        },
        {
          id:"smoke-dnp3-read",
          description:"Smoke harness allow DNP3 reads",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:$clients,
          destinations:[$server],
          protocols:[{"name":"tcp","port":"20000"}],
          ics:{protocol:"dnp3", functionCode:[1]},
          action:"ALLOW",
          log:true
        },
        {
          id:"smoke-dnp3-control-deny",
          description:"Smoke harness deny DNP3 direct operate",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:$clients,
          destinations:[$server],
          protocols:[{"name":"tcp","port":"20000"}],
          ics:{protocol:"dnp3", functionCode:[5, 6]},
          action:"DENY",
          log:true
        }
      ]
')

# AF_PACKET has no inline path: enforce is refused, so the traffic runs in
# learn mode.
if [[ "$SMOKE_DPI_CAPTURE" == "afpacket" ]]; then
  log "Checking that enforce without NFQUEUE is refused..."
  assert_enforce_refused "$UPDATED_CFG"
  UPDATED_CFG=$(jq '.dataPlane.dpiMode = "learn"' <<<"$UPDATED_CFG")
  COVERAGE_STATE=monitoring
else
  COVERAGE_STATE=enforcing
fi

DATAPLANE_CFG=$(echo "$UPDATED_CFG" | jq '.dataPlane')

tmp_cfg_resp=$(mktemp)
tmp_cfg_err=$(mktemp)
code=$(echo "$UPDATED_CFG" | $CURL -w "%{http_code}" -H "$AUTH_HEADER" -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- -o "$tmp_cfg_resp" 2>"$tmp_cfg_err" || true)
if [[ "$code" != "200" ]]; then
  log "config save failed (HTTP $code): body=$(cat "$tmp_cfg_resp"), err=$(cat "$tmp_cfg_err")"
  rm -f "$tmp_cfg_resp" "$tmp_cfg_err"
  exit 1
fi
rm -f "$tmp_cfg_resp" "$tmp_cfg_err"

apply_snapshot
assert_ics_coverage "$COVERAGE_STATE"

START_TS=$(timestamp)
export START_TS
export MODBUS_SRC="${LAN_NET}.5"
export MODBUS_DST="${WAN_NET}.4"

modbus_event_filter=$(cat <<'EOF'
any(.[]; .proto == "modbus" and .srcIp == env.MODBUS_SRC and .dstIp == env.MODBUS_DST and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.START_TS | fromdateiso8601)))
EOF
)

modbus_deny_filter=$(cat <<'EOF'
any(.[]; .kind == "firewall.rule.hit" and .attributes.ruleId == "smoke-modbus-write-deny" and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.START_TS | fromdateiso8601)))
EOF
)

modbus_inventory_filter=$(cat <<'EOF'
any(.[]; .protocol == "modbus" and ((.lastSeen | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.START_TS | fromdateiso8601)) and (.ip == env.MODBUS_SRC or .ip == env.MODBUS_DST))
EOF
)

log "Programming OT client and Modbus server routes through engine..."
{
  set +e
  compose exec -T ot_client ip route flush table main
  compose exec -T modbus_server ip route flush table main
  compose exec -T ot_client ip route add "${LAN_NET}.0/24" dev eth0 scope link src "${LAN_NET}.5"
  compose exec -T modbus_server ip route add "${WAN_NET}.0/24" dev eth0 scope link src "${WAN_NET}.4"
  compose exec -T ot_client ip route add "${WAN_NET}.0/24" via "${LAN_NET}.2" dev eth0
  compose exec -T modbus_server ip route add "${LAN_NET}.0/24" via "${WAN_NET}.2" dev eth0
  compose exec -T ot_client ip route add default via "${LAN_NET}.2" dev eth0
  compose exec -T modbus_server ip route add default via "${WAN_NET}.2" dev eth0
  if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
    for host in "${PROBE_HOSTS[@]}"; do
      compose exec -T ot_client ip addr add "${LAN_NET}.${host}/24" dev eth0
    done
  fi
  set -e
} >"$WORK_DIR/route-setup-dpi.log" 2>&1 || true
sed 's/^/  /' "$WORK_DIR/route-setup-dpi.log"

OT_ROUTE=$(compose exec -T ot_client ip route get "${WAN_NET}.4" | tr -d '\r')
echo "$OT_ROUTE" | grep -q "via ${LAN_NET}.2" || { log "ot_client route not via engine: $OT_ROUTE"; exit 1; }
pass "OT client route uses engine for Modbus traffic"

log "Testing Modbus read allow..."
READ_STATUS=0
compose exec -T ot_client python /opt/modbus/client.py read "$MODBUS_DST" 502 >"$WORK_DIR/modbus-read.out" 2>"$WORK_DIR/modbus-read.err" || READ_STATUS=$?
if [[ $READ_STATUS -ne 0 ]]; then
  log "Modbus read failed (exit $READ_STATUS):"
  cat "$WORK_DIR/modbus-read.err"
  exit 1
fi
pass "Modbus read allowed ($(tr -d '\r' <"$WORK_DIR/modbus-read.out"))"

if ! wait_for_jq "${BASE}/events?limit=100" "$modbus_event_filter"; then
  log "expected modbus event not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=20" | jq '.'
  exit 1
fi
pass "Modbus event recorded in telemetry"

log "Testing a Modbus read split across two TCP segments..."
if compose exec -T ot_client python /opt/modbus/client.py read-split "$MODBUS_DST" 502 >"$WORK_DIR/split.out" 2>"$WORK_DIR/split.err" &&
  grep -q '^READ_OK' "$WORK_DIR/split.out"; then
  pass "Split Modbus read passes ($(tr -d '\r' <"$WORK_DIR/split.out"))"
else
  check_fail "Split Modbus read failed: $(tr -d '\r' <"$WORK_DIR/split.err")"
fi

log "Testing two Modbus reads coalesced into one TCP segment..."
if compose exec -T ot_client python /opt/modbus/client.py read-coalesced "$MODBUS_DST" 502 >"$WORK_DIR/coalesced.out" 2>"$WORK_DIR/coalesced.err" &&
  [[ "$(grep -c '^READ_OK' "$WORK_DIR/coalesced.out")" == 2 ]]; then
  pass "Coalesced Modbus reads pass (two responses)"
else
  check_fail "Coalesced Modbus reads failed: $(cat "$WORK_DIR/coalesced.out" "$WORK_DIR/coalesced.err" | tr -d '\r' | tr '\n' ' ')"
fi

log "Starting the DNP3 outstation (port 20000) and testing a DNP3 read..."
compose cp test/data-smoke/dnp3/dnp3.py modbus_server:/tmp/dnp3.py >/dev/null
compose cp test/data-smoke/dnp3/dnp3.py ot_client:/tmp/dnp3.py >/dev/null
if ! compose exec -T modbus_server sh -c 'pgrep -f "dnp3.py server" >/dev/null'; then
  compose exec -d modbus_server python /tmp/dnp3.py server
fi
for _ in $(seq 1 20); do
  compose exec -T modbus_server test -s /tmp/dnp3-state.json && break
  sleep 0.5
done
DNP3_STATUS=0
compose exec -T ot_client python /tmp/dnp3.py read "$MODBUS_DST" >"$WORK_DIR/dnp3-read.out" 2>"$WORK_DIR/dnp3-read.err" || DNP3_STATUS=$?
if grep -q '^READ_OK' "$WORK_DIR/dnp3-read.out"; then
  pass "DNP3 FC 1 read passes and its FC 129 response reaches the master"
else
  check_fail "DNP3 FC 1 read failed (exit $DNP3_STATUS): $(tr -d '\r' <"$WORK_DIR/dnp3-read.err")"
fi
if grep -q '^UNSOLICITED_OK' "$WORK_DIR/dnp3-read.out"; then
  pass "DNP3 unsolicited response (FC 130) reaches the master"
else
  check_fail "DNP3 unsolicited response did not reach the master (exit $DNP3_STATUS): $(tr -d '\r' <"$WORK_DIR/dnp3-read.err")"
fi
dnp3_read_filter='any(.[]; .proto == "dnp3" and .srcIp == env.MODBUS_SRC and .attributes.function_code == 1 and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.START_TS | fromdateiso8601)))'
if wait_for_jq "${BASE}/events?limit=200" "$dnp3_read_filter"; then
  pass "DPI decoded the DNP3 FC 1 read"
else
  check_fail "no DNP3 FC 1 event from $MODBUS_SRC in telemetry"
fi

if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  log "Inline first-actuation prevention..."
  probe_first_write readwrite "${LAN_NET}.6"
  probe_first_write write "${LAN_NET}.7"
  probe_modbus_diag "${LAN_NET}.10"
  probe_dnp3_control operate 5 "${LAN_NET}.8" 3
  probe_dnp3_control operate-nr 6 "${LAN_NET}.9" 0
fi

log "Triggering a denied Modbus write..."
if compose exec -T ot_client python /opt/modbus/client.py write "$MODBUS_DST" 502 >"$WORK_DIR/modbus-write-trigger.out" 2>"$WORK_DIR/modbus-write-trigger.err"; then
  if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
    log "Initial Modbus write completed ($(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.out"))"
  else
    pass "Learn: the denied Modbus write reaches the server ($(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.out"))"
  fi
elif [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  log "Initial Modbus write blocked immediately ($(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.err"))"
else
  check_fail "Learn: the denied Modbus write was blocked: $(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.err")"
fi

if ! wait_for_jq "${BASE}/events?limit=100" "$modbus_deny_filter"; then
  log "expected Modbus deny rule hit not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=30" | jq '.'
  exit 1
fi
pass "Modbus write matched the deny rule"

FOLLOW_UP_STATUS=0
compose exec -T ot_client python /opt/modbus/client.py write "$MODBUS_DST" 502 >"$WORK_DIR/modbus-write-blocked.out" 2>"$WORK_DIR/modbus-write-blocked.err" || FOLLOW_UP_STATUS=$?
if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  log "Testing follow-up Modbus write is blocked..."
  if [[ $FOLLOW_UP_STATUS -eq 0 ]]; then
    log "Unexpected allow: follow-up Modbus write succeeded"
    cat "$WORK_DIR/modbus-write-blocked.out"
    exit 1
  fi
  pass "Follow-up Modbus write blocked after enforcement"
  assert_no_dynamic_block "$MODBUS_SRC" 502
  assert_no_dynamic_block "${LAN_NET}.8" 20000
  probe_reset_isolation
  if compose exec -T ot_client python /tmp/dnp3.py read "$MODBUS_DST" --source "${LAN_NET}.8" >"$WORK_DIR/dnp3-reconnect.out" 2>"$WORK_DIR/dnp3-reconnect.err"; then
    pass "DNP3 allowed reconnect succeeds immediately after deny"
  else
    check_fail "DNP3 reconnect failed: $(cat "$WORK_DIR/dnp3-reconnect.err")"
  fi
else
  log "Testing follow-up Modbus write is not blocked in learn mode..."
  if [[ $FOLLOW_UP_STATUS -eq 0 ]]; then
    pass "Learn: follow-up Modbus write is not blocked"
  else
    check_fail "Learn: follow-up Modbus write failed (exit $FOLLOW_UP_STATUS): $(tr -d '\r' <"$WORK_DIR/modbus-write-blocked.err")"
  fi
  assert_no_dynamic_block "$MODBUS_SRC" 502
fi

if ! wait_for_jq "${BASE}/stats/protocols" 'any(.[]; .protocol == "modbus" and .packetCount >= 2 and .readCount >= 1 and .writeCount >= 1)'; then
  log "expected modbus protocol stats not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/stats/protocols" | jq '.'
  exit 1
fi
pass "Protocol stats recorded Modbus read and write traffic"

if ! wait_for_jq "${BASE}/inventory" "$modbus_inventory_filter"; then
  log "expected modbus inventory asset not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/inventory" | jq '.'
  exit 1
fi
pass "Inventory discovered Modbus endpoints"

# Persistent connection: read -> write -> read on ONE TCP connection. The
# write must be decoded and denied even though it is not the first PDU,
# and the server's replies must not be mistaken for new flows and blocked.
PERSIST_TS=$(timestamp)
export PERSIST_TS

log "Testing read -> write -> read on one persistent Modbus connection..."
if ! compose exec -T ot_client python /opt/modbus/client.py persistent "$MODBUS_DST" 502 >"$WORK_DIR"/modbus-persistent.out 2>"$WORK_DIR"/modbus-persistent.err; then
  log "persistent Modbus client failed:"
  cat "$WORK_DIR"/modbus-persistent.out "$WORK_DIR"/modbus-persistent.err
  exit 1
fi
sed 's/^/  /' "$WORK_DIR"/modbus-persistent.out
PERSIST_PORT=$(tr -d '\r' <"$WORK_DIR"/modbus-persistent.out | awk '$1 == "PERSISTENT_PORT" { print $2 }')
export PERSIST_PORT
if [[ -z "$PERSIST_PORT" ]] || ! tr -d '\r' <"$WORK_DIR"/modbus-persistent.out | sed -n 2p | grep -q '^READ_OK'; then
  log "persistent connection did not complete its first read"
  exit 1
fi
pass "Persistent connection read reply received (client port ${PERSIST_PORT})"
if [[ "$SMOKE_DPI_CAPTURE" == "afpacket" ]]; then
  if tr -d '\r' <"$WORK_DIR"/modbus-persistent.out | sed -n 3p | grep -q '^WRITE_OK' &&
    tr -d '\r' <"$WORK_DIR"/modbus-persistent.out | sed -n 4p | grep -q '^READ_OK'; then
    pass "Learn: the write and the following read complete on the persistent connection"
  else
    check_fail "Learn: the persistent connection did not complete write and read: $(tr -d '\r' <"$WORK_DIR"/modbus-persistent.out | tr '\n' ' ')"
  fi
fi

persistent_write_filter=$(cat <<'EOF'
any(.[]; .proto == "modbus" and .srcIp == env.MODBUS_SRC and .dstIp == env.MODBUS_DST and .srcPort == (env.PERSIST_PORT | tonumber) and .attributes.function_code == 6 and .attributes.is_write == true and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.PERSIST_TS | fromdateiso8601)))
EOF
)
persistent_deny_filter=$(cat <<'EOF'
any(.[]; .kind == "firewall.rule.hit" and .attributes.ruleId == "smoke-modbus-write-deny" and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= (env.PERSIST_TS | fromdateiso8601)))
EOF
)

if ! wait_for_jq "${BASE}/events?limit=500" "$persistent_write_filter"; then
  log "write on the persistent connection was not decoded"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=30" | jq '[.[] | select(.proto == "modbus")]'
  exit 1
fi
pass "Persistent-connection write decoded (FC6, is_write=true)"

if ! wait_for_jq "${BASE}/events?limit=500" "$persistent_deny_filter"; then
  log "write on the persistent connection did not match the deny rule"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=30" | jq '.'
  exit 1
fi
pass "Persistent-connection write matched the deny rule"

BLOCK_FLOWS=$(compose exec -T engine nft list set inet containd block_flows | tr -d '\r')
if echo "$BLOCK_FLOWS" | grep -q "${MODBUS_DST} . ${MODBUS_SRC}"; then
  log "server replies were dynamically blocked:"
  echo "$BLOCK_FLOWS"
  exit 1
fi
pass "Server replies were not dynamically blocked"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  log "Failed assertions (${SMOKE_DPI_CAPTURE}):"
  printf '  - %s\n' "${FAILURES[@]}"
fi
if [[ $TESTS_PASSED -eq $TESTS_EXPECTED ]]; then
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
else
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
  exit 1
fi
