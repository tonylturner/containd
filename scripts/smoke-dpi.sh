#!/usr/bin/env bash
set -euo pipefail

# Smoke-test live ICS DPI with deterministic Modbus/TCP traffic.
# Requirements: docker compose, jq, curl.
#
# SMOKE_DPI_CAPTURE=afpacket (default) observes traffic on the interfaces;
# the first denied write reaches the server and only later writes are
# blocked. SMOKE_DPI_CAPTURE=nfqueue steers ICS traffic through NFQUEUE
# (nfqueueGroup SMOKE_NFQUEUE_GROUP, default 101) and also asserts US
# first-write prevention (milestone B §4.1 item 1, §10.3): the first Modbus
# write on a fresh connection, and the first write after a read on a
# persistent connection, are dropped before the server changes state.
#
# EXPECTED-FAIL GATE: those first-write assertions fail on the engine before
# the milestone B inline verdict (lane L3) and engine (lane L4) work merges,
# because the engine accepts the current packet and only installs a later
# block. They must pass after that merge. Do not weaken them to go green.

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
ENGINE=${ENGINE:-http://localhost:18081}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10 --connect-timeout 5"
SMOKE_SKIP_UP=${SMOKE_SKIP_UP:-0}
SMOKE_BUILD=${SMOKE_BUILD:-1}
SMOKE_DPI_CAPTURE=${SMOKE_DPI_CAPTURE:-afpacket}
NFQUEUE_GROUP=${SMOKE_NFQUEUE_GROUP:-101}
TESTS_PASSED=0
TESTS_EXPECTED=7
FAILURES=()
case "$SMOKE_DPI_CAPTURE" in
  afpacket) ;;
  nfqueue) TESTS_EXPECTED=10 ;;
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
# run reports every first-write assertion.
check_fail() { FAILURES+=("$*"); log "FAIL: $*"; }

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

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
  local ruleset_file snap ruleset_head tmp_cfg code tmp_apply_resp
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
  tmp_cfg=$(mktemp)
  printf '%s' "$DATAPLANE_CFG" >"$tmp_cfg"
  code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/config" --data-binary @"$tmp_cfg" -o "$WORK_DIR/smoke-dpi-engine-config.out" || true)
  rm -f "$tmp_cfg"
  if [[ "$code" != "200" ]]; then
    log "engine config failed (HTTP $code): $(cat "$WORK_DIR/smoke-dpi-engine-config.out")"
    exit 1
  fi

  log "Applying snapshot to engine..."
  tmp_apply_resp=$(mktemp)
  code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/apply_rules" --data "$snap" -o "$tmp_apply_resp" || true)
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

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  log "Ensuring smoke harness is up ($COMPOSE_FILE)..."
  if [[ "$SMOKE_BUILD" == "1" ]]; then
    compose up -d --build
  else
    compose up -d
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

# The nfqueue variant uses two extra client addresses so its first-write
# probes do not share the US dynamic block (src, dst, dport) of the others.
if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  CLIENT_SOURCES=$(jq -cn --arg net "$LAN_NET" '[$net + ".5/32", $net + ".6/32", $net + ".7/32"]')
else
  CLIENT_SOURCES=$(jq -cn --arg net "$LAN_NET" '[$net + ".5/32"]')
fi

UPDATED_CFG=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" \
  --argjson clients "$CLIENT_SOURCES" --arg server "${WAN_NET}.4/32" \
  --arg capture "$SMOKE_DPI_CAPTURE" --argjson queue "$NFQUEUE_GROUP" '
  .interfaces |= map(
    if .name=="wan" then .device=$wan
    elif .name=="lan1" then .device=$lan | .zone="lan"
    else . end)
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
  | .dataPlane.dpiIcsProtocols = ((.dataPlane.dpiIcsProtocols // {}) + {"modbus": true})
  | .firewall.rules = (
      [ .firewall.rules[]? | select(.id != "smoke-modbus-read" and .id != "smoke-modbus-write-deny") ]
      + [
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
        }
      ])
')

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
    compose exec -T ot_client ip addr add "${LAN_NET}.6/24" dev eth0
    compose exec -T ot_client ip addr add "${LAN_NET}.7/24" dev eth0
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

if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
  log "Inline first-write prevention (expected-fail gate until lanes L3 and L4 merge)..."
  probe_first_write readwrite "${LAN_NET}.6"
  probe_first_write write "${LAN_NET}.7"
fi

log "Triggering Modbus write enforcement..."
if compose exec -T ot_client python /opt/modbus/client.py write "$MODBUS_DST" 502 >"$WORK_DIR/modbus-write-trigger.out" 2>"$WORK_DIR/modbus-write-trigger.err"; then
  log "Initial Modbus write completed before dynamic block took effect ($(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.out"))"
else
  log "Initial Modbus write blocked immediately ($(tr -d '\r' <"$WORK_DIR/modbus-write-trigger.err"))"
fi

if ! wait_for_jq "${BASE}/events?limit=100" "$modbus_deny_filter"; then
  log "expected Modbus deny rule hit not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=30" | jq '.'
  exit 1
fi
pass "Modbus write matched the deny rule"

log "Testing follow-up Modbus write is blocked..."
if compose exec -T ot_client python /opt/modbus/client.py write "$MODBUS_DST" 502 >"$WORK_DIR/modbus-write-blocked.out" 2>"$WORK_DIR/modbus-write-blocked.err"; then
  log "Unexpected allow: follow-up Modbus write succeeded"
  cat "$WORK_DIR/modbus-write-blocked.out"
  exit 1
else
  pass "Follow-up Modbus write blocked after enforcement"
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

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  log "Failed assertions (${SMOKE_DPI_CAPTURE}):"
  printf '  - %s\n' "${FAILURES[@]}"
  if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
    log "The inline first-write assertions are the expected-fail gate until lanes L3 and L4 merge."
  fi
fi
if [[ $TESTS_PASSED -eq $TESTS_EXPECTED ]]; then
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
else
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
  exit 1
fi
