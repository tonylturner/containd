#!/usr/bin/env bash
set -euo pipefail

# Smoke-test live ICS DPI with deterministic Modbus/TCP traffic.
# Requirements: docker compose, jq, curl.

COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.smoke.yml}
BASE=${BASE:-http://localhost:18080/api/v1}
TOKEN=${TOKEN:-devtoken}
ENGINE=${ENGINE:-http://localhost:18081}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10 --connect-timeout 5"
SMOKE_SKIP_UP=${SMOKE_SKIP_UP:-0}
SMOKE_BUILD=${SMOKE_BUILD:-1}
TESTS_PASSED=0
TESTS_EXPECTED=7

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() { echo "[$(timestamp)] $*"; }
pass() { ((TESTS_PASSED++)); log "PASS: $*"; }

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
  code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/config" --data-binary @"$tmp_cfg" -o /tmp/smoke-dpi-engine-config.out || true)
  rm -f "$tmp_cfg"
  if [[ "$code" != "200" ]]; then
    log "engine config failed (HTTP $code): $(cat /tmp/smoke-dpi-engine-config.out)"
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

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  log "Ensuring smoke harness is up ($COMPOSE_FILE)..."
  if [[ "$SMOKE_BUILD" == "1" ]]; then
    docker compose -f "$COMPOSE_FILE" up -d --build
  else
    docker compose -f "$COMPOSE_FILE" up -d
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
WAN_DEV=$(discover_iface "$STATE" "172.30.0.2")
LAN_DEV=$(discover_iface "$STATE" "172.31.0.2")
if [[ -z "$WAN_DEV" || -z "$LAN_DEV" ]]; then
  echo "failed to discover wan/lan devices from interface state:" >&2
  echo "$STATE" >&2
  exit 1
fi
log "Detected wan=${WAN_DEV}, lan=${LAN_DEV}"

log "Fetching current config..."
CFG=$($CURL -H "$AUTH_HEADER" "${BASE}/config")

UPDATED_CFG=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" '
  .interfaces |= map(
    if .name=="wan" then .device=$wan
    elif .name=="lan1" then .device=$lan | .zone="lan"
    else . end)
  | .system.mgmt.httpListenAddr=":18080"
  | .system.mgmt.listenAddr=":18080"
  | .dataPlane.captureInterfaces = [$wan, $lan]
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
          sources:["172.31.0.5/32"],
          destinations:["172.30.0.4/32"],
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
          sources:["172.31.0.5/32"],
          destinations:["172.30.0.4/32"],
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
export MODBUS_SRC="172.31.0.5"
export MODBUS_DST="172.30.0.4"

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
  docker compose -f "$COMPOSE_FILE" exec -T ot_client ip route flush table main
  docker compose -f "$COMPOSE_FILE" exec -T modbus_server ip route flush table main
  docker compose -f "$COMPOSE_FILE" exec -T ot_client ip route add 172.31.0.0/24 dev eth0 scope link src 172.31.0.5
  docker compose -f "$COMPOSE_FILE" exec -T modbus_server ip route add 172.30.0.0/24 dev eth0 scope link src 172.30.0.4
  docker compose -f "$COMPOSE_FILE" exec -T ot_client ip route add 172.30.0.0/24 via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T modbus_server ip route add 172.31.0.0/24 via 172.30.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T ot_client ip route add default via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T modbus_server ip route add default via 172.30.0.2 dev eth0
  set -e
} >/tmp/route-setup-dpi.log 2>&1 || true
sed 's/^/  /' /tmp/route-setup-dpi.log

OT_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T ot_client ip route get 172.30.0.4 | tr -d '\r')
echo "$OT_ROUTE" | grep -q "via 172.31.0.2" || { log "ot_client route not via engine: $OT_ROUTE"; exit 1; }
pass "OT client route uses engine for Modbus traffic"

log "Testing Modbus read allow..."
docker compose -f "$COMPOSE_FILE" exec -T ot_client python /opt/modbus/client.py read 172.30.0.4 502 >/tmp/modbus-read.out 2>/tmp/modbus-read.err
READ_STATUS=$?
if [[ $READ_STATUS -ne 0 ]]; then
  log "Modbus read failed (exit $READ_STATUS):"
  cat /tmp/modbus-read.err
  exit 1
fi
pass "Modbus read allowed ($(tr -d '\r' </tmp/modbus-read.out))"

if ! wait_for_jq "${BASE}/events?limit=100" "$modbus_event_filter"; then
  log "expected modbus event not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=20" | jq '.'
  exit 1
fi
pass "Modbus event recorded in telemetry"

log "Triggering Modbus write enforcement..."
if docker compose -f "$COMPOSE_FILE" exec -T ot_client python /opt/modbus/client.py write 172.30.0.4 502 >/tmp/modbus-write-trigger.out 2>/tmp/modbus-write-trigger.err; then
  log "Initial Modbus write completed before dynamic block took effect ($(tr -d '\r' </tmp/modbus-write-trigger.out))"
else
  log "Initial Modbus write blocked immediately ($(tr -d '\r' </tmp/modbus-write-trigger.err))"
fi

if ! wait_for_jq "${BASE}/events?limit=100" "$modbus_deny_filter"; then
  log "expected Modbus deny rule hit not found"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=30" | jq '.'
  exit 1
fi
pass "Modbus write matched the deny rule"

log "Testing follow-up Modbus write is blocked..."
if docker compose -f "$COMPOSE_FILE" exec -T ot_client python /opt/modbus/client.py write 172.30.0.4 502 >/tmp/modbus-write-blocked.out 2>/tmp/modbus-write-blocked.err; then
  log "Unexpected allow: follow-up Modbus write succeeded"
  cat /tmp/modbus-write-blocked.out
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

if [[ $TESTS_PASSED -eq $TESTS_EXPECTED ]]; then
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
else
  printf "[%s] %bDPI smoke complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
fi
