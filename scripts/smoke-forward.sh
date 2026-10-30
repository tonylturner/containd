#!/usr/bin/env bash
set -euo pipefail

# Smoke-test forwarding and NAT using the simplified compose harness.
# Requirements: docker compose, jq, curl.
#
# The harness installs its own forward policy (default deny, one allow for
# lan_client to wan_server tcp/8080), SNAT from lan to wan and a DNAT port
# forward from the engine's WAN address to lan_target:80, then asserts:
# - allowed traffic arrives, and wan_server sees the engine's WAN address as
#   its source (masquerade), not the LAN client;
# - the DNAT forward reaches lan_target, lan_target sees the engine's LAN
#   address (return-path masquerade), and the DNAT rule's packet counter
#   increases across the probe;
# - every denied flow times out. Each deny probe targets a live listener,
#   and a control probe from the listener's own network segment proves that
#   listener answers before the deny is asserted.
#
# Probes run test/data-smoke/forward/probe.py inside the client containers.
# A deny passes only on a connection timeout, the outcome of the drop
# policy; a reply or reset means the flow got through.
#
# Exit status: 0 when every check passes, 1 when a check fails, 2 on a
# harness error (missing tool, failed compose or exec, dead listener, broken
# client route), which never counts as a pass or as a detected failure.
#
# SMOKE_MUTATION=permissive adds an allow-all forward rule and
# SMOKE_MUTATION=no-masquerade drops the LAN zone from the masquerade source
# zones (the DNAT return-path masquerade stays); both must make the run
# fail (scripts/smoke-forward-mutations.sh checks that). When
# SMOKE_RESULT_FILE is set, the IDs of the failed checks are written there,
# one per line.

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
SMOKE_MUTATION=${SMOKE_MUTATION:-}
SMOKE_RESULT_FILE=${SMOKE_RESULT_FILE:-}
PROBE_TIMEOUT=${SMOKE_PROBE_TIMEOUT:-3}
DNAT_PORT=${DNAT_PORT:-8088}
TESTS_PASSED=0
TESTS_EXPECTED=11
FAILED_CHECKS=""
FINISHED=0

ENGINE_WAN="${WAN_NET}.2"
ENGINE_LAN="${LAN_NET}.2"
LAN_CLIENT="${LAN_NET}.3"
LAN_TARGET="${LAN_NET}.4"
WAN_SERVER="${WAN_NET}.3"

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

timestamp() {
  # Portable ISO8601-ish UTC timestamp.
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}
log() { echo "[$(timestamp)] $*"; }
pass() {
  TESTS_PASSED=$((TESTS_PASSED + 1))
  log "PASS [$1]: $2"
}
# check_fail records a failed check and lets the run continue, so one run
# reports every failed check.
check_fail() {
  FAILED_CHECKS="${FAILED_CHECKS}$1"$'\n'
  log "FAIL [$1]: $2"
}
harness_error() {
  log "HARNESS ERROR: $*" >&2
  exit 2
}

WORK_DIR=$(mktemp -d)
# shellcheck source=scripts/smoke-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/smoke-lib.sh"
trap on_exit EXIT

# shellcheck source=scripts/smoke-engine-api.sh
source "$(dirname "${BASH_SOURCE[0]}")/smoke-engine-api.sh"

case "$SMOKE_MUTATION" in
  "" | permissive | no-masquerade) ;;
  *) harness_error "SMOKE_MUTATION must be empty, permissive or no-masquerade, got: $SMOKE_MUTATION" ;;
esac
if [[ -n "$SMOKE_RESULT_FILE" ]]; then
  : >"$SMOKE_RESULT_FILE"
fi

ensure_tools() {
  for bin in docker jq curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      harness_error "missing required tool: $bin"
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
  harness_error "timed out waiting for $url"
}

discover_iface() {
  local state=$1 ip=$2
  echo "$state" | jq -r --arg ip "$ip" '
    map(select(.addrs[]? | contains($ip))) | .[0].name // empty
  '
}

# probe SERVICE IP PORT prints the network outcome of one TCP connection
# from SERVICE: "open <reply line>", "timeout", "refused" or "unreachable".
# A probe that cannot run is a harness error, never an outcome.
probe() {
  local service=$1 ip=$2 port=$3 out status=0
  out=$(compose exec -T "$service" python /opt/forward/probe.py "$ip" "$port" "$PROBE_TIMEOUT" 2>"$WORK_DIR/probe.err") || status=$?
  out=$(printf '%s' "$out" | tr -d '\r')
  if [[ $status -ne 0 ]]; then
    harness_error "probe $service -> $ip:$port did not run (exit $status): $(tr -d '\r' <"$WORK_DIR/probe.err")"
  fi
  case "$out" in
    open | "open "* | timeout | refused | unreachable) printf '%s\n' "$out" ;;
    *) harness_error "probe $service -> $ip:$port printed no outcome: $out" ;;
  esac
}

# reply_field OUTCOME KEY prints KEY's value from an echo listener reply
# ("open server=NAME port=PORT client=IP").
reply_field() {
  local word
  for word in $1; do
    if [[ $word == "$2="* ]]; then
      printf '%s\n' "${word#*=}"
      return 0
    fi
  done
  return 0
}

# expect_listener SOURCE IP PORT NAME is the control probe for a deny: SOURCE
# shares the listener's network segment, so the engine does not forward the
# connection. A deny probe to a dead listener would time out for the wrong
# reason, so a silent listener is a harness error.
expect_listener() {
  local source=$1 ip=$2 port=$3 name=$4 reply status=0
  if [[ $source == engine ]]; then
    reply=$(compose exec -T engine curl -sS --connect-timeout "$PROBE_TIMEOUT" --max-time 10 "http://${ip}:${port}/" 2>"$WORK_DIR/control.err") || status=$?
    if [[ $status -ne 0 ]]; then
      harness_error "control probe engine -> $ip:$port failed (exit $status): $(tr -d '\r' <"$WORK_DIR/control.err")"
    fi
    reply="open $(printf '%s' "$reply" | tr -d '\r')"
  else
    reply=$(probe "$source" "$ip" "$port")
  fi
  if [[ "$(reply_field "$reply" server)" != "$name" || "$(reply_field "$reply" port)" != "$port" ]]; then
    harness_error "control probe $source -> $ip:$port: want $name listening, got: $reply"
  fi
  log "Control: $name answers on $ip:$port from $source ($reply)"
}

# deny_probe ID DESCRIPTION SERVICE IP PORT passes only when the connection
# times out, the outcome of the drop policy.
deny_probe() {
  local id=$1 desc=$2 service=$3 ip=$4 port=$5 outcome
  log "Testing $desc (should be dropped: $service -> $ip:$port)..."
  outcome=$(probe "$service" "$ip" "$port")
  case "$outcome" in
    timeout) pass "$id" "$desc dropped (connection timed out)" ;;
    unreachable) harness_error "$desc: $service has no route to $ip" ;;
    *) check_fail "$id" "$desc got through the firewall ($outcome)" ;;
  esac
}

# dnat_packets prints the packet counter of the DNAT rule for the port
# forward, or nothing when the rule or its counter is missing.
dnat_packets() {
  local table status=0
  table=$(compose exec -T engine nft list table inet containd_policy 2>"$WORK_DIR/nft.err") || status=$?
  if [[ $status -ne 0 ]]; then
    harness_error "nft list table inet containd_policy failed (exit $status): $(tr -d '\r' <"$WORK_DIR/nft.err")"
  fi
  printf '%s\n' "$table" | tr -d '\r' | awk -v want="dnat ip to ${LAN_TARGET}:80" -v port="dport ${DNAT_PORT} " '
    index($0, want) && index($0, port) {
      n++
      for (i = 1; i < NF; i++) if ($i == "packets") p = $(i + 1)
    }
    END { if (n == 1 && p ~ /^[0-9]+$/) print p }
  '
}

assert_route_via() {
  local service=$1 dst=$2 gateway=$3 route
  route=$(compose exec -T "$service" ip route get "$dst" | tr -d '\r')
  if ! echo "$route" | grep -q "via ${gateway} "; then
    harness_error "$service route to $dst not via engine: $route"
  fi
}

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  log "Bringing up smoke harness ($COMPOSE_FILE)..."
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
WAN_DEV=$(discover_iface "$STATE" "$ENGINE_WAN")
LAN_DEV=$(discover_iface "$STATE" "$ENGINE_LAN")
if [[ -z "$WAN_DEV" || -z "$LAN_DEV" ]]; then
  harness_error "failed to discover wan/lan devices from interface state: $STATE"
fi
log "Detected wan=${WAN_DEV}, lan=${LAN_DEV}"

log "Fetching current config..."
CFG=$($CURL -H "$AUTH_HEADER" "${BASE}/config")

log "Applying the harness policy (default deny, allow ${LAN_CLIENT} -> wan tcp/8080, SNAT lan->wan, DNAT ${DNAT_PORT} -> lan_target:80)${SMOKE_MUTATION:+ with mutation ${SMOKE_MUTATION}}..."
UPDATED_CFG=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" --arg dnatPort "$DNAT_PORT" \
  --arg lanTarget "$LAN_TARGET" --arg lanClient "${LAN_CLIENT}/32" --arg mutation "$SMOKE_MUTATION" '
  .interfaces |= map(
    if .name=="wan" then .device=$wan
    elif .name=="lan1" then .device=$lan | .zone="lan"
    else . end)
  | .system.mgmt.httpListenAddr=":18080"
  | .system.mgmt.listenAddr=":18080"
  | .dataPlane.enforcement = true
  | .dataPlane.enforceTable = "containd"
  | .firewall.nat.enabled = true
  | .firewall.nat.egressZone = "wan"
  | .firewall.nat.sourceZones = (if $mutation == "no-masquerade" then ["dmz"] else ["lan"] end)
  | .firewall.nat.portForwards = [
      {
        id:"lan-http",
        enabled:true,
        description:("WAN:" + $dnatPort + " -> lan_target:80"),
        ingressZone:"wan",
        proto:"tcp",
        listenPort:($dnatPort | tonumber),
        destIP:$lanTarget,
        destPort:80,
        allowedSources:[]
      }
    ]
  # The harness owns the whole forward policy, so a rule left behind by
  # an earlier run or the default config cannot open a denied flow.
  | .firewall.defaultAction = "DENY"
  | .firewall.rules = [
      {
        id:"allow-lan-client-wan",
        sourceZones:["lan"],
        destZones:["wan"],
        sources:[$lanClient],
        protocols:[{name:"tcp", port:"8080"}],
        action:"ALLOW"
      }
    ] + (if $mutation == "permissive" then [
      {
        id:"smoke-mutation-allow-all",
        description:"Deliberately permissive policy for the smoke mutation run",
        action:"ALLOW"
      }
    ] else [] end)
')
tmp_cfg_resp="$WORK_DIR/tmp_cfg_resp"
tmp_cfg_err="$WORK_DIR/tmp_cfg_err"
code=$(echo "$UPDATED_CFG" | $CURL -w "%{http_code}" -H "$AUTH_HEADER" -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- -o "$tmp_cfg_resp" 2>"$tmp_cfg_err" || true)
if [[ "$code" != "200" ]]; then
  harness_error "config save failed (HTTP $code): body=$(cat "$tmp_cfg_resp"), err=$(cat "$tmp_cfg_err")"
fi

# Bypass commit in the harness; push snapshot directly to engine.
log "Fetching compiled snapshot from mgmt..."
tmp_ruleset="$WORK_DIR/tmp_ruleset"
if ! $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" -o "$tmp_ruleset"; then
  harness_error "failed to fetch ruleset preview"
fi
SNAP=$(jq -c '.snapshot' "$tmp_ruleset")

log "Enabling enforcement on engine..."
tmp_engine_cfg_resp="$WORK_DIR/tmp_engine_cfg_resp"
code=$(engine_post engine /internal/config "$tmp_engine_cfg_resp" <<<'{"enforcement":true,"enforceTable":"containd"}')
if [[ "$code" != "200" ]]; then
  harness_error "engine config failed (HTTP $code): $(cat "$tmp_engine_cfg_resp")"
fi

log "Applying snapshot to engine..."
tmp_apply_resp="$WORK_DIR/tmp_apply_resp"
code=$(engine_post engine /internal/apply_rules "$tmp_apply_resp" <<<"$SNAP")
if [[ "$code" != "200" ]]; then
  harness_error "engine apply_rules failed (HTTP $code): $(cat "$tmp_apply_resp")"
fi

log "Enforced forward and NAT chains:"
for chain in forward prerouting postrouting; do
  # A missing NAT chain is reported by the checks that need it.
  compose exec -T engine nft list chain inet containd_policy "$chain" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
done

log "Verifying mgmt API still reachable..."
$CURL "${BASE}/health" >/dev/null

log "Setting test client routes (cross-subnet and default via the engine)..."
route_client lan_client "$LAN_CLIENT" "$LAN_NET" "$WAN_NET" "$ENGINE_LAN"
route_client lan_target "$LAN_TARGET" "$LAN_NET" "$WAN_NET" "$ENGINE_LAN"
route_client wan_server "$WAN_SERVER" "$WAN_NET" "$LAN_NET" "$ENGINE_WAN"
assert_route_via lan_client "$WAN_SERVER" "$ENGINE_LAN"
assert_route_via lan_target "$WAN_SERVER" "$ENGINE_LAN"
assert_route_via wan_server "$LAN_TARGET" "$ENGINE_WAN"

log "Control probes: deny targets answer on their own segment..."
expect_listener engine "$WAN_SERVER" 8080 wan_server
expect_listener engine "$WAN_SERVER" 8082 wan_server
expect_listener lan_client "$LAN_TARGET" 80 lan_target
expect_listener lan_client "$LAN_TARGET" 22 lan_target

log "Testing LAN -> WAN HTTP (lan_client -> wan_server:8080)..."
OUTCOME=$(probe lan_client "$WAN_SERVER" 8080)
if [[ "$(reply_field "$OUTCOME" server)" == wan_server && "$(reply_field "$OUTCOME" port)" == 8080 ]]; then
  pass lan-wan-allow "LAN->WAN allowed ($OUTCOME)"
else
  check_fail lan-wan-allow "LAN->WAN to wan_server:8080 did not arrive ($OUTCOME)"
fi
SEEN=$(reply_field "$OUTCOME" client)
if [[ "$SEEN" == "$ENGINE_WAN" ]]; then
  pass lan-wan-snat "wan_server saw the engine's WAN address $ENGINE_WAN as source (masquerade)"
else
  check_fail lan-wan-snat "wan_server saw source '${SEEN}', want the engine's WAN address $ENGINE_WAN (lan_client is $LAN_CLIENT)"
fi

deny_probe deny-lan-wan-8082 "LAN->WAN on a port without an allow rule" lan_client "$WAN_SERVER" 8082
deny_probe deny-lan-target-wan "LAN->WAN from a source without an allow rule" lan_target "$WAN_SERVER" 8080

DNAT_BEFORE=$(dnat_packets)
log "Testing DNAT WAN:${DNAT_PORT} -> lan_target:80 (from wan_server, DNAT packets before: ${DNAT_BEFORE:-missing})..."
OUTCOME=$(probe wan_server "$ENGINE_WAN" "$DNAT_PORT")
DNAT_AFTER=$(dnat_packets)
if [[ "$(reply_field "$OUTCOME" server)" == lan_target && "$(reply_field "$OUTCOME" port)" == 80 ]]; then
  pass dnat-forward "WAN DNAT reached lan_target:80 ($OUTCOME)"
else
  check_fail dnat-forward "WAN DNAT to ${ENGINE_WAN}:${DNAT_PORT} did not reach lan_target:80 ($OUTCOME)"
fi
SEEN=$(reply_field "$OUTCOME" client)
if [[ "$SEEN" == "$ENGINE_LAN" ]]; then
  pass dnat-return-snat "lan_target saw the engine's LAN address $ENGINE_LAN as source (return-path masquerade)"
else
  check_fail dnat-return-snat "lan_target saw source '${SEEN}', want the engine's LAN address $ENGINE_LAN (wan_server is $WAN_SERVER)"
fi
if [[ -z "$DNAT_BEFORE" || -z "$DNAT_AFTER" ]]; then
  check_fail dnat-counter "DNAT rule counter missing or unparseable (before='${DNAT_BEFORE}' after='${DNAT_AFTER}')"
elif ((DNAT_AFTER > DNAT_BEFORE)); then
  pass dnat-counter "DNAT rule counter increased ($DNAT_BEFORE -> $DNAT_AFTER packets)"
else
  check_fail dnat-counter "DNAT rule counter did not increase ($DNAT_BEFORE -> $DNAT_AFTER packets)"
fi

deny_probe deny-wan-lan-80 "WAN->LAN HTTP without DNAT" wan_server "$LAN_TARGET" 80
deny_probe deny-wan-lan-22 "WAN->LAN SSH" wan_server "$LAN_TARGET" 22

log "Testing no-route scenario (wan_server without a route to the engine)..."
compose exec -T wan_server ip route flush table main
compose exec -T wan_server ip route add unreachable "${WAN_NET}.0/24"
compose exec -T wan_server ip route add unreachable default
OUTCOME=$(probe wan_server "$ENGINE_WAN" "$DNAT_PORT")
if [[ "$OUTCOME" == unreachable ]]; then
  pass no-route "wan_server without routes cannot reach the DNAT address ($OUTCOME)"
else
  check_fail no-route "wan_server reached ${ENGINE_WAN}:${DNAT_PORT} without a route ($OUTCOME)"
fi

log "Restoring wan_server routes after no-route check..."
compose exec -T wan_server ip route del unreachable "${WAN_NET}.0/24"
compose exec -T wan_server ip route del unreachable default
route_client wan_server "$WAN_SERVER" "$WAN_NET" "$LAN_NET" "$ENGINE_WAN"
assert_route_via wan_server "$LAN_TARGET" "$ENGINE_WAN"

log "Re-testing DNAT after route restoration..."
OUTCOME=$(probe wan_server "$ENGINE_WAN" "$DNAT_PORT")
if [[ "$(reply_field "$OUTCOME" server)" == lan_target ]]; then
  pass dnat-after-restore "WAN DNAT after restore reached lan_target ($OUTCOME)"
else
  check_fail dnat-after-restore "WAN DNAT after restore did not reach lan_target ($OUTCOME)"
fi

FAILED_COUNT=$(printf '%s' "$FAILED_CHECKS" | grep -c . || true)
if [[ -n "$SMOKE_RESULT_FILE" ]]; then
  printf '%s' "$FAILED_CHECKS" >"$SMOKE_RESULT_FILE"
fi
if ((TESTS_PASSED + FAILED_COUNT != TESTS_EXPECTED)); then
  harness_error "ran $((TESTS_PASSED + FAILED_COUNT)) checks, TESTS_EXPECTED is $TESTS_EXPECTED"
fi
FINISHED=1
if ((FAILED_COUNT > 0)); then
  log "Failed checks${SMOKE_MUTATION:+ (mutation ${SMOKE_MUTATION})}:"
  printf '%s' "$FAILED_CHECKS" | sed 's/^/  - /'
  printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
  exit 1
fi
printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
