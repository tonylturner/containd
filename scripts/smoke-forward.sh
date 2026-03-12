#!/usr/bin/env bash
set -euo pipefail

# Smoke-test forwarding + NAT using the simplified compose harness.
# Requirements: docker compose, jq, curl.

COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.smoke.yml}
BASE=${BASE:-http://localhost:18080/api/v1}
TOKEN=${TOKEN:-devtoken}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10 --connect-timeout 5"
SMOKE_SKIP_UP=${SMOKE_SKIP_UP:-0}
SMOKE_BUILD=${SMOKE_BUILD:-1}
TESTS_PASSED=0
TESTS_EXPECTED=9

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

timestamp() {
  # Portable ISO8601-ish UTC timestamp.
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

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  log "Bringing up smoke harness ($COMPOSE_FILE)..."
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

log "Applying dataplane + firewall config (enforcement, SNAT, allow lan->wan, DNAT 8081 -> lan_target)..."
UPDATED_CFG=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" '
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
  | .firewall.nat.sourceZones = ["lan"]
  | .firewall.nat.portForwards = (
      # remove existing entry with same ID then add ours
      [ .firewall.nat.portForwards[]? | select(.id != "lan-http") ]
      + [
        {
          id:"lan-http",
          enabled:true,
          description:"WAN:8081 -> lan_target:80",
          ingressZone:"wan",
          proto:"tcp",
          listenPort:8081,
          destIP:"172.31.0.4",
          destPort:80,
          allowedSources:[]
        }
      ])
  | .firewall.rules = (
      [ .firewall.rules[]? | select(.id != "allow-lan-wan" and .id != "allow-wan-dnat" and .id != "allow-lan-client-wan") ]
      + [
        {
          id:"allow-lan-client-wan",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:["172.31.0.3/32"],
          protocols:[{name:"tcp", port:"8080"}],
          action:"ALLOW"
        }
      ])
')
tmp_cfg_resp=$(mktemp)
tmp_cfg_err=$(mktemp)
code=$(echo "$UPDATED_CFG" | $CURL -w "%{http_code}" -H "$AUTH_HEADER" -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- -o "$tmp_cfg_resp" 2>"$tmp_cfg_err" || true)
if [[ "$code" != "200" ]]; then
  log "config save failed (HTTP $code): body=$(cat "$tmp_cfg_resp"), err=$(cat "$tmp_cfg_err")"
  exit 1
fi
rm -f "$tmp_cfg_resp" "$tmp_cfg_err"

# Bypass commit in the harness; push snapshot directly to engine.
ENGINE=${ENGINE:-http://localhost:18081}
log "Fetching compiled snapshot from mgmt..."
tmp_ruleset=$(mktemp)
if ! $CURL -H "$AUTH_HEADER" "${BASE}/dataplane/ruleset" -o "$tmp_ruleset"; then
  log "failed to fetch ruleset preview"
  exit 1
fi
SNAP=$(jq -c '.snapshot' "$tmp_ruleset")
RULESET_HEAD=$(jq -r '.ruleset' "$tmp_ruleset" | head -n 20)
log "Compiled ruleset (first 20 lines):"
echo "$RULESET_HEAD"

log "Enabling enforcement on engine..."
$CURL -H "Content-Type: application/json" -X POST "${ENGINE}/internal/config" --data '{"enforcement":true,"enforceTable":"containd"}' >/dev/null

log "Applying snapshot to engine..."
tmp_apply_resp=$(mktemp)
code=$($CURL -w "%{http_code}" -H "Content-Type: application/json" -X POST "${ENGINE}/internal/apply_rules" --data "$SNAP" -o "$tmp_apply_resp" || true)
if [[ "$code" != "200" ]]; then
  log "engine apply_rules failed (HTTP $code): $(cat "$tmp_apply_resp")"
  exit 1
fi
rm -f "$tmp_ruleset" "$tmp_apply_resp"

log "Verifying mgmt API still reachable..."
$CURL "${BASE}/health" >/dev/null

log "Setting test client routes (lan->engine, wan->engine)..."
{
  set +e
  docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route flush table main
  docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route flush table main
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route flush table main
  docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route add 172.31.0.0/24 dev eth0 scope link src 172.31.0.3
  docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route add 172.31.0.0/24 dev eth0 scope link src 172.31.0.4
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add 172.30.0.0/24 dev eth0 scope link src 172.30.0.3
  docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route add 172.30.0.0/24 via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route add 172.30.0.0/24 via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add 172.31.0.0/24 via 172.30.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route add default via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route add default via 172.31.0.2 dev eth0
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add default via 172.30.0.2 dev eth0
  set -e
} >/tmp/route-setup.log 2>&1 || true
log "Route programming output:"
sed 's/^/  /' /tmp/route-setup.log

log "Asserting routes prefer engine for cross-subnet traffic..."
LAN_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route get 172.30.0.3 | tr -d '\r')
echo "$LAN_ROUTE" | grep -q "via 172.31.0.2" || { log "lan_client route not via engine: $LAN_ROUTE"; exit 1; }
WAN_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route get 172.31.0.4 | tr -d '\r')
echo "$WAN_ROUTE" | grep -q "via 172.30.0.2" || { log "wan_server route not via engine: $WAN_ROUTE"; exit 1; }
LAN_TGT_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route get 172.30.0.3 | tr -d '\r')
echo "$LAN_TGT_ROUTE" | grep -q "via 172.31.0.2" || { log "lan_target route not via engine: $LAN_TGT_ROUTE"; exit 1; }

log "Snapshotting DNAT counter before tests..."
DNAT_PKTS_BEFORE=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd prerouting | awk '/dnat ip to/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}' || true)

log "Testing LAN -> WAN HTTP (lan_client -> wan_server:8080)..."
docker compose -f "$COMPOSE_FILE" exec -T lan_client curl -svf http://172.30.0.3:8080 >/tmp/lan_wan.out 2>/tmp/lan_wan.err
LAN_STATUS=$?
if [[ $LAN_STATUS -ne 0 ]]; then
  log "LAN->WAN failed (exit $LAN_STATUS):"; cat /tmp/lan_wan.err; exit 1
fi
pass "LAN->WAN success (first line: $(head -n1 /tmp/lan_wan.out))"

log "Testing LAN -> WAN other port blocked (lan_client -> wan_server:8082)..."
if docker compose -f "$COMPOSE_FILE" exec -T lan_client curl -m 5 -sf http://172.30.0.3:8082 >/tmp/lan_wan_block.out 2>/tmp/lan_wan_block.err; then
  log "Unexpected allow: lan_client reached wan_server:8082"; cat /tmp/lan_wan_block.out; exit 1
else
  pass "LAN->WAN port 8082 correctly blocked by rule ordering/default deny"
fi

log "Testing LAN TARGET -> WAN should be blocked (lan_target -> wan_server:8080)..."
if docker compose -f "$COMPOSE_FILE" exec -T lan_target curl -m 5 -sf http://172.30.0.3:8080 >/tmp/lan_target_wan.out 2>/tmp/lan_target_wan.err; then
  log "Unexpected allow: lan_target reached wan_server:8080"; cat /tmp/lan_target_wan.out; exit 1
else
  pass "LAN target blocked from WAN as expected"
fi

log "Testing DNAT WAN:8081 -> LAN target:80 (from wan_server)..."
docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "wget -qO- --timeout=5 http://172.30.0.2:8081" >/tmp/wan_dnat.out 2>/tmp/wan_dnat.err
DNAT_STATUS=$?
if [[ $DNAT_STATUS -ne 0 ]]; then
  log "WAN DNAT failed (exit $DNAT_STATUS):"; cat /tmp/wan_dnat.err; exit 1
fi
pass "WAN DNAT success (first line: $(head -n1 /tmp/wan_dnat.out))"

log "Testing WAN direct to LAN (should be blocked: wan_server -> 172.31.0.4:80)..."
if docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "wget -qO- --timeout=5 http://172.31.0.4:80" >/tmp/wan_direct.out 2>/tmp/wan_direct.err; then
  log "Unexpected allow: wan_server reached 172.31.0.4:80"; exit 1
else
  pass "WAN direct to LAN HTTP correctly blocked"
fi

log "Testing WAN direct to LAN SSH (should be blocked: wan_server -> 172.31.0.4:22)..."
if docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "nc -z -w2 172.31.0.4 22" >/tmp/wan_direct_ssh.out 2>/tmp/wan_direct_ssh.err; then
  log "Unexpected allow: wan_server reached 172.31.0.4:22"; exit 1
else
  pass "WAN SSH to LAN correctly blocked"
fi

log "Checking nft counters for NAT and forward paths..."
DNAT_PKTS_AFTER=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd prerouting | awk '/dnat ip to/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}' || true)
POST_PKTS=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd postrouting | awk '/masquerade/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}' || true)
FWD_LAN_WAN=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd forward | awk '/dport 8080/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}' || true)
FWD_WAN_DNAT=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd forward | awk '/dport 80/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}' || true)
if [[ -n "$DNAT_PKTS_BEFORE" && -n "$DNAT_PKTS_AFTER" ]]; then
  if (( DNAT_PKTS_AFTER <= DNAT_PKTS_BEFORE )); then
    log "DNAT counter did not increment (before=$DNAT_PKTS_BEFORE after=$DNAT_PKTS_AFTER)"; exit 1
  fi
fi
log "Counters: prerouting DNAT packets=$DNAT_PKTS_AFTER, postrouting masq packets=$POST_PKTS, forward lan->wan=$FWD_LAN_WAN, forward wan->lan=$FWD_WAN_DNAT"
pass "Counters observed and DNAT incremented"

log "Testing no-route scenario (wan_server without path to engine/LAN)..."
WAN_NET_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T wan_server ip -4 route show 172.30.0.0/24 | tr -d '\r')
WAN_DEF_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T wan_server ip -4 route show default | tr -d '\r')
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route del 172.30.0.0/24 || true
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route del default || true
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add unreachable 172.30.0.0/24 || true
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add unreachable default || true
if docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "wget -qO- --timeout=5 http://172.30.0.2:8081" >/tmp/wan_noroute.out 2>/tmp/wan_noroute.err; then
  log "Unexpected success with no route present"; exit 1
else
  pass "No-route check passed (traffic failed as expected)"
fi

log "Restoring routes after no-route check..."
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route flush table main || true
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route flush unreachable || true
if [[ -n "$WAN_NET_ROUTE" ]]; then
  docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "ip route add $WAN_NET_ROUTE" || true
else
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add 172.30.0.0/24 dev eth0 scope link src 172.30.0.3 || true
fi
if [[ -n "$WAN_DEF_ROUTE" ]]; then
  docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "ip route add $WAN_DEF_ROUTE" || true
else
  docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route add default via 172.30.0.2 dev eth0 || true
fi

log "Re-testing DNAT after route restoration..."
docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "wget -qO- --timeout=5 http://172.30.0.2:8081" >/tmp/wan_dnat2.out 2>/tmp/wan_dnat2.err
if [[ $? -ne 0 ]]; then
  log "WAN DNAT after restore failed:"; cat /tmp/wan_dnat2.err; exit 1
fi
pass "WAN DNAT after restore success (first line: $(head -n1 /tmp/wan_dnat2.out))"

if [[ $TESTS_PASSED -eq $TESTS_EXPECTED ]]; then
  printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
else
  printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
fi
