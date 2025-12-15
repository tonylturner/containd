#!/usr/bin/env bash
set -euo pipefail

# Smoke-test forwarding + NAT using the simplified compose harness.
# Requirements: docker compose, jq, curl.

COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.smoke.yml}
BASE=${BASE:-http://localhost:18080/api/v1}
TOKEN=${TOKEN:-devtoken}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10 --connect-timeout 5"

timestamp() {
  # Portable ISO8601-ish UTC timestamp.
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}
log() { echo "[$(timestamp)] $*"; }

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

log "Bringing up smoke harness ($COMPOSE_FILE)..."
docker compose -f "$COMPOSE_FILE" up -d --build

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
      [ .firewall.rules[]? | select(.id != "allow-lan-wan" and .id != "allow-wan-dnat") ]
      + [
        {
          id:"allow-lan-wan",
          sourceZones:["lan"],
          destZones:["wan"],
          action:"ALLOW"
        },
        {
          id:"allow-wan-dnat",
          sourceZones:["wan"],
          destZones:["lan"],
          protocols:[{name:"tcp", port:"80"}],
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
ENGINE=${ENGINE:-http://localhost:8081}
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

log "Setting test client routes (lan->engine, wan->engine)..."
docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route replace 172.30.0.0/24 via 172.31.0.2
docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route replace 172.30.0.0/24 via 172.31.0.2
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route replace 172.31.0.0/24 via 172.30.0.2
docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route replace default via 172.31.0.2
docker compose -f "$COMPOSE_FILE" exec -T lan_target ip route replace default via 172.31.0.2
docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route replace default via 172.30.0.2

log "Asserting routes prefer engine for cross-subnet traffic..."
LAN_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T lan_client ip route get 172.30.0.3 | tr -d '\r')
echo "$LAN_ROUTE" | grep -q "via 172.31.0.2" || { log "lan_client route not via engine: $LAN_ROUTE"; exit 1; }
WAN_ROUTE=$(docker compose -f "$COMPOSE_FILE" exec -T wan_server ip route get 172.31.0.4 | tr -d '\r')
echo "$WAN_ROUTE" | grep -q "via 172.30.0.2" || { log "wan_server route not via engine: $WAN_ROUTE"; exit 1; }

log "Ensuring wan_server has curl for DNAT check..."
docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "apk add --no-cache curl >/dev/null"

log "Testing LAN -> WAN HTTP (lan_client -> wan_server:8080)..."
docker compose -f "$COMPOSE_FILE" exec -T lan_client curl -svf http://172.30.0.3:8080 >/tmp/lan_wan.out 2>/tmp/lan_wan.err
LAN_STATUS=$?
if [[ $LAN_STATUS -ne 0 ]]; then
  log "LAN->WAN failed (exit $LAN_STATUS):"; cat /tmp/lan_wan.err; exit 1
fi
log "LAN->WAN success (first line): $(head -n1 /tmp/lan_wan.out)"

log "Testing DNAT WAN:8081 -> LAN target:80 (from wan_server)..."
docker compose -f "$COMPOSE_FILE" exec -T wan_server curl -svf http://172.30.0.2:8081 >/tmp/wan_dnat.out 2>/tmp/wan_dnat.err
DNAT_STATUS=$?
if [[ $DNAT_STATUS -ne 0 ]]; then
  log "WAN DNAT failed (exit $DNAT_STATUS):"; cat /tmp/wan_dnat.err; exit 1
fi
log "WAN DNAT success (first line): $(head -n1 /tmp/wan_dnat.out)"

log "Testing WAN direct to LAN (should be blocked: wan_server -> 172.31.0.4:80)..."
if docker compose -f "$COMPOSE_FILE" exec -T wan_server curl -m 5 -sf http://172.31.0.4:80 >/tmp/wan_direct.out 2>/tmp/wan_direct.err; then
  log "Unexpected allow: wan_server reached 172.31.0.4:80"; exit 1
else
  log "WAN direct to LAN correctly blocked (exit $?)"
fi

log "Testing WAN direct to LAN SSH (should be blocked: wan_server -> 172.31.0.4:22)..."
if docker compose -f "$COMPOSE_FILE" exec -T wan_server sh -c "nc -z -w2 172.31.0.4 22" >/tmp/wan_direct_ssh.out 2>/tmp/wan_direct_ssh.err; then
  log "Unexpected allow: wan_server reached 172.31.0.4:22"; exit 1
else
  log "WAN SSH to LAN correctly blocked"
fi

log "Checking nft counters for NAT and forward paths..."
PRE_PKTS=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd prerouting | awk '/dnat ip to/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}')
POST_PKTS=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd postrouting | awk '/masquerade/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}')
FWD_LAN_WAN=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd forward | awk '/dport 8080/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}')
FWD_WAN_DNAT=$(docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft -ac list chain inet containd forward | awk '/dport 80/{for(i=1;i<NF;i++){if($i=="packets"){print $(i+1)}}}')
log "Counters: prerouting DNAT packets=$PRE_PKTS, postrouting masq packets=$POST_PKTS, forward lan->wan=$FWD_LAN_WAN, forward wan->lan=$FWD_WAN_DNAT"

log "Smoke test complete."
