#!/usr/bin/env bash
# Functional check on the smoke stack (run after smoke-forward.sh has set up
# devices + routes): enable nflog group 100, add a logged DENY rule for
# lan_client -> wan_server:8082, commit N times back-to-back through the mgmt
# API (the real Reconfigure+Start path), then probe and expect
# firewall.rule.hit events and no service.nflog.unavailable.
set -euo pipefail
BASE=${BASE:-http://localhost:18080/api/v1}
ENGINE=${ENGINE:-http://localhost:18081}
TOKEN=${TOKEN:-devtoken}
COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.smoke.yml}
COMMITS=${1:-8}
AUTH="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 10"
CFG=$($CURL -H "$AUTH" "$BASE/config")
NEW=$(echo "$CFG" | jq '
  .dataPlane.nflogGroup = 100
  | .firewall.rules = ([ .firewall.rules[]? | select(.id != "deny-lan-log") ] + [{
      id:"deny-lan-log", sourceZones:["lan"], destZones:["wan"], sources:["172.31.0.3/32"],
      protocols:[{name:"tcp", port:"8082"}], action:"DENY", log:true }])')
echo "$NEW" | $CURL -H "$AUTH" -H 'Content-Type: application/json' -X POST "$BASE/config/candidate" --data-binary @- >/dev/null
for n in $(seq 1 "$COMMITS"); do
  $CURL -H "$AUTH" -X POST "$BASE/config/commit" -o /dev/null -w "commit $n -> %{http_code}\n"
done
sleep 1
docker compose -f "$COMPOSE_FILE" exec -T engine /usr/sbin/nft list chain inet containd forward | grep -E 'log prefix' || { echo "no log clause in forward chain"; exit 1; }
for _ in 1 2 3; do docker compose -f "$COMPOSE_FILE" exec -T lan_client curl -m 3 -s http://172.30.0.3:8082 >/dev/null 2>&1 || true; done
sleep 1
EV=$($CURL "$ENGINE/internal/events?limit=500")
hits=$(echo "$EV" | jq '[.[]|select(.kind=="firewall.rule.hit" and .attributes.ruleId=="deny-lan-log")]|length')
unavail=$(echo "$EV" | jq '[.[]|select(.kind=="service.nflog.unavailable")]|length')
echo "rule hits: $hits   nflog unavailable events: $unavail"
[ "$hits" -gt 0 ] && [ "$unavail" -eq 0 ]
