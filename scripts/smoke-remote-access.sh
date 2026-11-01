#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live Linux-kernel OpenVPN/WireGuard safety checks. See test/remote-access.
set -euo pipefail
umask 077

ROOT=$(git rev-parse --show-toplevel)
REV=$(git rev-parse --short HEAD)
SMOKE_PROJECT=rasmoke
COMPOSE_FILE="$ROOT/test/remote-access/compose.yml"
RA_IMAGE="containd/containd:rasmoke-$REV"
RA_CLIENT_IMAGE="containd/remote-access-client:rasmoke-$REV"
RA_WORK=$(mktemp -d "${TMPDIR:-/tmp}/rasmoke.XXXXXX")
RA_LOG_DIR=${RA_LOG_DIR:-"$ROOT/build/remote-access/$(date -u +%Y%m%dT%H%M%SZ)-$$"}
export RA_IMAGE RA_CLIENT_IMAGE RA_WORK
mkdir -p "$RA_LOG_DIR"
# shellcheck source=scripts/smoke-lib.sh
source "$ROOT/scripts/smoke-lib.sh"
# shellcheck source=scripts/config-revision.sh
source "$ROOT/scripts/config-revision.sh"
RA_REVISION="$RA_WORK/config.revision"

ACTIVE=0
CHECK=prerequisites
PASSED=0
API_COUNT=0
FAILED=0
log() { printf '%s\n' "$*"; }
fail() { FAILED=1; log "FAIL [$CHECK]: $*"; exit 1; }
pass() { log "PASS [$CHECK]: $*"; PASSED=$((PASSED + 1)); }
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ $rc -ne 0 && $FAILED == 0 ]]; then
    log "FAIL [$CHECK]: harness command failed (exit $rc)"
    rc=2
  fi
  if [[ $ACTIVE == 1 ]]; then
    compose logs --no-color >"$RA_LOG_DIR/compose.log" 2>&1 || rc=2
    compose exec -T engine nft list ruleset >"$RA_LOG_DIR/nft.txt" 2>&1 || rc=2
    compose exec -T engine ip -details addr >"$RA_LOG_DIR/links.txt" 2>&1 || rc=2
    for service in client_a client_b; do
      compose exec -T "$service" cat /tmp/openvpn.log >"$RA_LOG_DIR/$service.log" 2>&1 || true
    done
    compose down --volumes --remove-orphans >"$RA_LOG_DIR/cleanup.log" 2>&1 || rc=2
  fi
  # Do not retain private keys/profiles. The directory itself is harmless.
  find "$RA_WORK" -type f -exec sh -c ': > "$1"' _ {} \;
  log "Result: $PASSED/7 checks passed; exit $rc; evidence $RA_LOG_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 2' INT TERM

for tool in docker curl jq; do
  command -v "$tool" >/dev/null || { log "missing $tool"; exit 2; }
done
docker info >/dev/null
if [[ -n $(docker ps -aq --filter label=com.docker.compose.project=rasmoke) ||
      -n $(docker network ls -q --filter label=com.docker.compose.project=rasmoke) ||
      -n $(docker volume ls -q --filter label=com.docker.compose.project=rasmoke) ]]; then
  log "refusing to touch an existing rasmoke project"
  exit 2
fi
docker build --build-arg "COMMIT=$(git rev-parse HEAD)" \
  -f "$ROOT/build/Dockerfile.mgmt" -t "$RA_IMAGE" "$ROOT" >"$RA_LOG_DIR/build.log" 2>&1
docker build -t "$RA_CLIENT_IMAGE" "$ROOT/test/remote-access" >"$RA_LOG_DIR/client-build.log" 2>&1
ACTIVE=1
compose up -d engine client_a client_b peer target inspect
BASE="https://$(compose port engine 8443)/api/v1"
ENGINE=$(compose ps -q engine)
TOKEN=$(compose exec -T client_a python3 - <"$ROOT/test/remote-access/mint-token.py")

wait_api() {
  local i
  for ((i=0; i<60; i++)); do
    if curl -ksSf --max-time 2 "$BASE/health" >/dev/null 2>&1; then return; fi
    sleep 2
  done
  fail "management did not become ready"
}
# Preserve status and response; never commit after a rejected candidate save.
api() {
  local method=$1 path=$2 body=${3:-} expected=${4:-200} code
  local -a request=(curl)
  case "$method $path" in
    "GET /config"|"GET /services/vpn")
      request=(cas_read "$RA_REVISION" curl)
      ;;
    "POST /config"|"POST /services/vpn"|"POST /config/commit"|"POST /services/vpn/openvpn/profile")
      request=(cas_write "$RA_REVISION" curl)
      ;;
  esac
  API_COUNT=$((API_COUNT + 1))
  code=$("${request[@]}" -ksS --max-time 60 -o "$RA_LOG_DIR/api-$API_COUNT.body" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -X "$method" --data-binary "$body" "$BASE$path")
  RESPONSE=$(cat "$RA_LOG_DIR/api-$API_COUNT.body")
  log "API $method $path HTTP $code (api-$API_COUNT.body)"
  [[ $code == "$expected" ]] || fail "$method $path: expected $expected, got $code: $RESPONSE"
}
commit() {
  api POST /config/commit
  jq -e '.status == "committed"' <<<"$RESPONSE" >/dev/null || fail "not committed: $RESPONSE"
}
refresh_engine() {
  # Docker assigns a new ephemeral host port and netns on container restart.
  BASE="https://$(compose port engine 8443)/api/v1"
  compose up -d --no-deps --force-recreate inspect
  wait_api
}
restart() {
  docker restart "$ENGINE" >"$RA_LOG_DIR/restart-$CHECK.txt"
  refresh_engine
}
wait_ping() {
  local service=$1 dest=$2 i
  for ((i=0; i<30; i++)); do
    if compose exec -T "$service" ping -c 1 -W 1 "$dest" >>"$RA_LOG_DIR/ping.txt" 2>&1; then return; fi
    sleep 1
  done
  fail "$service cannot ping $dest"
}
start_client() {
  local service=$1 profile=$2
  compose exec -T "$service" sh -c ': > /tmp/openvpn.log'
  compose exec -d "$service" openvpn --config "/work/$profile.ovpn" \
    --log /tmp/openvpn.log --hand-window 8 --tls-exit
}
stop_client() {
  local service=$1
  compose exec -T "$service" sh -c 'if pgrep -x openvpn >/dev/null; then pkill -TERM -x openvpn; fi'
  sleep 2
}
connect_client() {
  local service=$1 profile=$2 i
  start_client "$service" "$profile"
  for ((i=0; i<45; i++)); do
    if compose exec -T "$service" grep -q 'Initialization Sequence Completed' /tmp/openvpn.log; then
      wait_ping "$service" 10.250.2.3
      return
    fi
    sleep 1
  done
  fail "$service OpenVPN handshake failed"
}
revoked_client() {
  local label=$1 i since
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  start_client client_a a
  for ((i=0; i<20; i++)); do
    if compose exec -T client_a grep -q 'TLS Error' /tmp/openvpn.log; then break; fi
    sleep 1
  done
  compose exec -T client_a cat /tmp/openvpn.log >"$RA_LOG_DIR/revoked-$label.log"
  if grep -q 'Initialization Sequence Completed' "$RA_LOG_DIR/revoked-$label.log"; then
    fail "revoked credential connected"
  fi
  grep -q 'TLS Error' "$RA_LOG_DIR/revoked-$label.log" || fail "no TLS rejection observed"
  docker logs --since "$since" "$ENGINE" >"$RA_LOG_DIR/server-$label.log" 2>&1
  grep -qi 'certificate revoked' "$RA_LOG_DIR/server-$label.log" || fail "no server CRL rejection observed"
  stop_client client_a
}
wg_ping() {
  local i handshake
  wait_ping peer 10.250.2.3
  for ((i=0; i<10; i++)); do
    handshake=$(compose exec -T peer wg show ra-peer latest-handshakes)
    printf '%s\n' "$handshake" >>"$RA_LOG_DIR/handshakes.txt"
    if awk '$2 > 0 {ok=1} END {exit !ok}' <<<"$handshake"; then return; fi
    sleep 1
  done
  fail "WireGuard latest-handshake is unset"
}
vpn_files() {
  compose exec -T engine sh -c 'find /data/openvpn -type f -exec sha256sum {} \;' | LC_ALL=C sort
}

wait_api
CHECK=https-only
api GET /interfaces/state
WAN=$(jq -r 'map(select(any(.addrs[]?; startswith("10.250.1.2/"))))[0].name // empty' <<<"$RESPONSE")
LAN=$(jq -r 'map(select(any(.addrs[]?; startswith("10.250.2.2/"))))[0].name // empty' <<<"$RESPONSE")
[[ -n $WAN && -n $LAN ]] || fail "cannot discover appliance WAN/LAN devices"
api GET /config
CFG=$(jq --arg wan "$WAN" --arg lan "$LAN" '
  .interfaces |= map(if .name=="wan" then .device=$wan
    elif .name=="lan1" then .device=$lan | .zone="lan" else . end)
  | .system.mgmt.enableHTTP=false | .system.mgmt.enableHTTPS=true
  | .dataplane.enforcement=true | .dataplane.enforceTable="containd"
  | .firewall.defaultAction="DENY" | .firewall.nat.enabled=false
  | .firewall.rules=[{id:"vpn-to-target", sources:["vpn:any"],
      destinations:["10.250.2.3/32"], action:"ALLOW"}]
' <<<"$RESPONSE")
api POST /config "$CFG"
commit
restart
api GET /health
PLAIN=$(curl -sS --max-time 5 -o "$RA_LOG_DIR/plaintext.body" -w '%{http_code}' \
  "${BASE/https:/http:}/health")
[[ $PLAIN == 400 ]] || fail "TLS port served unexpected plaintext status $PLAIN"
grep -q 'HTTP request to an HTTPS server' "$RA_LOG_DIR/plaintext.body" || fail "unexpected plaintext response"
pass "HTTPS answers; plaintext on its port cannot serve the API"

CHECK=openvpn-server
compose exec -T target ip route replace default via 10.250.2.2
compose exec -T inspect ping -c 1 -W 2 10.250.2.3
api GET /services/vpn
api POST /services/vpn '{"openvpn":{"enabled":true,"mode":"server","server":{"listenPort":1194,"proto":"udp","listenZone":"wan","tunnelCIDR":"10.250.10.0/24","publicEndpoint":"10.250.1.2","pushRoutes":["10.250.2.0/24"]}},"wireguard":{"enabled":false}}'
commit
api POST /services/vpn/openvpn/clients '{"name":"smoke-a"}'
ID_A=$(jq -er '.id' <<<"$RESPONSE")
api GET "/services/vpn/openvpn/clients/$ID_A"
printf '%s\n' "$RESPONSE" >"$RA_WORK/a.ovpn"
connect_client client_a a
pass "issued API credential and downloaded profile; handshake and routed ping work"

CHECK=revoke
api POST "/services/vpn/openvpn/clients/$ID_A/revoke"
jq -e '.revoked == true and .applied == true' <<<"$RESPONSE" >/dev/null || fail "CRL not applied"
stop_client client_a
revoked_client initial
api POST /services/vpn/openvpn/clients '{"name":"smoke-b"}'
ID_B=$(jq -er '.id' <<<"$RESPONSE")
api GET "/services/vpn/openvpn/clients/$ID_B"
printf '%s\n' "$RESPONSE" >"$RA_WORK/b.ovpn"
connect_client client_b b
pass "same revoked profile rejected by CRL; unrevoked client still handshakes and pings"

CHECK=wireguard
compose exec -T inspect ip link add ra-foreign type wireguard
compose exec -T inspect ip addr add 10.250.30.1/24 dev ra-foreign
FOREIGN=$(compose exec -T inspect ip -j -details link show ra-foreign | jq -c '.[0] | {ifindex,ifname,linkinfo}')
compose exec -T peer sh -ec 'umask 077; wg genkey > /work/peer.key; wg pubkey < /work/peer.key > /work/peer.pub; wg genkey > /work/server.key; wg pubkey < /work/server.key > /work/server.pub'
WG_PRIVATE=$(cat "$RA_WORK/server.key")
PEER_PUBLIC=$(cat "$RA_WORK/peer.pub")
SERVER_PUBLIC=$(cat "$RA_WORK/server.pub")
api GET /services/vpn
VPN=$(jq --arg key "$WG_PRIVATE" --arg peer "$PEER_PUBLIC" '
  .wireguard={enabled:true,interface:"ra-owned",listenPort:51820,listenZone:"wan",
    addressCIDR:"10.250.20.1/24",privateKey:$key,
    peers:[{name:"smoke-peer",publicKey:$peer,allowedIPs:["10.250.20.2/32"]}]}' <<<"$RESPONSE")
api POST /services/vpn "$VPN"
commit
compose exec -T peer ip link add ra-peer type wireguard
compose exec -T peer ip addr add 10.250.20.2/24 dev ra-peer
compose exec -T peer wg set ra-peer private-key /work/peer.key peer "$SERVER_PUBLIC" \
  endpoint 10.250.1.2:51820 allowed-ips 10.250.2.0/24,10.250.20.0/24 persistent-keepalive 1
compose exec -T peer ip link set ra-peer up
compose exec -T peer ip route add 10.250.2.0/24 dev ra-peer
wg_ping
api POST /services/vpn "$(jq '.wireguard.enabled=false' <<<"$VPN")"
commit
if compose exec -T inspect ip link show ra-owned >"$RA_LOG_DIR/disabled-link.txt" 2>&1; then fail "owned link survived disable"; fi
[[ $(compose exec -T inspect ip -j -details link show ra-foreign | jq -c '.[0] | {ifindex,ifname,linkinfo}') == "$FOREIGN" ]] || fail "foreign link changed"
api POST /services/vpn "$VPN"
commit
wg_ping
pass "kernel handshake and routed ping; disable removes owned link, preserves foreign link"

CHECK=restart
api GET /services/vpn
VPN_BEFORE=$(jq -Sc . <<<"$RESPONSE")
api GET /services/vpn/openvpn/clients
INVENTORY_BEFORE=$(jq -Sc . <<<"$RESPONSE")
vpn_files >"$RA_LOG_DIR/material-before.txt"
stop_client client_b
restart
api GET /services/vpn
[[ $(jq -Sc . <<<"$RESPONSE") == "$VPN_BEFORE" ]] || fail "VPN config changed on restart"
api GET /services/vpn/openvpn/clients
[[ $(jq -Sc . <<<"$RESPONSE") == "$INVENTORY_BEFORE" ]] || fail "credential inventory changed"
vpn_files >"$RA_LOG_DIR/material-after.txt"
cmp "$RA_LOG_DIR/material-before.txt" "$RA_LOG_DIR/material-after.txt" || fail "CA/client/server material changed"
api GET "/services/vpn/openvpn/clients/$ID_B"
[[ $RESPONSE == "$(cat "$RA_WORK/b.ovpn")" ]] || fail "issued client profile changed"
connect_client client_b b
wg_ping
revoked_client restart
pass "both transports restored; config, credentials and CA persist; revoked profile still rejected"

CHECK=fault-quarantine
# Operator APIs cannot add new faults. Model the stored pre-upgrade snapshot
# using the same running-row mutation as the store's installStoredFault test.
docker stop "$ENGINE" >"$RA_LOG_DIR/stop.txt"
compose run --rm --no-deps store >"$RA_LOG_DIR/stored-fault.txt"
docker start "$ENGINE" >"$RA_LOG_DIR/start.txt"
refresh_engine
api GET /services/status
jq -e '.wireguard.state=="faulted" and .wireguard.fault.kind=="config"
  and .wireguard.fault.service=="wireguard"
  and (.wireguard.fault.message | type=="string" and length>0)
  and any(.faults[]; .service=="wireguard" and .kind=="config")
  and .vpn.openvpn_running==true
  and (.openvpn.state // "")!="faulted"' <<<"$RESPONSE" >/dev/null || fail "incorrect service fault status: $RESPONSE"
if compose exec -T inspect ip link show ra-owned >"$RA_LOG_DIR/quarantine-link.txt" 2>&1; then fail "quarantined WireGuard link survives"; fi
stop_client client_b
connect_client client_b b
api GET /health
jq -e '.enforcement.state=="enforcing" and .managementRecovery.state=="inactive"' \
  <<<"$RESPONSE" >/dev/null || fail "firewall enforcement or management recovery health is wrong"
compose exec -T engine nft list table inet containd_policy >"$RA_LOG_DIR/quarantine-policy.txt"
# Route the non-VPN control probe through containd, not Docker's gateway.
# Otherwise inter-bridge isolation could impersonate the firewall's drop.
compose exec -T client_a ip route replace 10.250.2.0/24 via 10.250.1.2
compose exec -T client_a ip route get 10.250.2.3 >"$RA_LOG_DIR/deny-route.txt"
grep -q 'via 10.250.1.2 ' "$RA_LOG_DIR/deny-route.txt" || fail "deny probe does not traverse containd"
if compose exec -T client_a ping -c 2 -W 2 10.250.2.3 >"$RA_LOG_DIR/denied-ping.txt" 2>&1; then fail "non-VPN WAN traffic passed default-deny firewall"; fi
grep -q '100% packet loss' "$RA_LOG_DIR/denied-ping.txt" || fail "deny probe did not time out"
pass "only WireGuard faulted; UI fault fields visible; OpenVPN and default-deny enforcement survive"

CHECK=directive-injection
api GET /config
CANDIDATE_BEFORE=$(jq -Sc . <<<"$RESPONSE")
vpn_files >"$RA_LOG_DIR/injection-before.txt"
api POST /services/vpn/openvpn/profile "$(jq -n --rawfile ovpn "$ROOT/test/remote-access/forbidden.ovpn" '{name:"forbidden",ovpn:$ovpn}')" 400
api GET /config
[[ $(jq -Sc . <<<"$RESPONSE") == "$CANDIDATE_BEFORE" ]] || fail "rejected upload changed candidate"
vpn_files >"$RA_LOG_DIR/injection-after.txt"
cmp "$RA_LOG_DIR/injection-before.txt" "$RA_LOG_DIR/injection-after.txt" || fail "rejected upload wrote VPN files"
pass "forbidden directives rejected with 400; candidate and VPN files unchanged"
[[ $PASSED == 7 ]] || fail "incomplete check count"
