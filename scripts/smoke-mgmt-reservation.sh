#!/usr/bin/env bash
set -euo pipefail
trap 'echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR

# A fully independent project: no published ports, shared images or host data.
ROOT=$(git rev-parse --show-toplevel)
PROJECT="containd-mgmt-c2-$(date +%s)-$$"
PREFIX=${MGMT_SMOKE_PREFIX:-10.217}
if [[ ! "$PREFIX" =~ ^10\.[0-9]{1,3}$ ]] || (( ${PREFIX#10.} > 255 )); then
  echo "MGMT_SMOKE_PREFIX must be 10.<0..255>" >&2
  exit 1
fi
mkdir -p "$ROOT/build"
SCRATCH=$(mktemp -d "$ROOT/build/mgmt-reservation.XXXXXX")
COMPOSE="$SCRATCH/compose.yml"
IMAGE="containd-mgmt-reservation:$PROJECT"
compose() { docker compose -p "$PROJECT" -f "$COMPOSE" "$@"; }
cleanup() {
  local status=$?
  trap - EXIT
  compose logs --no-color >"$SCRATCH/compose.log" 2>&1 || status=1
  compose down --volumes --remove-orphans || status=1
  echo "Diagnostics: $SCRATCH"
  exit "$status"
}

ARCH=$(docker info --format '{{.Architecture}}')
case "$ARCH" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "Unsupported Docker architecture: $ARCH" >&2; exit 1 ;;
esac
GOFLAGS=-mod=mod GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
  go build -o "$SCRATCH/containd" ./cmd/containd
cp "$ROOT/test/mgmt-reservation/entrypoint.sh" "$SCRATCH/entrypoint.sh"
docker build -f "$ROOT/test/mgmt-reservation/Dockerfile" -t "$IMAGE" "$SCRATCH"

cat >"$COMPOSE" <<EOF
services:
  containd:
    image: $IMAGE
    user: "0"
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]
    environment:
      MGMT_SMOKE_PREFIX: "$PREFIX"
      CONTAIND_MGMT_RESERVATION: '{"subnet":"$PREFIX.4.0/24","sources":["$PREFIX.4.10","$PREFIX.4.3"],"listen":":8080"}'
      CONTAIND_ENGINE_ADDR: "127.0.0.1:8081"
      CONTAIND_ENGINE_URL: "http://127.0.0.1:8081"
      CONTAIND_MGMT_ADDR: ":8080"
      CONTAIND_ENFORCE_ENABLED: "1"
      CONTAIND_LAB_MODE: "1"
      CONTAIND_JWT_SECRET: "isolated-management-smoke-secret-not-for-production"
      CONTAIND_CONFIG_DB: "/data/config.db"
      CONTAIND_AUDIT_DB: "/data/audit.db"
      CONTAIND_USERS_DB: "/data/users.db"
EOF
NAMES=(wan dmz lan1 lan2 lan3 lan4 lan5 lan6)
for i in "${!NAMES[@]}"; do
  name=${NAMES[$i]}
  upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
  printf '      CONTAIND_AUTO_%s_SUBNET: "%s.%s.0/24"\n' "$upper" "$PREFIX" "$i" >>"$COMPOSE"
done
cat >>"$COMPOSE" <<EOF
    volumes: [data:/data]
    networks:
EOF
for i in "${!NAMES[@]}"; do
  printf '      %s:\n        ipv4_address: %s.%s.2\n' "${NAMES[$i]}" "$PREFIX" "$i" >>"$COMPOSE"
done
for spec in source:10 proxy:3 outsider:11; do
  name=${spec%:*}
  ip=${spec#*:}
  cat >>"$COMPOSE" <<EOF
  $name:
    image: curlimages/curl:8.11.1
    entrypoint: ["/bin/sh", "-c"]
    command: ["sleep infinity"]
    networks:
      lan3:
        ipv4_address: $PREFIX.4.$ip
EOF
done
printf 'volumes:\n  data:\nnetworks:\n' >>"$COMPOSE"
for i in "${!NAMES[@]}"; do
  printf '  %s:\n    internal: true\n    ipam:\n      config:\n        - subnet: %s.%s.0/24\n' "${NAMES[$i]}" "$PREFIX" "$i" >>"$COMPOSE"
done
trap cleanup EXIT
compose up -d
BASE="http://$PREFIX.4.2:8080/api/v1"
peer() { compose exec -T "$1" curl --silent --show-error --max-time 5 --connect-timeout 2 "${@:2}"; }
wait_ready() {
  local ready=0
  for _ in $(seq 1 60); do
    if peer source --fail "$BASE/health" >"$SCRATCH/health.json" 2>"$SCRATCH/wait.err"; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo "management never became ready" >&2; return 1; }
}
login() {
  TOKEN=$(peer source --fail -H 'Content-Type: application/json' \
    -d '{"username":"containd","password":"containd"}' "$BASE/auth/login" | jq -er '.token')
}
api() { peer source --fail -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
assert_reachability() {
  peer source --fail "$BASE/health" >"$SCRATCH/source.json"
  peer proxy --fail "$BASE/health" >"$SCRATCH/proxy.json"
  if peer outsider --fail "$BASE/health" >"$SCRATCH/outsider.json" 2>"$SCRATCH/outsider.err"; then
    echo "non-source still reaches management" >&2
    return 1
  fi
  api "$BASE/system/management-reservation" >"$SCRATCH/reservation.json"
  jq -e '.active and .guard.active and ((.guard.error // "") == "")' "$SCRATCH/reservation.json" >/dev/null
}
reject_address() {
  # Docker may renumber NICs on restart. Derive this negative case from the
  # current boot authority and config, not from a cached pre-restart device.
  api "$BASE/system/management-reservation" >"$SCRATCH/reservation.json"
  api "$BASE/config" >"$SCRATCH/current.json"
  local device
  device=$(jq -er '.device' "$SCRATCH/reservation.json")
  jq '(.interfaces[] | select(.device == $device)).addresses = ["192.0.2.2/24"]' \
    --arg device "$device" "$SCRATCH/current.json" >"$SCRATCH/unsafe.json"
  local status
  status=$(peer source -o /tmp/rejection.json -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' --data-binary @- "$BASE/config/candidate" <"$SCRATCH/unsafe.json")
  [[ "$status" == 400 ]] || { echo "unsafe substrate accepted: HTTP $status" >&2; return 1; }
  compose exec -T source cat /tmp/rejection.json >"$SCRATCH/rejection.json"
  jq -e '.error | contains("reserved management path")' "$SCRATCH/rejection.json" >/dev/null
}
wait_ready
login
# A reachable outsider before the edit proves the negative test isn't a bad peer.
peer outsider --fail "$BASE/health" >"$SCRATCH/outsider-before.json"
api "$BASE/config" >"$SCRATCH/running.json"
jq '.interfaces |= map(.access = {mgmt:false,http:false,https:false,ssh:false}) | (.interfaces[] | select(.name == "lan4")).addresses = ["192.0.2.14/24"]' \
  "$SCRATCH/running.json" >"$SCRATCH/disabled.json"
api --data-binary @- "$BASE/config/candidate" <"$SCRATCH/disabled.json" >"$SCRATCH/stage.json"
api -D /tmp/commit.headers -X POST "$BASE/config/commit" >"$SCRATCH/commit.json"
compose exec -T source cat /tmp/commit.headers >"$SCRATCH/commit.headers"
jq -e '.status == "committed"' "$SCRATCH/commit.json" >/dev/null
if grep -qi '^X-Containd-Warnings:' "$SCRATCH/commit.headers"; then
  echo "commit applied with runtime warnings; see $SCRATCH/commit.headers" >&2
  exit 1
fi
assert_reachability
reject_address
OLD_DEVICE=$(jq -er '.device' "$SCRATCH/reservation.json")
compose exec -T containd sh -c 'echo 1 >/data/nic-generation'
compose restart containd
wait_ready
login
assert_reachability
reject_address
api "$BASE/config" >"$SCRATCH/restarted.json"
jq -e --arg old "$OLD_DEVICE" '.device != $old and (.bootFault == "")' "$SCRATCH/reservation.json" >/dev/null
jq -e 'all(.interfaces[]; .access.mgmt == false and .access.http == false and .access.https == false and .access.ssh == false)' \
  "$SCRATCH/restarted.json" >/dev/null

# Deliberately bypass the API to model legacy stored conflicts, not an allowed
# student edit. A custom row must survive normalization and trigger recovery.
DEVICE=$(jq -er '.device' "$SCRATCH/reservation.json")
jq --arg device "$DEVICE" '
  (.interfaces[] | select(.device == $device)) |= (.name = "custom-reserved" | .addresses = ["192.0.2.77/24"]) |
  .system.mgmt.enableHTTP = false | .system.mgmt.httpListenAddr = ":9090" |
  .system.ssh.listenAddr = ":8080"
' "$SCRATCH/restarted.json" >"$SCRATCH/legacy-conflict.json"
inject_conflict() {
  compose exec -T containd sh -c \
    'cat >/tmp/legacy-conflict.json && sqlite3 /data/config.db "UPDATE configs SET data=readfile('\''/tmp/legacy-conflict.json'\'') WHERE key='\''running'\''"' \
    <"$SCRATCH/legacy-conflict.json"
  compose restart containd
  wait_ready
  login
  assert_reachability
  jq -e '.bootFault | contains("reserved management path")' "$SCRATCH/reservation.json" >/dev/null
}
assert_no_apply() {
  compose exec -T containd curl -fsS http://127.0.0.1:8081/internal/ruleset_status >"$SCRATCH/fault-ruleset.json"
  jq -e '.ruleset == "" and .appliedAt == "0001-01-01T00:00:00Z"' "$SCRATCH/fault-ruleset.json" >/dev/null
  compose exec -T containd nft list ruleset >"$SCRATCH/fault-nft.txt"
  # Docker's DNS NAT chains exist even in a fresh namespace. The invariant is
  # no appliance firewall table, not no unrelated kernel tables.
  compose exec -T containd nft -j list tables >"$SCRATCH/fault-tables.json"
  jq -e '[.nftables[] | .table? | select(.name == "containd")] | length == 0' "$SCRATCH/fault-tables.json" >/dev/null
}
inject_conflict
assert_no_apply
sleep 3
assert_no_apply
api "$BASE/events?limit=100" >"$SCRATCH/fault-events.json"
jq -e '[.[] | select(.kind == "management.reservation.boot_fault")] | length == 1' "$SCRATCH/fault-events.json" >/dev/null
api "$BASE/config" >"$SCRATCH/fault-config.json"
jq -e '.system.mgmt.enableHTTP == false and .system.mgmt.httpListenAddr == ":9090" and any(.interfaces[]; .name == "custom-reserved" and .addresses == ["192.0.2.77/24"])' \
  "$SCRATCH/fault-config.json" >/dev/null
api --data-binary @- "$BASE/config/candidate" <"$SCRATCH/restarted.json" >"$SCRATCH/recovery-stage.json"
api -X POST "$BASE/config/commit" >"$SCRATCH/recovery-commit.json"
api "$BASE/system/management-reservation" >"$SCRATCH/recovered.json"
jq -e '.bootFault == ""' "$SCRATCH/recovered.json" >/dev/null
compose exec -T containd curl -fsS http://127.0.0.1:8081/internal/ruleset_status >"$SCRATCH/recovered-ruleset.json"
jq -e '.ruleset | length > 0' "$SCRATCH/recovered-ruleset.json" >/dev/null

# Factory reset is a second recovery path, using the same autobound defaults as
# first boot. It must work under a valid reservation and revoke the session.
inject_conflict
assert_no_apply
api -d '{"confirm":"NUCLEAR"}' "$BASE/system/factory-reset" >"$SCRATCH/reset.json"
jq -e '.status == "reset" and .loggedOut' "$SCRATCH/reset.json" >/dev/null
login
api "$BASE/system/management-reservation" >"$SCRATCH/reset-reservation.json"
jq -e '.bootFault == ""' "$SCRATCH/reset-reservation.json" >/dev/null
api "$BASE/config" >"$SCRATCH/reset-config.json"
jq -e --arg device "$DEVICE" '[.interfaces[] | select(.device == $device)] | length == 1 and all(.[]; (.addresses // [] | length) == 0 and (.addressMode // "static") == "static")' \
  "$SCRATCH/reset-config.json" >/dev/null
echo "PASS: reserved health/login, all-access-off commit, exact-source access, rejection, NIC renumber, fault/no apply, safe commit and factory reset recovery"
