#!/usr/bin/env bash
set -euo pipefail

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
docker build -f "$ROOT/test/mgmt-reservation/Dockerfile" -t "$IMAGE" "$SCRATCH"

cat >"$COMPOSE" <<EOF
services:
  containd:
    image: $IMAGE
    user: "0"
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]
    environment:
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
jq '.interfaces |= map(.access = {mgmt:false,http:false,https:false,ssh:false})' \
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
compose restart containd
wait_ready
login
assert_reachability
reject_address
api "$BASE/config" >"$SCRATCH/restarted.json"
jq -e 'all(.interfaces[]; .access.mgmt == false and .access.http == false and .access.https == false and .access.ssh == false)' \
  "$SCRATCH/restarted.json" >/dev/null
echo "PASS: reserved health/login, all-access-off commit, exact-source access, substrate rejection, restart"
