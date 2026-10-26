#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR

# A fully independent project: no published ports, shared images or host data.
ROOT=$(git rev-parse --show-toplevel)
PROJECT="containd-mgmt-c3-$(date +%s)-$$"
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
  if (( status != 0 )); then
    for service in containd transit-source transit-target; do
      compose exec -T "$service" sh -c 'ip -4 addr; ip -4 route; ip rule; cat /proc/sys/net/ipv4/ip_forward; nft list ruleset' \
        >"$SCRATCH/$service-network.txt" 2>&1 || true
    done
  fi
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
    sysctls:
      net.ipv4.ip_forward: "1"
    environment:
      MGMT_SMOKE_PREFIX: "$PREFIX"
      CONTAIND_MGMT_RESERVATION: '{"subnet":"$PREFIX.4.0/24","sources":["$PREFIX.4.10","$PREFIX.4.3"],"listen":":8080"}'
      CONTAIND_ENGINE_ADDR: "127.0.0.1:8081"
      CONTAIND_ENGINE_URL: "http://127.0.0.1:8081"
      CONTAIND_MGMT_ADDR: ":8080"
      CONTAIND_SSH_ADDR: ":18222"
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
cat >>"$COMPOSE" <<EOF
  transit-source:
    image: $IMAGE
    cap_add: [NET_ADMIN]
    entrypoint: ["/bin/sh", "-c"]
    command: ["ip route flush default && ip route replace $PREFIX.3.0/24 via $PREFIX.2.2 && sleep infinity"]
    networks:
      lan1:
        ipv4_address: $PREFIX.2.10
  transit-target:
    image: $IMAGE
    cap_add: [NET_ADMIN]
    entrypoint: ["/bin/sh", "-c"]
    command: ["ip route flush default && ip route replace $PREFIX.2.0/24 via $PREFIX.3.2 && exec python3 -m http.server 18082"]
    networks:
      lan2:
        ipv4_address: $PREFIX.3.10
EOF
printf 'volumes:\n  data:\nnetworks:\n' >>"$COMPOSE"
for i in "${!NAMES[@]}"; do
  internal=true
  # Docker's internal bridge host filter also drops legitimate cross-subnet
  # frames routed through an appliance. Transit bridges instead have no
  # masquerading and every attached namespace has its default route removed.
  if [[ "${NAMES[$i]}" == lan1 || "${NAMES[$i]}" == lan2 ]]; then internal=false; fi
  printf '  %s:\n    internal: %s\n    driver_opts:\n      com.docker.network.bridge.enable_ip_masquerade: "false"\n    ipam:\n      config:\n        - subnet: %s.%s.0/24\n' "${NAMES[$i]}" "$internal" "$PREFIX" "$i" >>"$COMPOSE"
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
# An explicit narrow allow, not default allow, proves the transit fixture works
# before the fault and that a safe commit replaces recovery enforcement.
jq --arg source "$PREFIX.2.10/32" --arg target "$PREFIX.3.10/32" '
  .firewall.defaultAction = "DENY" |
  .firewall.rules += [{id:"smoke-transit", sources:[$source], destinations:[$target],
    protocols:[{name:"tcp",port:"18082"}], action:"ALLOW"}]
' "$SCRATCH/disabled.json" >"$SCRATCH/transit-allowed.json"
api --data-binary @- "$BASE/config/candidate" <"$SCRATCH/transit-allowed.json" >"$SCRATCH/stage.json"
api -D /tmp/commit.headers -X POST "$BASE/config/commit" >"$SCRATCH/commit.json"
compose exec -T source cat /tmp/commit.headers >"$SCRATCH/commit.headers"
jq -e '.status == "committed"' "$SCRATCH/commit.json" >/dev/null
if grep -qi '^X-Containd-Warnings:' "$SCRATCH/commit.headers"; then
  echo "commit applied with runtime warnings; see $SCRATCH/commit.headers" >&2
  exit 1
fi
assert_reachability
transit() { peer transit-source --fail "http://$PREFIX.3.10:18082/"; }
transit >"$SCRATCH/transit-before.txt"
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
  local ready=0
  for _ in $(seq 1 20); do
    api "$BASE/system/management-reservation" >"$SCRATCH/reservation.json"
    if jq -e '.recovery == "recovery: new transit dropped"' "$SCRATCH/reservation.json" >/dev/null; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo "recovery ruleset never applied" >&2; return 1; }
}
assert_recovery() {
  # A broken target must not masquerade as a firewall drop.
  compose exec -T transit-target curl -fsS http://127.0.0.1:18082/ >"$SCRATCH/transit-target-ready.txt"
  compose exec -T containd curl -fsS http://127.0.0.1:8081/internal/ruleset_status >"$SCRATCH/fault-ruleset.json"
  jq -e '(.ruleset | contains("policy drop")) and (.appliedAt != "0001-01-01T00:00:00Z") and ((.error // "") == "")' "$SCRATCH/fault-ruleset.json" >/dev/null
  compose exec -T containd nft list ruleset >"$SCRATCH/fault-nft.txt"
  api "$BASE/system/management-reservation" >"$SCRATCH/reservation.json"
  jq -e '.recovery == "recovery: new transit dropped"' "$SCRATCH/reservation.json" >/dev/null
  compose exec -T containd curl -fsS http://127.0.0.1:8081/internal/config >"$SCRATCH/recovery-dataplane.json"
  jq -e '.enforcement and ((.captureInterfaces // [] | length) == 0) and (.dpiEnabled | not)' "$SCRATCH/recovery-dataplane.json" >/dev/null
  if transit >"$SCRATCH/transit-fault.txt" 2>"$SCRATCH/transit-fault.err"; then
    echo "new transit passed during recovery" >&2
    return 1
  fi
}
inject_conflict
assert_recovery
cp "$SCRATCH/fault-ruleset.json" "$SCRATCH/first-recovery-ruleset.json"
sleep 3
assert_recovery
jq -e --slurpfile first "$SCRATCH/first-recovery-ruleset.json" '.appliedAt == $first[0].appliedAt' "$SCRATCH/fault-ruleset.json" >/dev/null
api "$BASE/events?limit=100" >"$SCRATCH/fault-events.json"
jq -e '[.[] | select(.kind == "management.reservation.boot_fault")] | length == 1' "$SCRATCH/fault-events.json" >/dev/null
api "$BASE/config" >"$SCRATCH/fault-config.json"
jq -e '.system.mgmt.enableHTTP == false and .system.mgmt.httpListenAddr == ":9090" and any(.interfaces[]; .name == "custom-reserved" and .addresses == ["192.0.2.77/24"])' \
  "$SCRATCH/fault-config.json" >/dev/null
api --data-binary @- "$BASE/config/candidate" <"$SCRATCH/restarted.json" >"$SCRATCH/recovery-stage.json"
api -X POST "$BASE/config/commit" >"$SCRATCH/recovery-commit.json"
api "$BASE/system/management-reservation" >"$SCRATCH/recovered.json"
jq -e '.bootFault == "" and .recovery == ""' "$SCRATCH/recovered.json" >/dev/null
transit >"$SCRATCH/transit-recovered.txt"
compose exec -T containd curl -fsS http://127.0.0.1:8081/internal/ruleset_status >"$SCRATCH/recovered-ruleset.json"
jq -e '.ruleset | length > 0' "$SCRATCH/recovered-ruleset.json" >/dev/null

# Factory reset is a second recovery path, using the same autobound defaults as
# first boot. It must work under a valid reservation and revoke the session.
inject_conflict
assert_recovery
api -d '{"confirm":"NUCLEAR"}' "$BASE/system/factory-reset" >"$SCRATCH/reset.json"
jq -e '.status == "reset" and .loggedOut' "$SCRATCH/reset.json" >/dev/null
login
api "$BASE/system/management-reservation" >"$SCRATCH/reset-reservation.json"
jq -e '.bootFault == "" and .recovery == ""' "$SCRATCH/reset-reservation.json" >/dev/null
api "$BASE/config" >"$SCRATCH/reset-config.json"
jq -e --arg device "$DEVICE" '[.interfaces[] | select(.device == $device)] | length == 1 and all(.[]; (.addresses // [] | length) == 0 and (.addressMode // "static") == "static")' \
  "$SCRATCH/reset-config.json" >/dev/null

# Syntactically valid but not local: optional HTTPS must not crash-loop mgmt.
jq '.system.mgmt.enableHTTPS = true | .system.mgmt.httpsListenAddr = "192.0.2.250:18443"' \
  "$SCRATCH/reset-config.json" >"$SCRATCH/unbindable-listener.json"
api --data-binary @- "$BASE/config/candidate" <"$SCRATCH/unbindable-listener.json" >"$SCRATCH/listener-stage.json"
api -X POST "$BASE/config/commit" >"$SCRATCH/listener-commit.json"
compose restart containd
wait_ready
login
api "$BASE/system/management-reservation" >"$SCRATCH/listener-fault.json"
jq -e '.active and any(.listenerFaults[]; contains("192.0.2.250:18443"))' "$SCRATCH/listener-fault.json" >/dev/null
peer proxy --fail "$BASE/health" >"$SCRATCH/listener-proxy.json"
echo "PASS: reserved health/login, all-access-off commit, exact-source access, rejection, NIC renumber, fail-closed recovery/new transit dropped, safe commit/reset, optional-listener boot fault"
