#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regression-test management reachability with 5/7/8 NICs and NIC renumbering,
# with and without a management reservation. Run from the repository root.
# Requirements: Go, Docker with a Linux kernel, jq, Python 3 and image/package
# download access; containers need NET_ADMIN, NET_RAW and SYS_ADMIN.
# Uses private network namespaces with no host ports. Removes its container,
# image and data volumes on exit; diagnostics stay in build/mgmt-partial-nics.*.
# Scenarios and fixture details: test/mgmt-partial-nics/README.md.
set -Eeuo pipefail
trap 'echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR
ROOT=$(git rev-parse --show-toplevel)
PROJECT="containd-v033fix-partial-$(date +%s)-$$"
IMAGE="$PROJECT:local"
mkdir -p "$ROOT/build"
SCRATCH=$(mktemp -d "$ROOT/build/mgmt-partial-nics.XXXXXX")
CONTAINER=""
VOLUME=""
cleanup_case() {
  if [[ -n "$CONTAINER" ]]; then
    docker logs "$CONTAINER" >"$SCRATCH/$CONTAINER.log" 2>&1
    docker exec "$CONTAINER" nft list ruleset >"$SCRATCH/$CONTAINER.nft" 2>&1 || true
    docker container rm -f "$CONTAINER" >/dev/null
    CONTAINER=""
  fi
  if [[ -n "$VOLUME" ]]; then
    docker volume rm "$VOLUME" >/dev/null
    VOLUME=""
  fi
}
cleanup() {
  local status=$?
  trap - EXIT
  cleanup_case || status=1
  docker image rm "$IMAGE" >/dev/null || status=1
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
cp "$ROOT/test/mgmt-partial-nics/entrypoint.sh" "$SCRATCH/entrypoint.sh"
docker build -f "$ROOT/test/mgmt-partial-nics/Dockerfile" -t "$IMAGE" "$SCRATCH"
trap cleanup EXIT
BASE="http://10.99.99.2:8080/api/v1"
peer() { docker exec -i "$CONTAINER" ip netns exec "$1" curl -sS --max-time 5 --connect-timeout 2 "${@:2}"; }
api() { peer source --fail -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
wait_ready() {
  local ready=0
  for _ in $(seq 1 60); do
    if peer source --fail "$BASE/health" >"$SCRATCH/health.json" 2>"$SCRATCH/wait.err"; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo "management never ready" >&2; return 1; }
  # Do not mistake a pre-replay HTTP response for a working compiled INPUT.
  local applied=0
  for _ in $(seq 1 30); do
    docker exec "$CONTAINER" curl -fsS http://127.0.0.1:8081/internal/ruleset_status >"$SCRATCH/ruleset.json"
    if jq -e --argjson enforced "$ENFORCED" '
      (.appliedAt != "0001-01-01T00:00:00Z") and ((.error // "") == "") and
      (if $enforced then (.ruleset | contains("policy drop")) else .ruleset == "" end)
    ' "$SCRATCH/ruleset.json" >/dev/null; then applied=1; break; fi
    sleep 1
  done
  [[ "$applied" == 1 ]]
}
login() {
  TOKEN=$(peer source --fail -H 'Content-Type: application/json' \
    -d '{"username":"containd","password":"containd"}' "$BASE/auth/login" | jq -er '.token')
}
both_peers() {
  local name status
  for name in source proxy; do
    status=$(peer "$name" -o "/tmp/health-$name.json" -w '%{http_code}' "$BASE/health")
    [[ "$status" == 200 ]] || { echo "$name health: HTTP $status" >&2; return 1; }
    docker exec "$CONTAINER" cat "/tmp/health-$name.json" >"$SCRATCH/$name.json"
  done
}
assert_bindings() {
  api "$BASE/interfaces" >"$SCRATCH/interfaces.json"
  docker exec "$CONTAINER" ip -j -4 addr show >"$SCRATCH/addresses.json"
  python3 - "$SCRATCH/interfaces.json" "$SCRATCH/addresses.json" "$N" "$GENERATION" <<'PY'
import json, sys
rows, state = [json.load(open(p)) for p in sys.argv[1:3]]
n, generation = map(int, sys.argv[3:])
subnets = ["10.10.10", "10.20.20", "10.30.30", "10.40.40",
           "10.99.99", "10.60.60", "10.70.70", "10.80.80"]
names = ["wan", "dmz", "lan1", "lan2", "lan3", "lan4", "lan5", "lan6"]
for row in rows:
    i = names.index(row["name"])
    device = row.get("device", "")
    if i >= n:
        assert not device, row
        continue
    assert device == f"eth{(i + generation) % n}", row
    live = next(s for s in state if s["ifname"] == device)
    assert any(a["local"] == subnets[i] + ".2" for a in live["addr_info"]), row
PY
}
commit_policy() {
  api --data-binary @- "$BASE/config/candidate" <"$1" >"$SCRATCH/stage.json"
  api -D /tmp/commit.headers -X POST "$BASE/config/commit" >"$SCRATCH/commit.json"
  jq -e '.status == "committed"' "$SCRATCH/commit.json" >/dev/null
  docker exec "$CONTAINER" cat /tmp/commit.headers >"$SCRATCH/commit.headers"
  if grep -qi '^X-Containd-Warnings:' "$SCRATCH/commit.headers"; then
    echo "policy applied with warnings" >&2
    return 1
  fi
}
for N in 5 7 8; do
  for RESERVED in 0 1; do
    CONTAINER="$PROJECT-$N-$RESERVED"
    VOLUME="$CONTAINER-data"
    GENERATION=0
    ENFORCED=true
    : >"$SCRATCH/deployment.env"
    if [[ "$RESERVED" == 1 ]]; then
      printf '%s\n' 'CONTAIND_MGMT_RESERVATION={"subnet":"10.99.99.0/24","sources":["10.99.99.10","10.99.99.3"],"listen":":8080"}' >>"$SCRATCH/deployment.env"
    fi
    AUTO_NAMES=(WAN DMZ LAN1 LAN2 LAN3 LAN4 LAN5 LAN6)
    AUTO_SUBNETS=(10.10.10 10.20.20 10.30.30 10.40.40 10.99.99 10.60.60 10.70.70 10.80.80)
    for ((i=0; i<N; i++)); do
      printf 'CONTAIND_AUTO_%s_SUBNET=%s.0/24\n' "${AUTO_NAMES[$i]}" "${AUTO_SUBNETS[$i]}" >>"$SCRATCH/deployment.env"
    done
    docker volume create "$VOLUME" >/dev/null
    docker run -d --name "$CONTAINER" --network none \
      --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
      -v "$VOLUME:/data" -e "NIC_COUNT=$N" --env-file "$SCRATCH/deployment.env" \
      -e CONTAIND_ENGINE_ADDR=127.0.0.1:8081 -e CONTAIND_ENGINE_URL=http://127.0.0.1:8081 \
      -e CONTAIND_MGMT_ADDR=:8080 -e CONTAIND_SSH_ADDR=:18222 \
      -e CONTAIND_ENFORCE_ENABLED=1 -e CONTAIND_LAB_MODE=1 \
      -e CONTAIND_JWT_SECRET=isolated-partial-nics-secret-not-for-production \
      -e CONTAIND_CONFIG_DB=/data/config.db -e CONTAIND_AUDIT_DB=/data/audit.db -e CONTAIND_USERS_DB=/data/users.db \
      "$IMAGE" >/dev/null
    wait_ready
    login
    both_peers
    peer outsider --fail "$BASE/health" >"$SCRATCH/outsider-before.json"
    assert_bindings
    if [[ "$RESERVED" == 1 ]]; then
      api "$BASE/config" >"$SCRATCH/running.json"
      jq '.interfaces |= map(.access = {mgmt:false,http:false,https:false,ssh:false})' \
        "$SCRATCH/running.json" >"$SCRATCH/policy.json"
    else
      cp "$ROOT/test/mgmt-partial-nics/rd-policy.json" "$SCRATCH/policy.json"
      # The shipped full-replacement policy omits enforcement (false). Keep
      # the fixture exact and verify that runtime state, not a rewritten policy.
      jq -e '(.dataplane.enforcement // false) == false' "$SCRATCH/policy.json" >/dev/null
    fi
    commit_policy "$SCRATCH/policy.json"
    both_peers
    if [[ "$RESERVED" == 1 ]] && peer outsider --fail "$BASE/health" >"$SCRATCH/outsider-after.json" 2>"$SCRATCH/outsider.err"; then
      echo "outsider bypassed disabled access" >&2
      exit 1
    fi
    GENERATION=1
    if [[ "$RESERVED" == 0 ]]; then ENFORCED=false; fi
    docker exec "$CONTAINER" sh -c 'echo 1 >/data/nic-generation'
    docker restart "$CONTAINER" >/dev/null
    wait_ready
    login
    both_peers
    assert_bindings
    cp "$SCRATCH/interfaces.json" "$SCRATCH/$CONTAINER-renumbered-interfaces.json"
    if [[ "$RESERVED" == 1 ]]; then
      api "$BASE/config" >"$SCRATCH/restarted.json"
      jq -e 'all(.interfaces[]; .access.mgmt == false and .access.http == false)' "$SCRATCH/restarted.json" >/dev/null
      if peer outsider --fail "$BASE/health" >"$SCRATCH/outsider-restarted.json" 2>"$SCRATCH/outsider.err"; then
        echo "outsider bypassed policy after restart" >&2
        exit 1
      fi
    else
      # Opt-out remains opt-out: a later all-access-off edit is denied.
      api "$BASE/config" >"$SCRATCH/running.json"
      jq '.interfaces |= map(.access = {mgmt:false,http:false,https:false,ssh:false})' "$SCRATCH/running.json" >"$SCRATCH/off.json"
      commit_policy "$SCRATCH/off.json"
      for name in source proxy outsider; do
        if peer "$name" --fail "$BASE/health" >"$SCRATCH/off-$name.json" 2>"$SCRATCH/off-$name.err"; then
          echo "$name bypassed non-reserved policy" >&2
          exit 1
        fi
      done
    fi
    echo "PASS: N=$N reservation=$RESERVED fresh boot, policy, peers and renumber"
    cleanup_case
  done
done
