#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Upgrade a genuine 0.1.35 data directory, then restart and prove audit AddOnce.
: "${RULE_MODES_IMAGE:?set RULE_MODES_IMAGE to the branch-built firewall image}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESULTS=${RULE_MODES_RESULTS:-$ROOT/build/rule-modes-migration-$(date +%s)-$$}
NAME=rule-modes-migration-$$
mkdir -p "$RESULTS/data"
cleanup() { docker stop "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
boot() {
  docker run --rm -d --name "$NAME" --cap-add NET_ADMIN --cap-add NET_RAW \
    -p 127.0.0.1::18080 -v "$RESULTS/data:/data" \
    -e CONTAIND_MGMT_ADDR=:18080 -e CONTAIND_ADMIN_TOKEN=devtoken -e CONTAIND_LAB_MODE=1 \
    -e CONTAIND_CONFIG_DB=/data/config.db -e CONTAIND_AUDIT_DB=/data/audit.db -e CONTAIND_USERS_DB=/data/users.db \
    "$1" all >/dev/null
  BASE="http://127.0.0.1:$(docker port "$NAME" 18080 | awk -F: '{print $NF}')/api/v1"
  for _ in $(seq 1 60); do
    if curl -sf -H 'Authorization: Bearer devtoken' "$BASE/config" >"$RESULTS/config.json"; then return; fi
    sleep 1
  done
  docker logs "$NAME" >&2
  return 1
}
api() { curl -sf --max-time 15 -H 'Authorization: Bearer devtoken' -H 'Content-Type: application/json' "$@"; }
boot ghcr.io/tonylturner/containd:0.1.35
jq '.dataPlane.dpiMode="learn" | .firewall.rules=[{id:"migrate",ics:{protocol:"modbus",mode:"learn"},action:"DENY"}]' "$RESULTS/config.json" >"$RESULTS/legacy.json"
api -X POST "$BASE/config" --data-binary @"$RESULTS/legacy.json" >"$RESULTS/save.json"
api -X POST "$BASE/config/commit" -d '{}' >"$RESULTS/commit.json"
# Only running contains learn: unchanged candidate/previous banks are stamped
# but generate no change audit. This isolates exactly one bank record.
jq '.dataPlane.dpiMode="" | .firewall.rules=[]' "$RESULTS/config.json" >"$RESULTS/clean.json"
api -X POST "$BASE/config" --data-binary @"$RESULTS/clean.json" >"$RESULTS/candidate.json"
cleanup
for boot_number in 1 2; do
  boot "$RULE_MODES_IMAGE"
  api "$BASE/audit?limit=1000" | jq '[.[] | select(.action=="config.rule_modes.migrated")]' >"$RESULTS/audit-$boot_number.json"
  jq -e 'length==1 and (.[0].detail | fromjson | .bank=="running" and (.changes | length)==2 and .schemaAfter=="0.1.9")' "$RESULTS/audit-$boot_number.json" >/dev/null
  api "$BASE/config" >"$RESULTS/running-$boot_number.json"
  jq -e '.schema_version=="0.1.9" and .dataPlane.dpiMode=="monitor" and .firewall.rules[0].ics.mode=="monitor"' "$RESULTS/running-$boot_number.json" >/dev/null
  cleanup
done
cmp "$RESULTS/audit-1.json" "$RESULTS/audit-2.json"
printf 'Legacy migration and idempotent second boot verified: %s\n' "$RESULTS"
