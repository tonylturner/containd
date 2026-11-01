#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by smoke-iec104.sh. All evidence survives stack teardown.
# shellcheck disable=SC2016 # Dollar variables in jq programs are jq bindings.

observe_check() {
  local name=$1 detail=$2
  shift 2
  if "$@"; then
    pass "$name" "$detail"
  else
    fail "$name" "$detail"
    observe_inventory failure || log "could not capture inventory after failure"
    "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/diagnostics/iec104" -o "$RESULTS_DIR/diagnostics.json" ||
      log "could not capture diagnostics after failure"
    fatal "observability assertion failed; inspect $RESULTS_DIR (stopping without changing product or policy)"
  fi
}

observe_inventory() {
  "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/inventory/iec104" -o "$RESULTS_DIR/inventory-$1.json"
}

# Pair identity includes the ephemeral controlling port. Sum only this host's
# pairs and CA 1, so separate command connections can be compared truthfully.
observe_counts() {
  jq --arg cc "$CC_IP:" --arg rtu "$RTU_IP:$RTU_PORT" '
    [.pairs[] | select((.controlling | startswith($cc)) and .controlled == $rtu)
      | .cas[] | select(.ca == 1)]
    | {attempted: (map(.attemptedCommands) | add // 0),
       accepted: (map(.acceptedCommands) | add // 0)}' "$1"
}

observe_denied() {
  local before after
  observe_inventory denied
  before=$(observe_counts "$RESULTS_DIR/inventory-before-deny.json")
  after=$(observe_counts "$RESULTS_DIR/inventory-denied.json")
  observe_check "inventory: denied command increments attempts, never accepts" "$before -> $after" \
    jq -en --argjson before "$before" --argjson after "$after" \
    '$after.attempted > $before.attempted and $after.accepted == $before.accepted'
}

observe_allowed() {
  local before after
  observe_inventory allowed
  before=$(observe_counts "$RESULTS_DIR/inventory-denied.json")
  after=$(observe_counts "$RESULTS_DIR/inventory-allowed.json")
  observe_check "inventory: allowed type 46 command is accepted at CA 1 / IOA 2001" "$before -> $after" \
    jq -e --arg cc "$CC_IP:" --arg rtu "$RTU_IP:$RTU_PORT" \
    --argjson before "$before" --argjson after "$after" '
      $after.accepted >= 1 and $after.accepted > $before.accepted
      and any(.pairs[]; (.controlling | startswith($cc)) and .controlled == $rtu
        and any(.cas[]; .ca == 1 and .acceptedCommands >= 1
          and any(.points[]; .ioa == 2001 and .typeId == 46)))' \
    "$RESULTS_DIR/inventory-allowed.json"
}

# Filter before limiting, and follow every continuation. The management API
# conservatively marks service history unknown; engineError is never ignored.
observe_events() {
  local name=$1 cursor="" page="$WORK_DIR/observe-page.json" tmp="$WORK_DIR/observe-events.json"
  shift
  printf '[]\n' >"$RESULTS_DIR/events-$name.json"
  while :; do
    "${CURL[@]}" -G -H "$AUTH_HEADER" "${BASE}/events" --data-urlencode "query=1" \
      --data-urlencode "limit=5000" --data-urlencode "cursor=$cursor" "$@" -o "$page"
    jq -e '(.engineError // "") == "" and (.events | type == "array")' "$page" >/dev/null ||
      fatal "event query failed: $(cat "$page")"
    jq -s '.[0] + .[1].events' "$RESULTS_DIR/events-$name.json" "$page" >"$tmp"
    mv "$tmp" "$RESULTS_DIR/events-$name.json"
    cursor=$(jq -r '.nextCursor // empty' "$page")
    [[ -n "$cursor" ]] || break
  done
}

observe_alerts() {
  # The Alerts page uses this event feed, not the legacy /anomalies detector
  # buffer. Query separately from the filtered evidence API above.
  "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=5000" -o "$RESULTS_DIR/alerts-$1.json"
}

observe_clean() {
  local code
  observe_events clean --data-urlencode kind=anomaly
  observe_alerts clean
  observe_check "APCI: clean startup, GI and monitoring produce zero anomaly events" "events-clean.json" \
    jq -e '[.[] | select((.attributes.anomaly_type // "") | startswith("iec104_"))] | length == 0' \
    "$RESULTS_DIR/events-clean.json"
  observe_check "APCI: clean startup, GI and monitoring produce zero alerts" "alerts-clean.json" \
    jq -e '[.[] | select(.proto == "ids" and .kind == "anomaly")
      | select((.attributes.anomaly_type // "") | startswith("iec104_"))] | length == 0' \
    "$RESULTS_DIR/alerts-clean.json"
  code=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/flows" -o "$RESULTS_DIR/flows.json" -w '%{http_code}')
  observe_check "monitoring: flows API remains available with engine up" "GET /flows returns HTTP $code" \
    test "$code" = 200
}

observe_apci() {
  local out sid sock
  out=$(malformer -scenario data-before-start -lport 40407 -ca "$ALLOWED_CA" -hold 2s)
  printf '%s\n' "$out" >"$RESULTS_DIR/apci-client.txt"
  sock=$(socket_of "$out")
  sleep 1
  observe_events apci --data-urlencode kind=anomaly
  observe_alerts apci
  observe_check "APCI: one pre-STARTDT I-frame produces exactly one identified anomaly" "$out; events-apci.json" \
    jq -e --arg cc "$CC_IP" --arg rtu "$RTU_IP" '
      [.[] | select((.attributes.anomaly_type // "") | startswith("iec104_"))]
      | length == 1 and .[0].attributes.anomaly_type == "iec104_data_while_stopped"
        and .[0].srcIp == $cc and .[0].dstIp == $rtu and .[0].srcPort == 40407
        and (.[0].attributes.session_id | type == "string" and length > 0)' "$RESULTS_DIR/events-apci.json"
  sid=$(jq -r '.[] | select(.attributes.anomaly_type == "iec104_data_while_stopped") | .attributes.session_id' \
    "$RESULTS_DIR/events-apci.json")
  observe_check "APCI: alerts API contains exactly one matching session alert" "$sid; alerts-apci.json" \
    jq -e --arg sid "$sid" '
      [.[] | select(.proto == "ids" and .kind == "anomaly")
        | select((.attributes.anomaly_type // "") | startswith("iec104_"))]
      | length == 1 and .[0].attributes.anomaly_type == "iec104_data_while_stopped"
        and .[0].attributes.session_id == $sid' \
    "$RESULTS_DIR/alerts-apci.json"
  observe_events apci-session --data-urlencode "session=$sid"
  observe_check "APCI: anomalous GI retains the enforce allow decision without abort or drop" "$sid; socket=$sock" \
    jq -e --arg sock "$sock" '
      ($sock == "open" or $sock == "eof") and any(.[]; .kind == "ics.decision" and .attributes.type_id == 100
        and .attributes.mode == "enforce" and .attributes.decision == "allow")
      and all(.[]; (.kind != "ics.decision" or .attributes.decision == "allow")
        and .kind != "ics.verdict" and (.kind != "ics.session" or .attributes.outcome != "aborted"))' \
    "$RESULTS_DIR/events-apci-session.json"
}

observe_final() {
  local settled=0
  observe_inventory final
  observe_check "inventory: no overflow counters were incremented" "inventory-final.json" \
    jq -e '.overflow | to_entries | length > 0 and all(.[]; .value == 0)' "$RESULTS_DIR/inventory-final.json"
  for _ in $(seq 1 20); do
    "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/diagnostics/iec104" -o "$RESULTS_DIR/diagnostics.json"
    if jq -e '.heldPackets == 0 and .heldBytes == 0 and .oldestPendingSeconds == 0' \
      "$RESULTS_DIR/diagnostics.json" >/dev/null; then settled=1; break; fi
    sleep 0.5
  done
  observe_check "diagnostics: held packets, bytes and oldest pending settle to zero" "diagnostics.json" \
    test "$settled" = 1
  [[ "$(engine_get firewall /metrics "$RESULTS_DIR/iec104-metrics.txt")" == 200 ]] ||
    fatal "could not read the engine metrics"
  observe_check "diagnostics: provoked abort counters match metrics and pressure gauges are zero" \
    "diagnostics.json; iec104-metrics.txt" python3 - "$RESULTS_DIR" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
diag = json.loads((root / "diagnostics.json").read_text())
metrics = {}
for line in (root / "iec104-metrics.txt").read_text().splitlines():
    if line.startswith("containd_dp_iec104_"):
        key, value = line.split()
        metrics[key] = float(value)
for name in ("held_packets", "held_bytes", "oldest_pending_seconds"):
    assert metrics["containd_dp_iec104_" + name] == 0, name
aborts = {}
for key, value in metrics.items():
    match = re.fullmatch(r'containd_dp_iec104_aborts_total\{reason="([^"]+)"\}', key)
    if match:
        aborts[match[1]] = value
assert aborts == diag["aborts"], (aborts, diag["aborts"])
# The harness deliberately denies commands and closes/rebinds active queues.
# A decoded malformed APDU is a deny, not necessarily a framing-only abort;
# a configuration rebuild closes the queue before installing the new policy.
for reason in ("deny", "queue"):
    assert diag["aborts"][reason] > 0, (reason, diag["aborts"])
print(json.dumps(diag, sort_keys=True))
PY
}
