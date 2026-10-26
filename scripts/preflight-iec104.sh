#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESULTS_DIR="$ROOT/build/iec104-preflight"
RESULTS_FILE="$RESULTS_DIR/results.json"
COMPOSE_FILE="$ROOT/test/iec104/preflight/compose.yml"
STAMP=$(date -u +%Y%m%d-%H%M%S)
PROJECT="iec104-cp1-${STAMP}-$$"
IMAGE_NAME="containd-iec104-preflight:${PROJECT}"
export RESULTS_DIR IMAGE_NAME

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR/startup-failure.log" "$RESULTS_DIR/firewall-stats.json" \
  "$RESULTS_DIR/firewall-stats-stall-failure.json"
printf '{"schema_version":1,"status":"RUNNING","project":"%s","image":"%s","scenarios":[],"pcaps":[],"evidence":{},"errors":[]}\n' \
  "$PROJECT" "$IMAGE_NAME" >"$RESULTS_FILE"

STACK_ATTEMPTED=0
CURRENT_CAPTURE=""
CASE_FAILURES=0
CASE_VERDICT_ERRORS=0
CURRENT_SCENARIO=""
SCENARIO_VERDICT_FAILED=0
SCENARIO_VERDICT_FAILURES='[]'
REQUIRED_CASES=(
  "1 deferred ACCEPT"
  "2 deferred DROP"
  "3 multiple held packets"
  "4 callback returns without head-of-line stall"
  "5 verdict in both directions"
  "6 TCP payload larger than 2048 bytes"
  "7 two-sided RST and reconnect"
  "8 RFC 5961 challenge-ACK observation"
  "concurrent verdict stall probe"
  "queue stability after 32 deferred verdicts"
  "9 unbound queue fails closed"
)

# shellcheck source=scripts/preflight-iec104-helpers.sh
source "$ROOT/scripts/preflight-iec104-helpers.sh"

if ! command -v docker >/dev/null || ! command -v jq >/dev/null || ! command -v python3 >/dev/null; then
  fatal "Required host commands are docker, jq, and python3"
fi
if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  fatal "Docker Desktop is not reachable"
fi

NETWORK_SUBNETS=""
while IFS= read -r network_id; do
  [[ -n "$network_id" ]] || continue
  subnet_text=$(docker network inspect -f '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' "$network_id") \
    || fatal "Unable to inspect existing Docker network $network_id"
  NETWORK_SUBNETS+="${subnet_text}"$'\n'
done < <(docker network ls -q)
if ! python3 - "$NETWORK_SUBNETS" <<'PY'
import ipaddress
import sys

existing = [ipaddress.ip_network(line) for line in sys.argv[1].splitlines() if line.strip()]
for candidate in map(ipaddress.ip_network, ("10.250.0.0/24", "10.251.0.0/24")):
    conflicts = [str(network) for network in existing if candidate.overlaps(network)]
    if conflicts:
        print(f"{candidate} overlaps existing Docker network(s): {', '.join(conflicts)}", file=sys.stderr)
        sys.exit(1)
PY
then
  fatal "The preflight private subnets overlap an existing Docker network"
fi

printf '{"docker_server_version":"%s","host_os":"%s","existing_networks_checked":true}\n' \
  "$(docker version --format '{{.Server.Version}}')" "$(uname -s)" >"$RESULTS_DIR/platform.json"
if ! compose config --quiet; then
  fatal "docker compose config rejected the preflight composition"
fi
STACK_ATTEMPTED=1
if ! compose up --build -d --wait --wait-timeout 90; then
  compose logs --no-color >"$RESULTS_DIR/startup-failure.log" 2>&1 || true
  fatal "Docker Compose build/start failed; inspect Docker Desktop logs and compose output above"
fi
compose exec -T firewall sh -c 'ip -4 route; printf "\n--- nft ruleset ---\n"; nft list ruleset' \
  >"$RESULTS_DIR/topology.txt" || fatal "Could not record firewall routes and nft queue rules"
compose exec -T client ip -4 route >"$RESULTS_DIR/client-route.txt" \
  || fatal "Could not verify the client route through the firewall"
compose exec -T server ip -4 route >"$RESULTS_DIR/server-route.txt" \
  || fatal "Could not verify the server route through the firewall"
if ! grep -q 'via 10.250.0.2' "$RESULTS_DIR/client-route.txt" ||
  ! grep -q 'via 10.251.0.2' "$RESULTS_DIR/server-route.txt" ||
  ! grep -Eq 'queue (num |to )?101' "$RESULTS_DIR/topology.txt"; then
  fatal "The endpoints are not routed through the firewall or nft queue 101 is absent"
fi

printf '\nRunning NFQUEUE verdict and TCP reset scenarios on Docker Desktop (project %s)\n\n' "$PROJECT"

# 1. Deferred ACCEPT: the handler returns with the packet held; a timer submits
# ACCEPT about 300 ms later and the server application must get exactly the data.
begin_scenario "1 deferred ACCEPT"
start_capture deferred-accept || fatal "Could not start endpoint pcaps for deferred ACCEPT"
new_connection || fatal "Could not create the deferred-ACCEPT TCP connection"
set_rule 'A1:' c2s accept 300
ACCEPT_DATA='A1:deferred-accept-exact'
SEND_BODY=$(jq -cn --arg data "$ACCEPT_DATA" '{data:$data}')
endpoint client POST "/send?id=$CLIENT_ID" "$SEND_BODY" >/dev/null
wait_held 'A1:' 1 || fatal "Deferred-ACCEPT packet never appeared in userspace hold list"
wait_received server "$CLIENT_ID" "$ACCEPT_DATA" || fatal "Deferred-ACCEPT bytes were not received exactly"
wait_event_verdict 'A1:' accept || fatal "Deferred-ACCEPT verdict event was not recorded"
ACCEPT_HOLD_MS=$(hold_time_ms 'A1:' accept)
ACCEPT_METRICS=$(jq -cn --argjson held_ms "$ACCEPT_HOLD_MS" --arg data "$ACCEPT_DATA" \
  '{held_ms:$held_ms,bytes:($data|length),callback_returned_before_verdict:true}')
ACCEPT_OK=1
if ! awk -v n="$ACCEPT_HOLD_MS" 'BEGIN { exit !(n >= 250 && n <= 1500) }'; then ACCEPT_OK=0; fi
if [[ $(endpoint server GET "/conn?id=$CLIENT_ID" | jq -r .received) != "$ACCEPT_DATA" ]]; then ACCEPT_OK=0; fi
if [[ "$ACCEPT_OK" -eq 1 ]]; then
  record_case "1 deferred ACCEPT" PASS "exact application bytes delivered after ${ACCEPT_HOLD_MS}ms hold" "$ACCEPT_METRICS"
else
  record_case "1 deferred ACCEPT" FAIL "ACCEPT delivery or measured 250–1500ms hold assertion failed" "$ACCEPT_METRICS"
fi
stop_capture_or_fail

# Extra load assertion: demonstrate the same queue works after 32 independently
# deferred verdicts rather than only a single packet.
begin_scenario "queue stability after 32 deferred verdicts"
start_capture deferred-verdict-stress || fatal "Could not start pcaps for queue stability scenario"
new_connection || fatal "Could not create the deferred-verdict stress connection"
set_rule 'ST:' c2s accept 50
STRESS_DATA=""
for n in $(seq -w 0 31); do STRESS_DATA+="ST:${n};"; done
SEND_BODY=$(jq -cn --arg data "$STRESS_DATA" '{data:$data,chunk_size:6,gap_ms:40}')
endpoint client POST "/send?id=$CLIENT_ID" "$SEND_BODY" >/dev/null
wait_received server "$CLIENT_ID" "$STRESS_DATA" || fatal "32-packet verdict stress payload did not arrive intact"
wait_event_verdict 'ST:' accept || fatal "No deferred stress verdict was observed"
STRESS_EVENTS=$(fw GET /events)
STRESS_COUNT=$(jq -r '[.events[] | select(.matched and (.prefix | startswith("ST:")) and .verdict == "accept")] | length' \
  <<<"$STRESS_EVENTS")
STRESS_NIL=$(fw GET /stats | jq -r .verdicts_setverdict_nil)
STRESS_METRICS=$(jq -cn --argjson expected 32 --argjson matched "$STRESS_COUNT" \
  --argjson nil "$STRESS_NIL" '{expected_packets:$expected,matched_deferred_verdicts:$matched,setverdict_nil_count:$nil}')
if [[ "$STRESS_COUNT" -ge 32 ]]; then
  record_case "queue stability after 32 deferred verdicts" PASS "32 separately held packets accepted; queue remained active" "$STRESS_METRICS"
else
  record_case "queue stability after 32 deferred verdicts" FAIL "fewer than 32 independently deferred packets were observed" "$STRESS_METRICS"
fi
stop_capture_or_fail

# 2. Deferred DROP must leave the server application buffer empty, even after a
# retransmission interval; close the client while the matching drop stays armed.
begin_scenario "2 deferred DROP"
start_capture deferred-drop || fatal "Could not start endpoint pcaps for deferred DROP"
new_connection || fatal "Could not create the deferred-DROP TCP connection"
set_rule 'DROP:' c2s drop 100
DROP_DATA='DROP:must-never-reach-server'
SEND_BODY=$(jq -cn --arg data "$DROP_DATA" '{data:$data}')
endpoint client POST "/send?id=$CLIENT_ID" "$SEND_BODY" >/dev/null
wait_held 'DROP:' 1 || fatal "Deferred-DROP packet never appeared in userspace hold list"
wait_event_verdict 'DROP:' drop || fatal "Deferred-DROP was not submitted"
sleep 1.2
DROP_SNAPSHOT=$(endpoint server GET "/conn?id=$CLIENT_ID")
DROP_RECEIVED=$(jq -r .received <<<"$DROP_SNAPSHOT")
close_endpoint client "$CLIENT_ID"
sleep 0.3
DROP_FINAL=$(endpoint server GET "/conn?id=$CLIENT_ID")
DROP_FINAL_BYTES=$(jq -r .received <<<"$DROP_FINAL")
DROP_METRICS=$(jq -cn --arg initial "$DROP_RECEIVED" --arg final "$DROP_FINAL_BYTES" \
  '{server_buffer_after_1_2s:$initial,server_buffer_after_client_close:$final,expected_bytes:0}')
if [[ -z "$DROP_RECEIVED" && -z "$DROP_FINAL_BYTES" ]]; then
  record_case "2 deferred DROP" PASS "dropped data absent from server application buffer after 1.5s" "$DROP_METRICS"
else
  record_case "2 deferred DROP" FAIL "dropped bytes reached the server application buffer" "$DROP_METRICS"
fi
stop_capture_or_fail

# Concurrent verdict stall probe: queue 50 separately emitted data packets over five TCP flows, then submit
# exactly one concurrent HTTP verdict request per currently held packet. The
# packet event records each SetVerdict call's own elapsed time (not HTTP time).
begin_scenario "concurrent verdict stall probe"
start_capture verdict-stall || fatal "Could not start endpoint pcaps for concurrent verdict probe"
set_rule 'Q50:' c2s manual 0
declare -a STALL_FLOW_IDS=()
declare -a STALL_FLOW_DATA=()
declare -a STALL_SEND_PIDS=()
for flow in 0 1 2 3 4; do
  new_connection || fatal "Could not open concurrent-verdict flow $flow"
  STALL_FLOW_IDS+=("$CLIENT_ID")
  payload=""
  for sequence in $(seq -w 0 9); do
    payload+="Q50:${flow}:${sequence};"
  done
  STALL_FLOW_DATA+=("$payload")
  SEND_BODY=$(jq -cn --arg data "$payload" \
    '{data:$data,chunk_size:8,gap_ms:10}')
  endpoint client POST "/send?id=$CLIENT_ID" "$SEND_BODY" \
    >"$RESULTS_DIR/stall-send-$flow.json" 2>"$RESULTS_DIR/stall-send-$flow.stderr" &
  STALL_SEND_PIDS+=("$!")
done
STALL_SEND_FAILURES=0
for flow in 0 1 2 3 4; do
  if wait "${STALL_SEND_PIDS[$flow]}"; then
    :
  else
    rc=$?
    STALL_SEND_FAILURES=$((STALL_SEND_FAILURES + 1))
    printf 'Flow %s send failed with exit %s (not retried)\n' "$flow" "$rc" \
      >>"$RESULTS_DIR/stall-send-failures.txt"
  fi
done
if [[ "$STALL_SEND_FAILURES" -ne 0 ]]; then
  fatal "$STALL_SEND_FAILURES concurrent probe flow write(s) failed"
fi
wait_held 'Q50:' 50 || fatal "Fewer than 50 packets entered the concurrent-verdict hold"
STALL_HELD=$(fw GET /held)
STALL_ID_LINES=$(jq -r '[.held[] | select(.prefix | startswith("Q50:")) | .id] | .[]' \
  <<<"$STALL_HELD")
STALL_PACKET_COUNT=$(jq -r '[.held[] | select(.prefix | startswith("Q50:"))] | length' \
  <<<"$STALL_HELD")
STALL_INITIAL_PACKET_COUNT=$STALL_PACKET_COUNT
STALL_IDS=()
while IFS= read -r id; do
  [[ -n "$id" ]] && STALL_IDS+=("$id")
done <<<"$STALL_ID_LINES"
if [[ "$STALL_PACKET_COUNT" -lt 50 || "${#STALL_IDS[@]}" -ne "$STALL_PACKET_COUNT" ]]; then
  fatal "Concurrent probe held-packet snapshot was inconsistent (count=$STALL_PACKET_COUNT)"
fi

STALL_SUBMIT_OK=1
if compose exec -T firewall /usr/local/bin/preflight parallel-verdict \
  http://127.0.0.1:8081 "${STALL_IDS[@]}" \
  >"$RESULTS_DIR/stall-parallel-verdicts.json" 2>"$RESULTS_DIR/stall-parallel-verdicts.stderr"; then
  :
else
  rc=$?
  STALL_SUBMIT_OK=0
  printf 'Parallel verdict helper exited %s; no request was retried\n' "$rc" \
    >>"$RESULTS_DIR/stall-parallel-verdicts.stderr"
fi

if [[ "$STALL_SUBMIT_OK" -eq 0 ]]; then
  STALL_SUBMIT_FAILED=1
  STALL_HTTP_RESULTS=$(jq -c 'if type == "array" then . else [] end' \
    "$RESULTS_DIR/stall-parallel-verdicts.json" 2>/dev/null || printf '[]')
  STALL_HTTP_ERRORS=$(jq -c '[.[] | select(.error != null and .error != "") | {id,error}]' \
    <<<"$STALL_HTTP_RESULTS")
  STALL_BATCH_IDS=$(jq -c '[.[].id]' <<<"$STALL_HTTP_RESULTS")
  if [[ $(jq -r 'length' <<<"$STALL_BATCH_IDS") -ne "$STALL_PACKET_COUNT" ]] ||
    ! wait_verdict_events "$STALL_BATCH_IDS"; then
    STALL_FAILURE_STATS=$(fw GET /stats || printf '{}')
    record_latency_evidence "$STALL_FAILURE_STATS"
    record_evidence failed_verdict_observation "$(jq -cn \
      --argjson ids "$STALL_BATCH_IDS" --argjson errors "$STALL_HTTP_ERRORS" \
      --argjson stats "$STALL_FAILURE_STATS" \
      '{packet_ids:$ids,http_errors:$errors,latencies:{setverdict:$stats.setverdict_latency,verdict_handler:$stats.verdict_handler_latency},requests_retried:false,all_handlers_completed:false}')"
    fatal "At least one failed concurrent verdict handler did not return within the observation window"
  fi
  STALL_FAILURE_STATS=$(fw GET /stats)
  STALL_FAILURE_EVENTS=$(fw GET /events | jq -c --arg prefix 'Q50:' \
    '[.events[] | select(.matched and (.prefix | startswith($prefix)))]')
  record_latency_evidence "$STALL_FAILURE_STATS"
  record_evidence failed_verdict_observation "$(jq -cn \
    --argjson errors "$STALL_HTTP_ERRORS" --argjson stats "$STALL_FAILURE_STATS" \
    --argjson events "$STALL_FAILURE_EVENTS" \
    '{http_errors:$errors,packet_events:$events,latencies:{setverdict:$stats.setverdict_latency,verdict_handler:$stats.verdict_handler_latency},requests_retried:false,all_handlers_completed:true}')"
else
  STALL_HTTP_RESULTS=$(cat "$RESULTS_DIR/stall-parallel-verdicts.json")
  STALL_HTTP_ERRORS='[]'
  STALL_SUBMIT_FAILED=0
fi
STALL_SUBMITTED_IDS=("${STALL_IDS[@]}")
STALL_LATE_BATCHES=0
STALL_QUIET_POLLS=0
while [[ "$STALL_QUIET_POLLS" -lt 3 ]]; do
  STALL_HELD=$(fw GET /held)
  STALL_LATE_LINES=$(jq -r '[.held[] | select(.prefix | startswith("Q50:")) | .id] | .[]' \
    <<<"$STALL_HELD")
  if [[ -z "$STALL_LATE_LINES" ]]; then
    STALL_QUIET_POLLS=$((STALL_QUIET_POLLS + 1))
    sleep 0.05
    continue
  fi

  STALL_LATE_IDS=()
  while IFS= read -r id; do
    [[ -n "$id" ]] && STALL_LATE_IDS+=("$id")
  done <<<"$STALL_LATE_LINES"
  for late_id in "${STALL_LATE_IDS[@]}"; do
    for submitted_id in "${STALL_SUBMITTED_IDS[@]}"; do
      if [[ "$late_id" == "$submitted_id" ]]; then
        fatal "Concurrent probe attempted to retry packet $late_id"
      fi
    done
  done
  STALL_LATE_BATCHES=$((STALL_LATE_BATCHES + 1))
  if [[ "$STALL_LATE_BATCHES" -gt 5 ]]; then
    fatal "Concurrent probe continued accumulating held retransmissions after five release batches"
  fi
  LATE_RESULTS_FILE="$RESULTS_DIR/stall-parallel-verdicts-late-$STALL_LATE_BATCHES.json"
  if compose exec -T firewall /usr/local/bin/preflight parallel-verdict \
    http://127.0.0.1:8081 "${STALL_LATE_IDS[@]}" \
    >"$LATE_RESULTS_FILE" 2>"$LATE_RESULTS_FILE.stderr"; then
    LATE_RESULTS=$(cat "$LATE_RESULTS_FILE")
    STALL_HTTP_RESULTS=$(jq -cn --argjson first "$STALL_HTTP_RESULTS" \
      --argjson late "$LATE_RESULTS" '$first + $late')
    STALL_SUBMITTED_IDS+=("${STALL_LATE_IDS[@]}")
    STALL_PACKET_COUNT=$((STALL_PACKET_COUNT + ${#STALL_LATE_IDS[@]}))
    STALL_QUIET_POLLS=0
  else
    LATE_RESULTS=$(jq -c 'if type == "array" then . else [] end' \
      "$LATE_RESULTS_FILE" 2>/dev/null || printf '[]')
    LATE_BATCH_ERRORS=$(jq -c '[.[] | select(.error != null and .error != "") | {id,error}]' \
      <<<"$LATE_RESULTS")
    LATE_BATCH_IDS=$(jq -c '[.[].id]' <<<"$LATE_RESULTS")
    STALL_HTTP_RESULTS=$(jq -cn --argjson first "$STALL_HTTP_RESULTS" \
      --argjson late "$LATE_RESULTS" '$first + $late')
    STALL_HTTP_ERRORS=$(jq -cn --argjson first "$STALL_HTTP_ERRORS" \
      --argjson late "$LATE_BATCH_ERRORS" '$first + $late')
    STALL_SUBMITTED_IDS+=("${STALL_LATE_IDS[@]}")
    STALL_PACKET_COUNT=$((STALL_PACKET_COUNT + ${#STALL_LATE_IDS[@]}))
    STALL_SUBMIT_FAILED=1
    if [[ $(jq -r 'length' <<<"$LATE_BATCH_IDS") -ne "${#STALL_LATE_IDS[@]}" ]] ||
      ! wait_verdict_events "$LATE_BATCH_IDS"; then
      STALL_FAILURE_STATS=$(fw GET /stats || printf '{}')
      record_latency_evidence "$STALL_FAILURE_STATS"
      record_evidence failed_verdict_observation "$(jq -cn \
        --argjson ids "$LATE_BATCH_IDS" --argjson errors "$LATE_BATCH_ERRORS" \
        --argjson stats "$STALL_FAILURE_STATS" \
        '{packet_ids:$ids,http_errors:$errors,latencies:{setverdict:$stats.setverdict_latency,verdict_handler:$stats.verdict_handler_latency},requests_retried:false,all_handlers_completed:false}')"
      fatal "A failed late-retransmission verdict handler did not return within the observation window"
    fi
    STALL_FAILURE_STATS=$(fw GET /stats)
    STALL_FAILURE_EVENTS=$(fw GET /events | jq -c --arg prefix 'Q50:' \
      '[.events[] | select(.matched and (.prefix | startswith($prefix)))]')
    record_latency_evidence "$STALL_FAILURE_STATS"
    record_evidence failed_verdict_observation "$(jq -cn \
      --argjson errors "$STALL_HTTP_ERRORS" --argjson stats "$STALL_FAILURE_STATS" \
      --argjson events "$STALL_FAILURE_EVENTS" \
      '{http_errors:$errors,packet_events:$events,latencies:{setverdict:$stats.setverdict_latency,verdict_handler:$stats.verdict_handler_latency},requests_retried:false,all_handlers_completed:true}')"
    STALL_QUIET_POLLS=0
  fi
done

for flow in 0 1 2 3 4; do
  wait_received server "${STALL_FLOW_IDS[$flow]}" "${STALL_FLOW_DATA[$flow]}" \
    || fatal "Concurrent probe data for flow $flow was not delivered intact"
done
STALL_EVENTS=$(fw GET /events)
STALL_SETVERDICT_MS=$(jq -c --arg prefix 'Q50:' \
  '[.events[] | select(.matched and (.prefix | startswith($prefix)) and .verdict == "accept") | .setverdict_ms]' \
  <<<"$STALL_EVENTS")
STALL_RETURN_COUNT=$(jq -r 'length' <<<"$STALL_SETVERDICT_MS")
STALL_LATENCY_MAX_MS=$(jq -r 'max // 0' <<<"$STALL_SETVERDICT_MS")
STALL_LATENCY_P99_MS=$(jq -r 'if length == 0 then 0 else (sort | .[((length * 0.99 | ceil) - 1)]) end' \
  <<<"$STALL_SETVERDICT_MS")
STALL_HELD_LEFT=$(fw GET /held | jq -r '[.held[] | select(.prefix | startswith("Q50:"))] | length')
STALL_HTTP_COUNT=$(jq -r 'length' <<<"$STALL_HTTP_RESULTS")
STALL_HTTP_MAX_MS=$(jq -r '[.[].http_duration_ms] | max // 0' <<<"$STALL_HTTP_RESULTS")
STALL_HTTP_P99_MS=$(jq -r 'if length == 0 then 0 else ([.[].http_duration_ms] | sort | .[((length * 0.99 | ceil) - 1)]) end' \
  <<<"$STALL_HTTP_RESULTS")
STALL_METRICS=$(jq -cn --argjson expected 50 --argjson initial "$STALL_INITIAL_PACKET_COUNT" \
  --argjson held "$STALL_PACKET_COUNT" --argjson late_batches "$STALL_LATE_BATCHES" \
  --argjson posts "$STALL_HTTP_COUNT" --argjson returns "$STALL_RETURN_COUNT" \
  --argjson max_ms "$STALL_LATENCY_MAX_MS" --argjson p99_ms "$STALL_LATENCY_P99_MS" \
  --argjson http_max_ms "$STALL_HTTP_MAX_MS" --argjson http_p99_ms "$STALL_HTTP_P99_MS" \
  --argjson held_left "$STALL_HELD_LEFT" --argjson setverdict_ms "$STALL_SETVERDICT_MS" \
  --argjson http_errors "$STALL_HTTP_ERRORS" \
  '{expected_packets:$expected,initial_held_packets:$initial,total_held_packets:$held,late_retransmission_release_batches:$late_batches,parallel_verdict_posts:$posts,setverdict_returns:$returns,setverdict_latency_max_ms:$max_ms,setverdict_latency_p99_ms:$p99_ms,verdict_http_client_latency_max_ms:$http_max_ms,verdict_http_client_latency_p99_ms:$http_p99_ms,http_errors:$http_errors,unresolved_held_packets:$held_left,per_packet_setverdict_ms:$setverdict_ms,requests_retried:false}')
if [[ "$STALL_SUBMIT_FAILED" -eq 0 && "$STALL_PACKET_COUNT" -ge 50 &&
  "$STALL_HTTP_COUNT" -eq "$STALL_PACKET_COUNT" &&
  "$STALL_RETURN_COUNT" -eq "$STALL_PACKET_COUNT" && "$STALL_HELD_LEFT" -eq 0 ]] &&
  awk -v n="$STALL_LATENCY_MAX_MS" 'BEGIN { exit !(n <= 250) }'; then
  record_case "concurrent verdict stall probe" PASS \
    "released $STALL_PACKET_COUNT held packets concurrently; every SetVerdict returned in ${STALL_LATENCY_MAX_MS}ms (limit 250ms)" \
    "$STALL_METRICS"
else
  if [[ "$STALL_SUBMIT_FAILED" -eq 1 ]]; then
    STALL_FAILURE_ASSERTION="One or more POST /verdict calls failed or timed out; each request was observed but never retried"
  else
    STALL_FAILURE_ASSERTION="concurrent release count, delivery, or 250ms SetVerdict latency assertion failed"
  fi
  record_case "concurrent verdict stall probe" FAIL \
    "$STALL_FAILURE_ASSERTION" \
    "$STALL_METRICS"
fi
stop_capture_or_fail


# 3. Hold three packets on one flow and one on another; release the 2nd packet
# first, then the independent flow, then fill the gap on the first flow.
begin_scenario "3 multiple held packets"
start_capture multiple-held || fatal "Could not start endpoint pcaps for multiple-held scenario"
set_rule 'M:' c2s manual 0
new_connection || fatal "Could not open first multiple-held flow"
FLOW1=$CLIENT_ID
FLOW1_SEND=$(jq -cn --arg data 'M:flow1-1;' '{data:$data}')
endpoint client POST "/send?id=$FLOW1" "$FLOW1_SEND" >/dev/null
sleep 0.1
FLOW1_SEND=$(jq -cn --arg data 'M:flow1-2;' '{data:$data}')
endpoint client POST "/send?id=$FLOW1" "$FLOW1_SEND" >/dev/null
sleep 0.1
FLOW1_SEND=$(jq -cn --arg data 'M:flow1-3;' '{data:$data}')
endpoint client POST "/send?id=$FLOW1" "$FLOW1_SEND" >/dev/null
new_connection || fatal "Could not open second multiple-held flow"
FLOW2=$CLIENT_ID
FLOW2_SEND=$(jq -cn --arg data 'M:flow2-1;' '{data:$data}')
endpoint client POST "/send?id=$FLOW2" "$FLOW2_SEND" >/dev/null
wait_held 'M:' 4 || fatal "Did not observe four concurrently held packets"
HELD_LIST=$(fw GET /held)
HELD_DISTINCT=$(jq -r --arg a 'M:flow1-1;' --arg b 'M:flow1-2;' --arg c 'M:flow1-3;' --arg d 'M:flow2-1;' \
  '[.held[].prefix] | map(select(. == $a or . == $b or . == $c or . == $d)) | unique | length' <<<"$HELD_LIST")
MULTI_HELD_COUNT=$(jq -r '[.held[] | select(.prefix | startswith("M:"))] | length' <<<"$HELD_LIST")
release_held 'M:flow1-2;'
sleep 0.1
release_held 'M:flow2-1;'
wait_received server "$FLOW2" 'M:flow2-1;' || fatal "Second flow did not progress while first flow had a sequence gap"
FLOW1_BEFORE=$(endpoint server GET "/conn?id=$FLOW1" | jq -r .received)
release_held 'M:flow1-1;'
release_held 'M:flow1-3;'
FLOW1_EXPECTED='M:flow1-1;M:flow1-2;M:flow1-3;'
wait_received server "$FLOW1" "$FLOW1_EXPECTED" || fatal "First-flow stream was not reassembled intact after chosen-order verdicts"
if ! release_all_held 'M:'; then
  fatal "Could not settle all delayed retransmissions from the multiple-held flows"
fi
MULTI_LEFT=$(fw GET /held | jq -r '[.held[] | select(.prefix | startswith("M:"))] | length')
MULTI_METRICS=$(jq -cn --argjson held "$MULTI_HELD_COUNT" --argjson distinct "$HELD_DISTINCT" \
  --arg before "$FLOW1_BEFORE" --arg flow1 "$FLOW1_EXPECTED" --arg flow2 'M:flow2-1;' \
  --argjson leftover "$MULTI_LEFT" \
  '{packets_held_including_retransmits:$held,distinct_original_packet_payloads:$distinct,first_flow_before_gap_fill:$before,first_flow_after:$flow1,unaffected_flow:$flow2,release_order:["flow1-2","flow2-1","flow1-1","flow1-3"],unresolved_matching_packets:$leftover}')
if [[ "$MULTI_HELD_COUNT" -ge 4 && "$HELD_DISTINCT" -eq 4 && -z "$FLOW1_BEFORE" && "$MULTI_LEFT" -eq 0 ]]; then
  record_case "3 multiple held packets" PASS "four held packets released in chosen order; independent flow progressed" "$MULTI_METRICS"
else
  record_case "3 multiple held packets" FAIL "held packet count, payload identity, or sequence-gap isolation failed" "$MULTI_METRICS"
fi
stop_capture_or_fail

# 4. The NFQUEUE callback returns without a verdict: a different flow can pass
# while the first packet remains held.
begin_scenario "4 callback returns without head-of-line stall"
start_capture callback-return || fatal "Could not start endpoint pcaps for callback-return scenario"
set_rule 'H:' c2s manual 0
new_connection || fatal "Could not open held callback-return flow"
HELD_FLOW=$CLIENT_ID
SEND_BODY=$(jq -cn --arg data 'H:callback-returned' '{data:$data}')
endpoint client POST "/send?id=$HELD_FLOW" "$SEND_BODY" >/dev/null
wait_held 'H:' 1 || fatal "Callback-return packet was not held"
HELD_COUNT_BEFORE=$(fw GET /held | jq -r '[.held[] | select(.prefix | startswith("H:"))] | length')
new_connection || fatal "Could not open independent callback-return flow"
FREE_FLOW=$CLIENT_ID
SEND_BODY=$(jq -cn --arg data 'FREE:independent-flow' '{data:$data}')
endpoint client POST "/send?id=$FREE_FLOW" "$SEND_BODY" >/dev/null
wait_received server "$FREE_FLOW" 'FREE:independent-flow' \
  || fatal "Independent flow stalled behind a held packet (head-of-line block)"
HELD_COUNT_AFTER=$(fw GET /held | jq -r '.held | length')
release_held 'H:'
wait_received server "$HELD_FLOW" 'H:callback-returned' || fatal "Held callback-return packet did not arrive after verdict"
if ! release_all_held 'H:'; then
  fatal "Could not settle all held callback-return retransmissions"
fi
HELD_LEFT=$(fw GET /held | jq -r '[.held[] | select(.prefix | startswith("H:"))] | length')
CALLBACK_METRICS=$(jq -cn --argjson held_before "$HELD_COUNT_BEFORE" --argjson held_after "$HELD_COUNT_AFTER" \
  --arg free 'FREE:independent-flow' \
  --argjson leftover "$HELD_LEFT" \
  '{held_count_before_independent_flow:$held_before,held_count_after_independent_flow:$held_after,independent_flow_delivered_before_release:$free,unresolved_matching_packets:$leftover}')
if [[ "$HELD_COUNT_BEFORE" -ge 1 && "$HELD_COUNT_AFTER" -ge 1 && "$HELD_LEFT" -eq 0 ]]; then
  record_case "4 callback returns without head-of-line stall" PASS "independent flow delivered before held packet was released" "$CALLBACK_METRICS"
else
  record_case "4 callback returns without head-of-line stall" FAIL "independent flow did not pass while another packet remained held" "$CALLBACK_METRICS"
fi
stop_capture_or_fail

# 5. Exercise deferred accept and drop from server to client as well as the
# client-to-server direction used above.
begin_scenario "5 verdict in both directions"
start_capture reverse-direction || fatal "Could not start endpoint pcaps for reverse-direction scenario"
new_connection || fatal "Could not open reverse-direction TCP flow"
REVERSE_ID=$CLIENT_ID
set_rule 'B:' s2c accept 300
REVERSE_ACCEPT='B:server-to-client'
SEND_BODY=$(jq -cn --arg data "$REVERSE_ACCEPT" '{data:$data}')
endpoint server POST "/write?id=$REVERSE_ID" "$SEND_BODY" >/dev/null
wait_held 'B:' 1 || fatal "Server-to-client data was not queued and held"
wait_received client "$REVERSE_ID" "$REVERSE_ACCEPT" || fatal "Server-to-client deferred ACCEPT did not deliver exact bytes"
wait_event_verdict 'B:' accept || fatal "Server-to-client ACCEPT verdict was not observed"
REVERSE_HOLD_MS=$(hold_time_ms 'B:' accept)
set_rule 'Z:' s2c drop 100
REVERSE_DROP='Z:server-data-dropped'
SEND_BODY=$(jq -cn --arg data "$REVERSE_DROP" '{data:$data}')
endpoint server POST "/write?id=$REVERSE_ID" "$SEND_BODY" >/dev/null
wait_held 'Z:' 1 || fatal "Server-to-client DROP packet was not held"
wait_event_verdict 'Z:' drop || fatal "Server-to-client DROP verdict was not observed"
sleep 1.2
REVERSE_FINAL=$(endpoint client GET "/conn?id=$REVERSE_ID" | jq -r .received)
close_endpoint server "$REVERSE_ID"
REVERSE_METRICS=$(jq -cn --arg accepted "$REVERSE_FINAL" --arg expected "$REVERSE_ACCEPT" \
  --argjson held_ms "$REVERSE_HOLD_MS" --arg dropped "$REVERSE_DROP" \
  '{client_buffer:$accepted,accepted_bytes_expected:$expected,accept_hold_ms:$held_ms,dropped_marker_absent:true,dropped_marker:$dropped}')
if [[ "$REVERSE_FINAL" == "$REVERSE_ACCEPT" ]]; then
  record_case "5 verdict in both directions" PASS "server-to-client ACCEPT delivered and deferred DROP stayed out of client buffer" "$REVERSE_METRICS"
else
  record_case "5 verdict in both directions" FAIL "reverse-direction delivery/drop assertion failed" "$REVERSE_METRICS"
fi
stop_capture_or_fail

# 6. TCP stream payload exceeds the snaplen used in production. The harness
# configures a 65535-byte NFQUEUE copy and verifies the reconstructed stream.
begin_scenario "6 TCP payload larger than 2048 bytes"
start_capture large-payload || fatal "Could not start endpoint pcaps for large-payload scenario"
new_connection || fatal "Could not open large-payload TCP flow"
LARGE_ID=$CLIENT_ID
LARGE_DATA="BIG:$(python3 -c 'print("0123456789abcdef" * 640, end="")')"
set_rule 'BIG:' c2s accept 300
SEND_BODY=$(jq -cn --arg data "$LARGE_DATA" --argjson chunk 1024 '{data:$data,chunk_size:$chunk,gap_ms:10}')
endpoint client POST "/send?id=$LARGE_ID" "$SEND_BODY" >/dev/null
wait_held 'BIG:' 1 || fatal "Large TCP payload was not held"
wait_received server "$LARGE_ID" "$LARGE_DATA" || fatal "Large TCP stream was not delivered intact"
wait_event_verdict 'BIG:' accept || fatal "Large-payload deferred ACCEPT did not occur"
LARGE_HOLD_MS=$(hold_time_ms 'BIG:' accept)
LARGE_STATS=$(fw GET /stats)
LARGE_PACKET_MAX=$(jq -r .max_observed_packet <<<"$LARGE_STATS")
LARGE_PACKET_COPY=$(jq -r .max_packet_len_config <<<"$LARGE_STATS")
LARGE_BYTES=${#LARGE_DATA}
LARGE_METRICS=$(jq -cn --argjson stream_bytes "$LARGE_BYTES" --argjson held_ms "$LARGE_HOLD_MS" \
  --argjson max_packet "$LARGE_PACKET_MAX" --argjson copy_range "$LARGE_PACKET_COPY" \
  '{tcp_stream_bytes:$stream_bytes,held_accept_ms:$held_ms,largest_observed_ipv4_packet:$max_packet,nfqueue_max_packet_len:$copy_range,stream_reassembled_exactly:true}')
if [[ "$LARGE_BYTES" -gt 2048 && "$LARGE_PACKET_COPY" -eq 65535 ]]; then
  record_case "6 TCP payload larger than 2048 bytes" PASS "10KiB+ TCP stream held then accepted intact with 65535-byte copy range" "$LARGE_METRICS"
else
  record_case "6 TCP payload larger than 2048 bytes" FAIL "large stream or NFQUEUE copy range assertion failed" "$LARGE_METRICS"
fi
stop_capture_or_fail

# 7. Drop unforwarded client bytes and use raw IPv4 RSTs with endpoint-correct
# sequence numbers. Both application sockets must report reset, then reconnect.
begin_scenario "7 two-sided RST and reconnect"
start_capture rst-reconnect || fatal "Could not start endpoint pcaps for RST scenario"
new_connection || fatal "Could not open RST test flow"
RST_ID=$CLIENT_ID
RST_PORT=$CLIENT_PORT
set_rule 'RST-DROP:' c2s drop 100
RST_DENIED='RST-DROP:withheld-by-drop'
SEND_BODY=$(jq -cn --arg data "$RST_DENIED" '{data:$data}')
endpoint client POST "/send?id=$RST_ID" "$SEND_BODY" >/dev/null
wait_held 'RST-DROP:' 1 || fatal "RST scenario's denied payload was not held"
wait_event_verdict 'RST-DROP:' drop || fatal "RST scenario's denied payload was not dropped"
SEQ=$(fw GET "/sequences?client_port=$RST_PORT")
SEQ_CLIENT=$(jq -er .expected_client <<<"$SEQ")
SEQ_SERVER=$(jq -er .expected_server <<<"$SEQ")
RST_SERVER_BODY=$(jq -cn --argjson port "$RST_PORT" --argjson seq "$SEQ_SERVER" \
  '{target:"server",client_port:$port,seq:$seq}')
RST_SERVER_SENT=$(fw POST /inject-rst "$RST_SERVER_BODY")
RST_CLIENT_BODY=$(jq -cn --argjson port "$RST_PORT" --argjson seq "$SEQ_CLIENT" \
  '{target:"client",client_port:$port,seq:$seq}')
RST_CLIENT_SENT=$(fw POST /inject-rst "$RST_CLIENT_BODY")
CLIENT_RESET=""
SERVER_RESET=""
for _ in $(seq 1 50); do
  CLIENT_RESET=$(endpoint client GET "/conn?id=$RST_ID")
  SERVER_RESET=$(endpoint server GET "/conn?id=$RST_ID")
  if jq -e '.read_error != "" and .read_error != "EOF"' <<<"$CLIENT_RESET" >/dev/null &&
    jq -e '.read_error != "" and .read_error != "EOF"' <<<"$SERVER_RESET" >/dev/null; then
    break
  fi
  sleep 0.1
done
CLIENT_ERROR=$(jq -r .read_error <<<"$CLIENT_RESET")
SERVER_ERROR=$(jq -r .read_error <<<"$SERVER_RESET")
RESET_OK=1
if [[ -z "$CLIENT_ERROR" || "$CLIENT_ERROR" == EOF || -z "$SERVER_ERROR" || "$SERVER_ERROR" == EOF ]]; then RESET_OK=0; fi
OLD_PORT=$RST_PORT
new_connection || fatal "The same client application could not reconnect after two-sided reset"
RECONNECT_ID=$CLIENT_ID
RECONNECT_PORT=$CLIENT_PORT
RECONNECT_DATA='reconnect-after-two-sided-rst'
SEND_BODY=$(jq -cn --arg data "$RECONNECT_DATA" '{data:$data}')
endpoint client POST "/send?id=$RECONNECT_ID" "$SEND_BODY" >/dev/null
wait_received server "$RECONNECT_ID" "$RECONNECT_DATA" || fatal "New connection after RST did not work"
if [[ "$OLD_PORT" == "$RECONNECT_PORT" ]]; then RESET_OK=0; fi
RST_METRICS=$(jq -cn --argjson server_seq "$SEQ_SERVER" --argjson client_seq "$SEQ_CLIENT" \
  --arg client_error "$CLIENT_ERROR" --arg server_error "$SERVER_ERROR" \
  --argjson old_port "$OLD_PORT" --argjson new_port "$RECONNECT_PORT" \
  --argjson server_rst "$RST_SERVER_SENT" --argjson client_rst "$RST_CLIENT_SENT" \
  '{rst_to_server_seq:$server_seq,rst_to_client_seq:$client_seq,client_socket_error:$client_error,server_socket_error:$server_error,old_source_port:$old_port,reconnect_source_port:$new_port,rst_to_server:$server_rst,rst_to_client:$client_rst,reconnect_payload:"reconnect-after-two-sided-rst"}')
if [[ "$RESET_OK" -eq 1 ]]; then
  record_case "7 two-sided RST and reconnect" PASS "both endpoint sockets reported non-EOF read errors; a new source port reconnected" "$RST_METRICS"
else
  record_case "7 two-sided RST and reconnect" FAIL "two-sided socket reset or distinct-source-port reconnect assertion failed" "$RST_METRICS"
fi
stop_capture_or_fail

# 8. RFC 5961 evidence probe: the first in-window but inexact RST is not a hard
# gate; if a challenge ACK is observed, retry with its ACK number and inspect
# the client socket result.
begin_scenario "8 RFC 5961 challenge-ACK observation"
start_capture challenge-ack || fatal "Could not start endpoint pcaps for challenge-ACK probe"
new_connection || fatal "Could not open challenge-ACK test flow"
CHALLENGE_ID=$CLIENT_ID
CHALLENGE_PORT=$CLIENT_PORT
CHALLENGE_SEQ=$(fw GET "/sequences?client_port=$CHALLENGE_PORT")
CHALLENGE_EXPECTED=$(jq -er .expected_client <<<"$CHALLENGE_SEQ")
BAD_SEQ=$((CHALLENGE_EXPECTED + 1))
fw POST /clear-events '{}' >/dev/null
BAD_RST=$(jq -cn --argjson port "$CHALLENGE_PORT" --argjson seq "$BAD_SEQ" \
  '{target:"client",client_port:$port,seq:$seq}')
BAD_RST_SENT=$(fw POST /inject-rst "$BAD_RST")
CHALLENGE_EVENTS='{"events":[]}'
CHALLENGE_ACK=""
for _ in $(seq 1 40); do
  CHALLENGE_EVENTS=$(fw GET /events)
  CHALLENGE_ACK=$(jq -r --arg client_ip '10.250.0.10' --argjson expected "$CHALLENGE_EXPECTED" \
    '[.events[] | select(.src_ip == $client_ip and (((.flags / 16 | floor) % 2) == 1) and .payload_len == 0 and .ack == $expected) | .ack] | first // empty' \
    <<<"$CHALLENGE_EVENTS")
  [[ -n "$CHALLENGE_ACK" ]] && break
  sleep 0.1
done
RETRY_SENT='null'
RETRY_ERROR='not_attempted_no_challenge_ack'
CHALLENGE_SEEN=false
if [[ -n "$CHALLENGE_ACK" ]]; then
  CHALLENGE_SEEN=true
  RETRY_BODY=$(jq -cn --argjson port "$CHALLENGE_PORT" --argjson seq "$CHALLENGE_ACK" \
    '{target:"client",client_port:$port,seq:$seq}')
  RETRY_SENT=$(fw POST /inject-rst "$RETRY_BODY")
  RETRY_ERROR=''
  for _ in $(seq 1 40); do
    RETRY_SNAPSHOT=$(endpoint client GET "/conn?id=$CHALLENGE_ID")
    RETRY_ERROR=$(jq -r .read_error <<<"$RETRY_SNAPSHOT")
    if [[ -n "$RETRY_ERROR" && "$RETRY_ERROR" != EOF ]]; then break; fi
    sleep 0.1
  done
fi
CHALLENGE_METRICS=$(jq -cn --argjson bad_seq "$BAD_SEQ" --argjson observed "$CHALLENGE_SEEN" \
  --argjson challenge_ack "$([[ -n "$CHALLENGE_ACK" ]] && printf '%s' "$CHALLENGE_ACK" || printf null)" \
  --argjson expected "$CHALLENGE_EXPECTED" --arg retry_error "$RETRY_ERROR" \
  --argjson bad_rst "$BAD_RST_SENT" --argjson retry "$RETRY_SENT" \
  '{inexact_rst_seq:$bad_seq,challenge_ack_observed:$observed,challenge_ack_number:$challenge_ack,expected_receive_seq:$expected,retry_socket_error:$retry_error,bad_rst:$bad_rst,retry_rst:$retry}')
record_evidence challenge_ack "$CHALLENGE_METRICS"
if [[ -n "$CHALLENGE_ACK" && -n "$RETRY_ERROR" && "$RETRY_ERROR" != EOF ]]; then
  record_case "8 RFC 5961 challenge-ACK observation" EVIDENCE "challenge ACK observed; retry using its ACK number closed client socket" "$CHALLENGE_METRICS"
elif [[ -z "$CHALLENGE_ACK" ]]; then
  record_case "8 RFC 5961 challenge-ACK observation" EVIDENCE "Linux emitted no matching challenge ACK; the retry branch was not applicable" "$CHALLENGE_METRICS"
else
  record_case "8 RFC 5961 challenge-ACK observation" EVIDENCE "challenge ACK observed; retry socket outcome was $RETRY_ERROR" "$CHALLENGE_METRICS"
fi
close_endpoint server "$CHALLENGE_ID" || true
stop_capture_or_fail

# 9. Stop only this harness's queue socket, leave nft routing active, and verify
# a packet hitting queue 101 with no listener does not reach the application.
begin_scenario "9 unbound queue fails closed"
start_capture unbound-queue || fatal "Could not start endpoint pcaps for unbound-queue scenario"
new_connection || fatal "Could not open fail-closed test connection before stopping the queue"
UNBOUND_ID=$CLIENT_ID
PRE_STOP_HELD=$(fw GET /held | jq -r '.held | length')
if [[ "$PRE_STOP_HELD" -ne 0 ]]; then
  fatal "Outstanding held packets remain before unbound-queue scenario ($PRE_STOP_HELD)"
fi
fw POST /queue/stop '{}' >/dev/null || fatal "Could not stop the harness NFQUEUE socket"
UNBOUND_DATA='UNBOUND:must-not-forward'
SEND_BODY=$(jq -cn --arg data "$UNBOUND_DATA" '{data:$data}')
endpoint client POST "/send?id=$UNBOUND_ID" "$SEND_BODY" >/dev/null
sleep 1
UNBOUND_SNAPSHOT=$(endpoint server GET "/conn?id=$UNBOUND_ID")
UNBOUND_RECEIVED=$(jq -r .received <<<"$UNBOUND_SNAPSHOT")
UNBOUND_STATS=$(fw GET /stats)
UNBOUND_ACTIVE=$(jq -r .queue_active <<<"$UNBOUND_STATS")
UNBOUND_METRICS=$(jq -cn --arg received "$UNBOUND_RECEIVED" --argjson queue_active "$UNBOUND_ACTIVE" \
  --arg marker "$UNBOUND_DATA" --argjson held_before_stop "$PRE_STOP_HELD" \
  '{server_buffer:$received,expected_bytes:0,queue_active:$queue_active,marker:$marker,nft_rule_retained:true,held_before_queue_stop:$held_before_stop}')
if [[ -z "$UNBOUND_RECEIVED" && "$UNBOUND_ACTIVE" == false ]]; then
  record_case "9 unbound queue fails closed" PASS "no-bypass queue dropped data after userspace queue socket stopped" "$UNBOUND_METRICS"
else
  record_case "9 unbound queue fails closed" FAIL "traffic reached the server or userspace queue remained active" "$UNBOUND_METRICS"
fi
stop_capture_or_fail

# Persist actual SetVerdict return/error counters after the final scenario.
fw GET /stats >"$RESULTS_DIR/firewall-stats.json" || fatal "Could not retrieve final queue stats"
jq -e '.verdict_errors | length == 0' "$RESULTS_DIR/firewall-stats.json" >/dev/null || \
  record_evidence verdict_errors "$(jq -c .verdict_errors "$RESULTS_DIR/firewall-stats.json")"
record_latency_evidence "$(cat "$RESULTS_DIR/firewall-stats.json")"
record_evidence setverdict_semantics "$(jq -cn --arg source 'go-nfqueue v2.0.3 SetVerdict sends a netlink request without requesting a kernel ACK; nil means submitted without a local Send error, not confirmed disposition.' \
  --argjson stats "$(cat "$RESULTS_DIR/firewall-stats.json")" \
  '{observed_source_semantics:$source,observed_run_stats:$stats}')"
printf 'All required scenarios completed; artifacts are under %s\n' "$RESULTS_DIR"
