#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by smoke-dpi.sh: tolerant and strict ICS parsing on live Modbus
# traffic. Uses the caller's compose, pass, check_fail, timestamp,
# engine_apply, engine_apply_id, CURL, AUTH_HEADER, BASE, WORK_DIR, UPDATED_CFG, DATAPLANE_CFG,
# SMOKE_DPI_CAPTURE and MODBUS_DST.
#
# Tolerant (the default, no dpiIcsParsing key) passes content it cannot vouch
# for inside a frame whose length it knows and raises one conformance alert
# per connection per finding; strict drops that content and resets the
# session. A lost frame boundary resets in both modes. Without an inline path
# (afpacket) the traffic runs in monitor mode, so strict reports would_drop and
# nothing is reset by the firewall.
# shellcheck disable=SC2016 # Dollar variables in jq programs are jq bindings.

PARSING_CODE="modbus.pid_nonzero"

# server_pid_fc3_requests PID: FC 3 requests the Modbus server decoded whose
# MBAP protocol identifier was PID.
server_pid_fc3_requests() {
  compose exec -T modbus_server sh -c 'cat /tmp/modbus-requests.jsonl 2>/dev/null || true' |
    jq -s --argjson pid "$1" '[.[] | select(.function_code == 3 and .protocol_id == $pid)] | length'
}

# push_parsing LABEL FILTER applies the jq FILTER to the harness config, saves
# it as the candidate (gating on HTTP 200) and pushes the dataplane document
# to the engine, which applies a parsing-only change to new decisions without
# rebuilding or resetting sessions.
push_parsing() {
  local label=$1 filter=$2 code
  UPDATED_CFG=$(jq "$filter" <<<"$UPDATED_CFG")
  DATAPLANE_CFG=$(jq '.dataplane' <<<"$UPDATED_CFG")
  code=$(echo "$UPDATED_CFG" | cas_write "$WORK_DIR/config.revision" curl -s --max-time 10 --connect-timeout 5 -w "%{http_code}" -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- -o "$WORK_DIR/parsing-config.out" || true)
  if [[ "$code" != "200" ]]; then
    check_fail "$label: config save failed (HTTP $code): $(head -c 300 "$WORK_DIR/parsing-config.out")"
    return 1
  fi
  code=$(engine_apply engine /internal/config "$WORK_DIR/parsing-engine.out" "$(engine_apply_id)" <<<"$DATAPLANE_CFG")
  if [[ "$code" != "200" ]]; then
    check_fail "$label: engine config failed (HTTP $code): $(head -c 300 "$WORK_DIR/parsing-engine.out")"
    return 1
  fi
  pass "$label: dpiIcsParsing $(jq -c '.dpiIcsParsing' <<<"$DATAPLANE_CFG")"
}

# port_events PORT SINCE OUT writes the telemetry events of the client
# connection on PORT recorded at or after SINCE to OUT.
port_events() {
  local port=$1 since=$2 out=$3
  "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=1000" 2>/dev/null | jq --argjson port "$port" --arg since "$since" '
    [.[] | select(.srcPort == $port
      and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= ($since | fromdateiso8601)))]' \
    >"$out" 2>/dev/null || printf '[]\n' >"$out"
}

# wait_port_events PORT SINCE OUT FILTER [JQ_ARG...] polls port_events for up
# to 20 s until the jq FILTER holds; the last snapshot stays in OUT.
wait_port_events() {
  local port=$1 since=$2 out=$3 filter=$4
  shift 4
  for _ in $(seq 1 20); do
    port_events "$port" "$since" "$out"
    if jq -e "$@" "$filter" "$out" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# event_summary OUT: the decision and alert evidence of a connection, for a
# failure message.
event_summary() {
  jq -c '[.[] | {kind, fc: .attributes.function_code, decision: .attributes.decision, reason: .attributes.reason,
    rule_id: .attributes.rule_id, action: .attributes.action, conformance: .attributes.conformance}]' "$1" | head -c 700
}

# probe_pid_nonzero PARSING sends two FC 3 reads with protocol identifier 1
# on one connection and asserts the outcome of PARSING (tolerant | strict)
# for this capture mode: delivery to the server, the request events'
# conformance codes, the nonconformant decision strict records, and exactly
# one ics-conformance alert for the connection naming the action taken.
probe_pid_nonzero() {
  local parsing=$1 status=0 since port before after reads out err evidence label
  local want_requests want_decision="" want_action events
  since=$(timestamp)
  before=$(server_pid_fc3_requests 1)
  compose exec -T ot_client python /opt/modbus/client.py pid-nonzero "$MODBUS_DST" 502 \
    >"$WORK_DIR/pid-$parsing.out" 2>"$WORK_DIR/pid-$parsing.err" || status=$?
  after=$(server_pid_fc3_requests 1)
  out=$(tr -d '\r' <"$WORK_DIR/pid-$parsing.out")
  err=$(tr -d '\r' <"$WORK_DIR/pid-$parsing.err" | tr '\n' ' ')
  port=$(awk '$1 == "PID_NONZERO_PORT" {print $2}' <<<"$out")
  reads=$(grep -c '^READ_OK' <<<"$out" || true)
  evidence="client exit $status; READ_OK replies $reads; PID 1 FC 3 requests at the server $before -> $after; $err"
  if [[ "$parsing" == strict && "$SMOKE_DPI_CAPTURE" == nfqueue ]]; then
    label="Strict: the PID 1 read is dropped before the server and the session reset"
    want_requests=1 want_decision=deny want_action="dropped and reset"
    if [[ "$status" -eq 3 && "$reads" -eq 0 && "$after" == "$before" && "$err" == *"Connection reset"* ]]; then
      pass "$label ($evidence)"
    else
      check_fail "$label ($evidence)"
    fi
  else
    want_requests=2 want_action=passed
    label="Tolerant: both PID 1 reads reach the server and are answered"
    if [[ "$parsing" == strict ]]; then
      label="Strict (monitor, no inline path): both PID 1 reads reach the server"
      want_decision=would_drop want_action="would drop"
    fi
    if [[ "$status" -eq 0 && "$reads" -eq 2 && "$after" == $((before + 2)) ]]; then
      pass "$label ($evidence)"
    else
      check_fail "$label ($evidence)"
    fi
  fi
  if [[ -z "$port" ]]; then
    check_fail "$parsing: the client reported no port, so its events cannot be checked ($evidence)"
    return
  fi
  events="$WORK_DIR/pid-$parsing-events.json"
  if wait_port_events "$port" "$since" "$events" \
    '[.[] | select(.proto == "modbus" and .kind == "request" and .attributes.function_code == 3
      and any(.attributes.conformance[]?; . == $code))] | length == $n' \
    --arg code "$PARSING_CODE" --argjson n "$want_requests"; then
    pass "$parsing: $want_requests FC 3 request event(s) on port $port keep their fields and carry conformance $PARSING_CODE"
  else
    check_fail "$parsing: expected $want_requests request event(s) with conformance $PARSING_CODE on port $port: $(event_summary "$events")"
  fi
  if [[ -n "$want_decision" ]]; then
    if wait_port_events "$port" "$since" "$events" \
      'any(.[]; .proto == "modbus" and .kind == "ics.decision" and .attributes.decision == $d
        and .attributes.reason == "nonconformant" and any(.attributes.conformance[]?; . == $code))' \
      --arg d "$want_decision" --arg code "$PARSING_CODE"; then
      pass "$parsing: ics.decision $want_decision with reason nonconformant on port $port"
    else
      check_fail "$parsing: no ics.decision $want_decision with reason nonconformant on port $port: $(event_summary "$events")"
    fi
  fi
  # Every request event is already recorded, so every alert of the
  # connection is too: the second identical request must not add one.
  port_events "$port" "$since" "$events"
  if jq -e --arg code "$PARSING_CODE" --arg a "$want_action" \
    '[.[] | select(.proto == "ids" and .kind == "alert" and .attributes.rule_id == "ics-conformance"
      and any(.attributes.conformance[]?; . == $code))] | length == 1 and .[0].attributes.action == $a' \
    "$events" >/dev/null 2>&1; then
    pass "$parsing: exactly one ics-conformance alert ($want_action) for the connection on port $port"
  else
    check_fail "$parsing: expected exactly one ics-conformance alert ($want_action) on port $port: $(event_summary "$events")"
  fi
}

# probe_bad_length PARSING sends an FC 3 read whose MBAP length is 1 (outside
# 2..254): the frame boundary is lost, so the firewall resets the session in
# both parsing modes when inline, records a malformed event without
# conformance codes and raises no conformance alert.
probe_bad_length() {
  local parsing=$1 status=0 since port out err evidence label want events
  since=$(timestamp)
  compose exec -T ot_client python /opt/modbus/client.py bad-length "$MODBUS_DST" 502 \
    >"$WORK_DIR/badlen-$parsing.out" 2>"$WORK_DIR/badlen-$parsing.err" || status=$?
  out=$(tr -d '\r' <"$WORK_DIR/badlen-$parsing.out" | tr '\n' ' ')
  err=$(tr -d '\r' <"$WORK_DIR/badlen-$parsing.err" | tr '\n' ' ')
  port=$(awk '$1 == "BAD_LENGTH_PORT" {print $2}' <<<"$out")
  evidence="client exit $status (want 3): $out$err"
  if [[ "$SMOKE_DPI_CAPTURE" == nfqueue ]]; then
    label="$parsing: a lost MBAP frame boundary (length 1) resets the session"
    want="Connection reset"
  else
    label="$parsing (monitor, no inline path): a lost MBAP frame boundary (length 1) reaches the server, which closes"
    want="connection closed"
  fi
  if [[ "$status" -eq 3 && "$err" == *"$want"* ]]; then
    pass "$label ($evidence)"
  else
    check_fail "$label ($evidence)"
  fi
  if [[ -z "$port" ]]; then
    check_fail "$parsing: the bad-length client reported no port, so its events cannot be checked ($evidence)"
    return
  fi
  events="$WORK_DIR/badlen-$parsing-events.json"
  if wait_port_events "$port" "$since" "$events" \
    'any(.[]; .proto == "modbus" and .kind == "malformed" and (.attributes.error | tostring | contains("invalid MBAP length 1"))
      and (.attributes | has("conformance") | not))
     and ([.[] | select(.proto == "ids" and .kind == "alert" and .attributes.rule_id == "ics-conformance")] | length == 0)'; then
    pass "$parsing: the lost boundary is a malformed event without conformance codes and raises no conformance alert (port $port)"
  else
    check_fail "$parsing: expected a malformed event without codes and no conformance alert on port $port: $(event_summary "$events")"
  fi
  if [[ "$SMOKE_DPI_CAPTURE" == nfqueue ]]; then
    if wait_port_events "$port" "$since" "$events" \
      'any(.[]; .proto == "modbus" and .kind == "ics.decision" and .attributes.decision == "deny"
        and .attributes.reason == "stream_error" and (.attributes.error | tostring | contains("invalid MBAP length")))'; then
      pass "$parsing: the lost boundary fails closed (ics.decision deny, reason stream_error) on port $port"
    else
      check_fail "$parsing: no fail-closed ics.decision for the lost boundary on port $port: $(event_summary "$events")"
    fi
  fi
}

# run_parsing_probes proves tolerant parsing by default, then strict Modbus
# parsing pushed through the API, and restores the default.
run_parsing_probes() {
  log "Testing tolerant and strict Modbus parsing..."
  if "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/config" | jq -e '.dataplane.dpiIcsParsing == null' >/dev/null 2>&1; then
    pass "Tolerant parsing is the default: the saved config has no dpiIcsParsing"
  else
    check_fail "the saved config already sets dpiIcsParsing: $("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/config" | jq -c '.dataplane.dpiIcsParsing')"
  fi
  probe_pid_nonzero tolerant
  probe_bad_length tolerant
  push_parsing "Strict Modbus parsing saved and pushed to the engine" '.dataplane.dpiIcsParsing = {"modbus": "strict"}' || true
  probe_pid_nonzero strict
  if compose exec -T ot_client python /opt/modbus/client.py read "$MODBUS_DST" 502 >"$WORK_DIR/strict-read.out" 2>"$WORK_DIR/strict-read.err" &&
    grep -q '^READ_OK' "$WORK_DIR/strict-read.out"; then
    pass "Strict: a new connection with protocol identifier 0 still reads ($(tr -d '\r' <"$WORK_DIR/strict-read.out"))"
  else
    check_fail "Strict: a conformant read failed: $(tr -d '\r' <"$WORK_DIR/strict-read.err" | tr '\n' ' ')"
  fi
  probe_bad_length strict
  push_parsing "Tolerant parsing restored" 'del(.dataplane.dpiIcsParsing)' || true
}
