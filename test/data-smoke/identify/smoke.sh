#!/usr/bin/env bash
# Sourced by scripts/smoke-dpi.sh after the standard-port regression probes.
# The caller supplies compose, API helpers, assertion functions and isolation.

run_identification_probes() {
  if [[ "$SMOKE_DPI_CAPTURE" == "nfqueue" ]]; then
    if "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=1000" | jq -e 'all(.[]; .proto != "identify")' >/dev/null; then
      pass "NFQUEUE produced no identification events"
    else
      check_fail "NFQUEUE unexpectedly produced identification events"
    fi
    return
  fi

  # Add L4 delivery permissions only. ICS rules retain their registered ports.
  UPDATED_CFG=$(jq --argjson clients "$CLIENT_SOURCES" --arg server "${WAN_NET}.4/32" '
    .dataplane.dpiIcsProtocols.iec104 = true
    | .dataplane.dpiIcsParsing.modbus = "tolerant"
    | .firewall.rules += [
      {id:"smoke-identify-delivery", sources:$clients, destinations:[$server],
       protocols:[{name:"tcp",port:"1502"},{name:"tcp",port:"12404"}], action:"ALLOW"},
      {id:"smoke-iec104-scope", protocols:[{name:"tcp",port:"2404"}],
       ics:{protocol:"iec104",mode:"monitor"}, action:"ALLOW"}]
  ' <<<"$UPDATED_CFG")
  local code
  code=$(cas_write "$WORK_DIR/config.revision" curl -s --max-time 10 -w '%{http_code}' -o "$WORK_DIR/identify-save.json" \
    -H "$AUTH_HEADER" -H 'Content-Type: application/json' -X POST "${BASE}/config" --data-binary @- <<<"$UPDATED_CFG")
  [[ "$code" == 200 ]] || { log "identification config save failed: $(cat "$WORK_DIR/identify-save.json")"; exit 1; }
  # shellcheck disable=SC2034 # apply_snapshot consumes this caller-owned value.
  DATAPLANE_CFG=$(jq '.dataplane' <<<"$UPDATED_CFG")
  apply_snapshot

  # Always rebuild the listener from current sources, including when the
  # firewall image is reused with SMOKE_BUILD=0. This is a real RTU listener,
  # not a port-forwarding proxy to TCP/2404.
  export IEC104_ENDPOINT_IMAGE=${IEC104_ENDPOINT_IMAGE:-containd-iec104-endpoint:${SMOKE_PROJECT}-identify}
  compose --profile identify build identify_rtu
  compose --profile identify up -d --no-build identify_rtu identify_cc
  for _ in $(seq 1 30); do
    if compose logs identify_rtu | grep -q 'RTU listening on 0.0.0.0:12404'; then break; fi
    sleep 0.2
  done
  compose logs identify_rtu | grep -q 'RTU listening on 0.0.0.0:12404'
  compose exec -d -e MODBUS_PORT=1502 -e MODBUS_STATE_FILE=/tmp/identify-state.json \
    -e MODBUS_REQUEST_LOG=/tmp/identify-requests.jsonl modbus_server python /opt/modbus/server.py
  for _ in $(seq 1 30); do
    if compose exec -T modbus_server test -s /tmp/identify-state.json; then break; fi
    sleep 0.2
  done
  compose exec -T modbus_server test -s /tmp/identify-state.json

  local server_capture client_capture capture_ok=1
  compose exec -T modbus_server python -u - <test/data-smoke/identify/reset_capture.py >"$WORK_DIR/identify-server-capture.out" 2>&1 &
  server_capture=$!
  compose exec -T ot_client python -u - <test/data-smoke/identify/reset_capture.py >"$WORK_DIR/identify-client-capture.out" 2>&1 &
  client_capture=$!
  for _ in $(seq 1 30); do
    if grep -q '^READY$' "$WORK_DIR/identify-server-capture.out" && grep -q '^READY$' "$WORK_DIR/identify-client-capture.out"; then break; fi
    sleep 0.1
  done
  grep -q '^READY$' "$WORK_DIR/identify-server-capture.out"
  grep -q '^READY$' "$WORK_DIR/identify-client-capture.out"

  local since mb_port mb_filter iec_filter mb_connection
  since=$(date -u +%s)
  if compose exec -T ot_client python /opt/modbus/client.py read "$MODBUS_DST" 1502 >"$WORK_DIR/identify-modbus.out" 2>&1; then
    pass "Modbus TCP/1502 read and reply reached their endpoints"
  else
    check_fail "Modbus TCP/1502 read failed: $(cat "$WORK_DIR/identify-modbus.out")"
  fi
  mb_port=$(awk '$1 == "READ_PORT" {print $2}' "$WORK_DIR/identify-modbus.out" | tr -d '\r')
  [[ "$mb_port" =~ ^[0-9]+$ ]] || { log "alternate read has no source port"; exit 1; }
  # Exact connection, not a generic protocol hit or the final cache state.
  mb_filter="[.[] | select(.proto == \"identify\" and .srcPort == $mb_port and .attributes.service_port == 1502 and .srcIp == env.MODBUS_SRC and .dstIp == env.MODBUS_DST and ((.timestamp | sub(\"\\\\.[0-9]+Z$\"; \"Z\") | fromdateiso8601) >= $since))]"
  if wait_for_jq "${BASE}/events?limit=1000" "$mb_filter | length == 1 and all(.[]; .attributes.protocol == \"modbus\" and .attributes.identification_state == \"confirmed\" and .attributes.binding == \"observation\" and .attributes.outside_rule_port_scope == true and .attributes.syn_coverage == [true,true])"; then
    pass "TCP/1502 has exactly one content-confirmed, outside-scope Modbus observation identity"
  else
    check_fail "TCP/1502 identification missing, duplicated or not content-confirmed outside scope"
  fi
  local connection
  connection=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=1000" | jq -er "$mb_filter | .[0].transportConnectionId // empty")
  if wait_for_jq "${BASE}/events?limit=1000" "[.[] | select(.transportConnectionId == \"$connection\" and .proto == \"modbus\" and .attributes.observation_only == true and .attributes.transaction_id == 1)] | length == 2 and any(.[]; .kind == \"request\" and .srcPort == $mb_port and .dstPort == 1502) and any(.[]; .kind == \"response\" and .srcPort == 1502) and ([.[].flowId] | unique | length) == 2"; then
    pass "TCP/1502 observation decoded request and reply exactly once, with directional flow IDs"
  else
    check_fail "TCP/1502 lacks exact directional observation request/reply semantics"
  fi

  mb_connection=$connection

  # One one-shot real lib60870 connection, with server state and monitor data.
  if compose exec -T identify_cc iec104ep cmd "$MODBUS_DST" 12404 gi 1 >"$WORK_DIR/identify-iec104.out" 2>&1 &&
    grep -q 'ioa=1001' "$WORK_DIR/identify-iec104.out"; then
    pass "IEC104 TCP/12404 GI received the real RTU monitoring object"
  else
    check_fail "IEC104 TCP/12404 client lacks IOA 1001: $(cat "$WORK_DIR/identify-iec104.out")"
  fi
  iec_filter="[.[] | select(.proto == \"identify\" and .attributes.service_port == 12404 and ((.timestamp | sub(\"\\\\.[0-9]+Z$\"; \"Z\") | fromdateiso8601) >= $since))]"
  if wait_for_jq "${BASE}/events?limit=1000" "$iec_filter | length == 1 and all(.[]; .attributes.protocol == \"iec104\" and .attributes.identification_state == \"confirmed\" and .attributes.binding == \"observation\" and .attributes.outside_rule_port_scope == true and .attributes.syn_coverage == [true,true])"; then
    pass "TCP/12404 has exactly one content-confirmed, outside-scope IEC104 observation identity"
  else
    check_fail "TCP/12404 identification missing, duplicated or not content-confirmed outside scope"
  fi
  connection=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=1000" | jq -er "$iec_filter | .[0].transportConnectionId // empty")
  if wait_for_jq "${BASE}/events?limit=1000" "[.[] | select(.transportConnectionId == \"$connection\" and .proto == \"iec104\" and .attributes.observation_only == true)] | any(.[]; .attributes.direction == \"request\" and .dstPort == 12404 and .attributes.type_id == 100 and .attributes.ca == 1) and any(.[]; .attributes.direction == \"response\" and .srcPort == 12404 and .attributes.ca == 1 and .attributes.ioa == 1001 and (.attributes.session_id | length) > 0) and ([.[].flowId] | unique | length) == 2 and ([.[] | [.attributes.apdu_id,.attributes.ioa,.kind]] | length) == ([.[] | [.attributes.apdu_id,.attributes.ioa,.kind]] | unique | length)"; then
    pass "TCP/12404 observation decoded GI request and RTU reply with correct directions and frozen APDU identities"
  else
    check_fail "TCP/12404 lacks directional GI/monitor observation semantics or replay duplicated an APDU"
  fi
  wait "$server_capture" || capture_ok=0
  wait "$client_capture" || capture_ok=0
  if [[ "$capture_ok" == 1 ]] && "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?limit=1000" | jq -e \
    --arg mb "$mb_connection" --arg iec "$connection" \
    'all(.[]; (.transportConnectionId != $mb and .transportConnectionId != $iec) or (.kind | startswith("ics.") | not))' >/dev/null; then
    pass "Both endpoint captures saw alternate-port packets; no reset or enforcement decision attempts"
  else
    check_fail "Alternate-port reset capture failed: $(cat "$WORK_DIR/identify-server-capture.out" "$WORK_DIR/identify-client-capture.out")"
  fi
  assert_no_dynamic_block "$MODBUS_SRC" 1502
  assert_no_dynamic_block "$MODBUS_SRC" 12404
}
