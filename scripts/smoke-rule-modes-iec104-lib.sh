#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Uses the IEC104 truth harness's receiver counters and lib60870 command client.

iec_modes_fail() {
  log "FAIL rule modes: $*" >&2
  log "RTU state: $(rtu_state)" >&2
  log "shadow counters: $("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/firewall/shadow-counters")" >&2
  log "monitor events: $("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&mode=monitor")" >&2
  return 1
}

iec_modes_evidence() {
  local id=$1 decision=$2 expected=${3:-1} counters events field=wouldDeny
  [[ $decision != would_allow ]] || field=wouldAllow
  for _ in $(seq 1 30); do
    counters=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/firewall/shadow-counters")
    events=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&ruleId=$id&mode=monitor")
    if echo "$counters" | jq -e --arg id "$id" --arg f "$field" --argjson n "$expected" '
      .available and .unit == "messages" and any(.rules[]; .ruleId == $id and .shadowMatches == $n and .[$f] == $n)' >/dev/null &&
      echo "$events" | jq -e --arg d "$decision" 'any(.events[]; .attributes.decision == $d and .attributes.reason == "rule")' >/dev/null; then
      printf '%s\n' "$counters" >"$RESULTS_DIR/modes-$id-$decision-$expected-counters.json"
      printf '%s\n' "$events" >"$RESULTS_DIR/modes-$id-$decision-$expected-events.json"
      rtu_state >"$RESULTS_DIR/modes-$id-$decision-$expected-rtu.json"
      return 0
    fi
    sleep 0.2
  done
  iec_modes_fail "rule=$id expected shadowMatches=$expected, $field=$expected and decision=$decision; counters=$counters events=$events"
}

# Keep IDs fixed: first/last is the monitor's actual array position relative
# to enforce, not its lexical rule ID. Only coexistence policies have a pair.
iec_modes_order() {
  jq --arg order "$1" '
    if $order == "last" then .firewall.rules |= (.[:-2] + (.[-2:] | reverse)) else . end'
}

iec_modes_install() {
  local cfg=$1 label=$2 order=$3 running
  cfg=$(iec_modes_order "$order" <<<"$cfg") || return 1
  apply_config "$cfg" "$label" || return 1
  # apply_config stages and directly applies the snapshot. Promote it as well
  # so the authoritative running bank can prove the installed array order.
  cas_write "$WORK_DIR/config.revision" "${CURL[@]}" -H "$AUTH_HEADER" \
    -X POST "${BASE}/config/commit" >"$RESULTS_DIR/modes-$order-$label-commit.json" || return 1
  running=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/config") || return 1
  printf '%s\n' "$running" >"$RESULTS_DIR/modes-$order-$label-running.json"
  jq -e --argjson expected "$(jq '[.firewall.rules[].id]' <<<"$cfg")" \
    '[.firewall.rules[].id] == $expected' <<<"$running" >/dev/null || {
    iec_modes_fail "$order $label: running rules do not match the installed order"; return 1;
  }
}

run_iec_rule_modes_matrix() {
  local capture=${SMOKE_DPI_CAPTURE:-nfqueue} policy_base cfg id eid order before writes out after written status objects events
  policy_base=$(jq --arg capture "$capture" --arg cc "$CC_DEV" --arg rtu "$RTU_DEV" --argjson l4 "$(jq '.firewall.rules' <<<"$BASELINE")" '
    .dataplane.dpiMode="monitor" | .firewall.rules=$l4
    | if $capture == "afpacket" then .dataplane.nfqueueGroup=0 | .dataplane.captureInterfaces=[$cc,$rtu] else . end
    ' <<<"$EU_POLICY")
  for order in first last; do
    id=a-monitor;eid=z-enforce
    cfg=$(jq --arg id "$id" '.firewall.rules += [{id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"DENY"}]' <<<"$policy_base")
    apply_config "$cfg" 'monitor-only command' || { iec_modes_fail "$capture $order: policy apply failed"; return 1; }
    before=$(rtu_field commands_received);writes=$(rtu_field writes_applied)
    # This RTU requires select-before-operate on the same connection. A
    # direct execute is delivered but rejected by the RTU, not the firewall.
    status=0
    run_cmd sbo "$ALLOWED_CA" "$ALLOWED_IOA" "$DCS_OPEN" >"$RESULTS_DIR/modes-command-$order.out" 2>&1 || status=$?
    after=$(rtu_field commands_received); written=$(rtu_field writes_applied)
    [[ $status == 0 && $after == $((before+2)) && $written == $((writes+1)) ]] || {
      cat "$RESULTS_DIR/modes-command-$order.out" >&2
      iec_modes_fail "$capture $order monitor DENY SBO: client exit=$status expected=0; commands $before->$after expected=$((before+2)); writes $writes->$written expected=$((writes+1))"
      return 1
    }
    iec_modes_evidence "$id" would_drop 2 || return 1 # select and execute are two decoded messages
    pass "$capture $order monitor DENY: receiver actuates SBO; two shadow messages" "client exit=$status; commands $before->$after; writes $writes->$written"
    if [[ $capture == nfqueue ]]; then
      # Read-only enforce scope allows STARTDT but not the command; monitor
      # ALLOW must never satisfy that scope's fail-closed default.
      cfg=$(jq --arg id "$id" --arg eid "$eid" '.firewall.rules += [
        {id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"ALLOW"},
        {id:$eid,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"enforce",readOnly:true},action:"ALLOW"}]' <<<"$policy_base")
      iec_modes_install "$cfg" envelope "$order" || { iec_modes_fail "$capture $order: policy apply failed"; return 1; }
      before=$(rtu_field commands_received);writes=$(rtu_field writes_applied)
      out=$(malformer -scenario dc-execute -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE" -hold 2s) || {
        iec_modes_fail "$capture $order: command probe failed: $out"; return 1;
      }
      after=$(rtu_field commands_received); written=$(rtu_field writes_applied)
      if ! { [[ $(socket_of "$out") == reset && $after == "$before" && $written == "$writes" ]] && iec_probe_sent 0 "$out"; }; then
        iec_modes_fail "$capture $order enforce envelope: expected reset, no delivery/writes; probe=$out commands $before->$after writes $writes->$written"; return 1;
      fi
      iec_modes_evidence "$id" would_allow || return 1
      printf '%s\n' "$out" >"$RESULTS_DIR/modes-$order-envelope-probe.json"
      pass "$order monitor ALLOW cannot admit a command in an enforce envelope"
      cfg=$(jq --arg id "$id" --arg eid "$eid" '.dataplane.dpiIcsParsing={iec104:"strict"} | .firewall.rules += [
        {id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"DENY"},
        {id:$eid,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"enforce"},action:"ALLOW"}]' <<<"$policy_base")
      iec_modes_install "$cfg" strict "$order" || { iec_modes_fail "$capture $order: policy apply failed"; return 1; }
      before=$(rtu_field commands_received)
      out=$(malformer -scenario reserved-bits -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE" -hold 2s) || {
        iec_modes_fail "$capture $order: strict probe failed: $out"; return 1;
      }
      after=$(rtu_field commands_received)
      if ! { [[ $(socket_of "$out") == reset && $after == "$before" ]] && iec_probe_sent 0 "$out"; }; then
        iec_modes_fail "$capture $order strict scope: expected reset and no delivery; probe=$out commands $before->$after"; return 1;
      fi
      iec_modes_evidence "$id" would_drop || return 1
      events=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&mode=enforce")
      echo "$events" |
        jq -e --arg id "$eid" 'any(.events[]; .attributes.reason == "nonconformant" and .attributes.scopeId == $id and .attributes.findingCode == "iec104.reserved_bits" and .attributes.ruleId == null and .attributes.action == null)' >/dev/null || { iec_modes_fail "$capture $order strict attribution: expected nonconformant/reserved_bits scope=$eid, no rule/action; events=$events"; return 1; }
      printf '%s\n' "$events" >"$RESULTS_DIR/modes-$order-strict-enforce-events.json"
      printf '%s\n' "$out" >"$RESULTS_DIR/modes-$order-strict-probe.json"
      pass "$order strict denial is scope-attributed, independent of monitor DENY"
    fi
  done
  # The RTU's CA 1 GI emits one Type 13 ASDU with five IOAs, received by CC.
  # Its periodic Type 13 uses a different COT and cannot inflate this counter.
  cfg=$(jq '.firewall.rules += [{id:"multi-object",protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[13],direction:"response",cot:[20]},action:"DENY"}]' <<<"$policy_base")
  apply_config "$cfg" 'multi-object counter' || { iec_modes_fail "$capture $order: policy apply failed"; return 1; }
  run_cmd gi "$ALLOWED_CA" >"$RESULTS_DIR/modes-gi.out" 2>&1 || {
    cat "$RESULTS_DIR/modes-gi.out" >&2
    iec_modes_fail "$capture: GI client failed"; return 1;
  }
  objects=$(grep -c 'RCVD type=13 cot=20 negative=0 elements=5 ' "$RESULTS_DIR/modes-gi.out")
  [[ $objects == 1 ]] || {
    cat "$RESULTS_DIR/modes-gi.out" >&2
    iec_modes_fail "$capture GI: expected one received Type 13 ASDU containing five objects; matching ASDUs=$objects"; return 1;
  }
  iec_modes_evidence multi-object would_drop || return 1
  pass "$capture five received Type 13 objects count as one shadow message"
}
