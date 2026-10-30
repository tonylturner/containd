#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Uses the IEC104 truth harness's receiver counters and lib60870 command client.

iec_modes_counts() {
  $CURL -H "$AUTH_HEADER" "${BASE}/firewall/shadow-counters" | jq -er --arg id "$1" \
    'select(.available) | .rules[] | select(.ruleId == $id) | .shadowMatches'
}
iec_modes_one() {
  local id=$1 decision=$2
  for _ in $(seq 1 30); do
    if [[ $(iec_modes_counts "$id") == 1 ]] &&
      $CURL -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&ruleId=$id&mode=monitor" |
      jq -e --arg d "$decision" 'any(.events[]; .attributes.decision == $d and .attributes.reason == "rule")' >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}
run_iec_rule_modes_matrix() {
  local capture=${SMOKE_DPI_CAPTURE:-nfqueue} policy_base cfg id eid order before writes out
  policy_base=$(jq --arg capture "$capture" --arg cc "$CC_DEV" --arg rtu "$RTU_DEV" --argjson l4 "$(jq '.firewall.rules' <<<"$BASELINE")" '
    .dataPlane.dpiMode="monitor" | .firewall.rules=$l4
    | if $capture == "afpacket" then .dataPlane.nfqueueGroup=0 | .dataPlane.captureInterfaces=[$cc,$rtu] else . end
    ' <<<"$EU_POLICY")
  for order in first last; do
    id=a-monitor;eid=z-enforce
    [[ $order == first ]] || { id=z-monitor;eid=a-enforce; }
    cfg=$(jq --arg id "$id" '.firewall.rules += [{id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"DENY"}]' <<<"$policy_base")
    apply_config "$cfg" 'monitor-only command' || return 1
    before=$(rtu_field commands_received);writes=$(rtu_field writes_applied)
    run_cmd direct "$ALLOWED_CA" "$ALLOWED_IOA" "$DCS_OPEN" >"$RESULTS_DIR/modes-command-$order.out" 2>&1 || return 1
    [[ $(rtu_field commands_received) == $((before+1)) && $(rtu_field writes_applied) == $((writes+1)) ]] || return 1
    iec_modes_one "$id" would_drop || return 1
    pass "$capture $order monitor DENY: receiver actuates; one shadow message"
    if [[ $capture == nfqueue ]]; then
      # Read-only enforce scope allows STARTDT but not the command; monitor
      # ALLOW must never satisfy that scope's fail-closed default.
      cfg=$(jq --arg id "$id" --arg eid "$eid" '.firewall.rules += [
        {id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"ALLOW"},
        {id:$eid,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"enforce",readOnly:true},action:"ALLOW"}]' <<<"$policy_base")
      apply_config "$cfg" 'enforce envelope plus monitor ALLOW' || return 1
      before=$(rtu_field commands_received);writes=$(rtu_field writes_applied)
      out=$(malformer -scenario dc-execute -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE" -hold 2s)
      [[ $(socket_of "$out") == reset && $(rtu_field commands_received) == "$before" && $(rtu_field writes_applied) == "$writes" ]] || return 1
      iec_modes_one "$id" would_allow || return 1
      pass "$order monitor ALLOW cannot admit a command in an enforce envelope"
      cfg=$(jq --arg id "$id" --arg eid "$eid" '.dataPlane.dpiIcsParsing={iec104:"strict"} | .firewall.rules += [
        {id:$id,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[46],direction:"request"},action:"DENY"},
        {id:$eid,protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"enforce"},action:"ALLOW"}]' <<<"$policy_base")
      apply_config "$cfg" 'strict scope plus monitor DENY' || return 1
      before=$(rtu_field commands_received)
      out=$(malformer -scenario reserved-bits -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE" -hold 2s)
      [[ $(socket_of "$out") == reset && $(rtu_field commands_received) == "$before" ]] || return 1
      iec_modes_one "$id" would_drop || return 1
      $CURL -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&mode=enforce" |
        jq -e --arg id "$eid" 'any(.events[]; .attributes.reason == "nonconformant" and .attributes.scopeId == $id and .attributes.findingCode == "iec104.reserved_bits" and .attributes.ruleId == null and .attributes.action == null)' >/dev/null || return 1
      pass "$order strict denial is scope-attributed, independent of monitor DENY"
    fi
  done
  # The RTU's CA 1 GI emits one Type 13 ASDU with five IOAs, received by CC.
  # Its periodic Type 13 uses a different COT and cannot inflate this counter.
  cfg=$(jq '.firewall.rules += [{id:"multi-object",protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor",typeIds:[13],direction:"response",cot:[20]},action:"DENY"}]' <<<"$policy_base")
  apply_config "$cfg" 'multi-object counter' || return 1
  run_cmd gi "$ALLOWED_CA" >"$RESULTS_DIR/modes-gi.out" 2>&1 || return 1
  [[ $(grep -c 'type=13 cot=20' "$RESULTS_DIR/modes-gi.out") == 5 ]] || return 1
  iec_modes_one multi-object would_drop || return 1
  pass "$capture five received Type 13 objects count as one shadow message"
}
