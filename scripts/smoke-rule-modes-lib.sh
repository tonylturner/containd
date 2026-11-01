#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced after smoke-dpi's isolated stack, routes and initial policy are ready.
# Receiver state and decoded-message counters are independent assertions.

modes_fail() {
  log "FAIL rule modes: $*" >&2
  log "receiver state: $(server_state)" >&2
  log "shadow counters: $("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/firewall/shadow-counters")" >&2
  return 1
}

modes_apply() {
  UPDATED_CFG=$1
  local code
  code=$(printf '%s' "$UPDATED_CFG" | cas_write "$WORK_DIR/config.revision" "${CURL[@]}" -H "$AUTH_HEADER" -H 'Content-Type: application/json' \
    -X POST "${BASE}/config" --data-binary @- -o "$WORK_DIR/modes-save.json" -w '%{http_code}')
  [[ $code == 200 ]] || { modes_fail "config save HTTP=$code expected=200; response=$(cat "$WORK_DIR/modes-save.json")"; return 1; }
  DATAPLANE_CFG=$(jq '.dataplane' <<<"$UPDATED_CFG")
  export DATAPLANE_CFG
  apply_snapshot || { modes_fail "engine snapshot apply failed"; return 1; }
}

modes_counter() {
  "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/firewall/shadow-counters" |
    jq -er --arg id "$1" 'select(.available and .unit == "messages") | .rules[] | select(.ruleId == $id)'
}

modes_evidence() {
  local id=$1 decision=$2 field=$3
  for _ in $(seq 1 30); do
    if modes_counter "$id" | jq -e --arg f "$field" '.shadowMatches == 1 and .[$f] == 1' >/dev/null &&
      "${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&ruleId=$id&mode=monitor" |
        jq -e --arg d "$decision" 'any(.events[]; .attributes.decision == $d and .attributes.reason == "rule")' >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  modes_fail "rule=$id expected shadowMatches=1, $field=1 and event decision=$decision; events=$("${CURL[@]}" -H "$AUTH_HEADER" "${BASE}/events?kind=ics.decision&ruleId=$id&mode=monitor")"
}

run_rule_modes_matrix() {
  local policy_base=$UPDATED_CFG order trial active cfg id eid before after writes value status want field decision
  for order in first last; do
    for pair in 'DENY none pass' 'ALLOW DENY drop' 'DENY ALLOW pass' 'ALLOW none default-drop'; do
      read -r trial active want <<<"$pair"
      id="a-monitor-$trial-$active-$want"; eid=z-enforce
      [[ $order == first ]] || { id="z-monitor-$trial-$active-$want"; eid=a-enforce; }
      cfg=$(jq --arg trial "$trial" --arg active "$active" --arg want "$want" --arg id "$id" --arg eid "$eid" \
        --arg server "${WAN_NET}.4/32" --arg capture "$SMOKE_DPI_CAPTURE" '
        .dataplane.dpiMode="monitor" | .firewall.rules=[
          {id:$id, destinations:[$server], protocols:[{name:"tcp",port:"502"}],
           ics:{protocol:"modbus",mode:"monitor",direction:"request",functionCode:[6]},action:$trial}]
        | if $active != "none" then .firewall.rules += [{id:$eid,destinations:[$server],protocols:[{name:"tcp",port:"502"}],ics:{protocol:"modbus",mode:"enforce",functionCode:[6]},action:$active}] else . end
        | if $active == "none" and $want != "default-drop" then .firewall.rules += [{id:"ordinary-l4",protocols:[{name:"tcp",port:"502"}],action:"ALLOW"}] else . end
        # AF_PACKET cannot enforce ICS; use the same policy semantics only in queue mode.
        ' <<<"$policy_base")
      if [[ $SMOKE_DPI_CAPTURE == afpacket && $active != none ]]; then
        continue # mixed inline decisions are exercised in the NFQUEUE run
      fi
      modes_apply "$cfg" || return 1
      before=$(server_fc6_requests); writes=$(server_state | jq '.writes')
      value=$((writes + 16000)); status=0
      compose exec -T ot_client python /opt/modbus/client.py write "${WAN_NET}.4" 502 --value "$value" \
        >"$WORK_DIR/modes-client.out" 2>&1 || status=$?
      sleep 0.5
      after=$(server_fc6_requests)
      if [[ $want == pass ]]; then
        if ! [[ $status == 0 && $after == $((before + 1)) ]] ||
          ! server_state | jq -e --argjson v "$value" '.registers[1] == $v' >/dev/null; then
          modes_fail "$SMOKE_DPI_CAPTURE $order monitor=$trial enforce=$active: expected delivery and register=$value; status=$status FC6=$before->$after; client=$(cat "$WORK_DIR/modes-client.out")"
          return 1
        fi
      else
        [[ $status != 0 && $after == "$before" && $(server_state | jq '.writes') == "$writes" ]] || { modes_fail "$SMOKE_DPI_CAPTURE $order monitor=$trial enforce=$active: expected no delivery/writes; status=$status FC6=$before->$after writes before=$writes; client=$(cat "$WORK_DIR/modes-client.out")"; return 1; }
      fi
      if [[ $want != default-drop ]]; then
        decision=would_drop;field=wouldDeny
        [[ $trial == DENY ]] || { decision=would_allow; field=wouldAllow; }
        modes_evidence "$id" "$decision" "$field" || return 1
      else
        [[ $(modes_counter "$id" | jq '.shadowMatches') == 0 ]] || { modes_fail "$SMOKE_DPI_CAPTURE $order rule=$id: expected zero matches for default-dropped traffic"; return 1; }
      fi
      pass "$SMOKE_DPI_CAPTURE $order: monitor $trial + enforce $active => $want (receiver verified); client exit=$status FC6=$before->$after writes before=$writes receiver=$(server_state)"
    done
  done
  # DNAT: selectors name backend:502, not the public listen port 1502.
  cfg=$(jq --arg backend "${WAN_NET}.4" --arg capture "$SMOKE_DPI_CAPTURE" '
    .dataplane.dpiMode="monitor" | .firewall.rules=[{id:"dnat-monitor",destinations:[($backend+"/32")],protocols:[{name:"tcp",port:"502"}],ics:{protocol:"modbus",mode:"monitor",direction:"request",functionCode:[6]},action:"DENY"}]
    | .firewall.nat.portForwards=[{id:"modbus",enabled:true,ingressZone:"lan",proto:"tcp",listenPort:1502,destIp:$backend,destPort:502}]
    ' <<<"$policy_base")
  modes_apply "$cfg" || return 1
  before=$(server_fc6_requests)
  compose exec -T ot_client python /opt/modbus/client.py write "${LAN_NET}.2" 1502 --value 19001 || { modes_fail "$SMOKE_DPI_CAPTURE DNAT client failed"; return 1; }
  sleep 0.5
  [[ $(server_fc6_requests) == $((before+1)) ]] || { modes_fail "$SMOKE_DPI_CAPTURE DNAT: expected FC6=$((before+1)); observed=$(server_fc6_requests)"; return 1; }
  modes_evidence dnat-monitor would_drop wouldDeny || return 1
  pass "$SMOKE_DPI_CAPTURE DNAT monitor matches backend coordinates; receiver admitted by DNAT"
}
