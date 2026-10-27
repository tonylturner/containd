#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by smoke-iec104.sh: tolerant and strict IEC 104 parsing gates on
# content whose APDU length octet framed it, and the lost-length reset that
# both modes keep. Uses the caller's compose, malformer, socket_of,
# rtu_field, iec_event_since, apply_config, timestamp, gate_pass, gate_fail,
# fail, CURL, AUTH_HEADER, BASE, RESULTS_DIR, HOLD, EU_POLICY and the point
# map constants.
#
# Strict denies every event with conformance findings before any ALLOW
# (reason nonconformant; a matched DENY keeps reason rule). Tolerant, the
# default, evaluates the decoded fields: an ALLOW that matches them admits
# the APDU, an absent field never satisfies a predicate, and the DENY rule
# catches the rest with reason rule. Both modes raise one ics-conformance
# alert per connection per code and reset a session whose frame boundary is
# lost. Evidence is the RTU's own counters, the client socket state and the
# connection's decision and alert events, saved as parsing-<name>.json.
# shellcheck disable=SC2016 # Dollar variables in jq programs are jq bindings.

# port_of OUT: the client_port field of a malformer result line.
port_of() {
  sed -n 's/.*client_port=\([0-9]*\).*/\1/p' <<<"$1"
}

# parsing_events NAME PORT SINCE saves the events of the client connection on
# PORT recorded at or after SINCE to RESULTS_DIR/parsing-NAME.json.
parsing_events() {
  local name=$1 port=$2 since=$3 out="$RESULTS_DIR/parsing-$1.json"
  $CURL -H "$AUTH_HEADER" "${BASE}/events?limit=5000" 2>/dev/null | jq --argjson port "$port" --arg since "$since" '
    [.[] | select(.srcPort == $port
      and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= ($since | fromdateiso8601)))]' \
    >"$out" 2>/dev/null || printf '[]\n' >"$out"
}

# wait_parsing_events NAME PORT SINCE FILTER [JQ_ARG...] polls the
# connection's events for up to 10 s until the jq FILTER holds.
wait_parsing_events() {
  local name=$1 port=$2 since=$3 filter=$4
  shift 4
  for _ in $(seq 1 20); do
    parsing_events "$name" "$port" "$since"
    if jq -e "$@" "$filter" "$RESULTS_DIR/parsing-$name.json" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# parsing_summary NAME: the decision and alert evidence of a connection.
parsing_summary() {
  jq -c '[.[] | select(.kind == "ics.decision" or .proto == "ids")
    | {kind, decision: .attributes.decision, reason: .attributes.reason, ruleId: .attributes.ruleId,
       rule_id: .attributes.rule_id, action: .attributes.action, conformance: .attributes.conformance}]' \
    "$RESULTS_DIR/parsing-$1.json" | head -c 600
}

# parsing_slug LABEL: a file-name-safe form of an assertion label.
parsing_slug() {
  tr -cs 'a-zA-Z0-9' '-' <<<"$1" | tr '[:upper:]' '[:lower:]' | sed 's/^-//; s/-*$//'
}

# parsing_denied LABEL SCENARIO REASON CODE [MALFORMER_ARG...]: the APDU is
# dropped before the RTU and the session reset, with a deny decision of
# REASON. With a CODE, the decision carries it (a DENY rule match names
# deny-other-iec104) and the connection raises exactly one "dropped and
# reset" conformance alert; without one (a lost frame boundary) the decision
# has no findings and no conformance alert is raised.
parsing_denied() {
  local label=$1 scenario=$2 reason=$3 code=$4 name since out sock port before after detail
  shift 4
  name=$(parsing_slug "$label")
  since=$(timestamp)
  before=$(rtu_field commands_received)
  out=$(malformer -scenario "$scenario" "$@" -hold "$HOLD")
  sock=$(socket_of "$out")
  port=$(port_of "$out")
  sleep 1
  after=$(rtu_field commands_received)
  detail="client_socket=${sock:-none} port=${port:-none}; RTU commands_received $before -> $after"
  if [[ "$sock" == reset && -n "$before" && "$after" == "$before" ]]; then
    gate_pass "$label: dropped before the RTU and the session reset" "$detail"
  else
    gate_fail "$label: dropped before the RTU and the session reset" "$detail"
  fi
  if [[ -z "$port" ]]; then
    gate_fail "$label: decision and alert evidence" "no client_port in: $out"
    return
  fi
  if [[ -n "$code" ]]; then
    if wait_parsing_events "$name" "$port" "$since" '
      any(.[]; .proto == "iec104" and .kind == "ics.decision" and .attributes.decision == "deny"
        and .attributes.reason == $reason and ($reason != "rule" or .attributes.ruleId == "deny-other-iec104")
        and any(.attributes.conformance[]?; . == $code))
      and ([.[] | select(.proto == "ids" and .kind == "alert" and .attributes.rule_id == "ics-conformance"
        and any(.attributes.conformance[]?; . == $code))] | length == 1 and .[0].attributes.action == "dropped and reset")' \
      --arg reason "$reason" --arg code "$code"; then
      gate_pass "$label: deny decision (reason $reason) carries $code and one 'dropped and reset' conformance alert" "parsing-$name.json"
    else
      gate_fail "$label: deny decision (reason $reason) carries $code and one 'dropped and reset' conformance alert" "$(parsing_summary "$name")"
    fi
  elif wait_parsing_events "$name" "$port" "$since" '
      any(.[]; .proto == "iec104" and .kind == "ics.decision" and .attributes.decision == "deny"
        and .attributes.reason == $reason and (.attributes | has("conformance") | not))
      and ([.[] | select(.proto == "ids" and .kind == "alert" and .attributes.rule_id == "ics-conformance")] | length == 0)' \
    --arg reason "$reason"; then
    gate_pass "$label: deny decision (reason $reason) without findings and no conformance alert" "parsing-$name.json"
  else
    gate_fail "$label: deny decision (reason $reason) without findings and no conformance alert" "$(parsing_summary "$name")"
  fi
}

# parsing_allowed LABEL SCENARIO CODE REPEAT [MALFORMER_ARG...]: REPEAT APDUs
# with the finding reach the RTU on one connection without a reset, each
# with an allow decision that carries CODE, and the connection raises exactly
# one "passed" conformance alert for the code.
parsing_allowed() {
  local label=$1 scenario=$2 code=$3 repeat=$4 name since out sock port before after detail
  shift 4
  name=$(parsing_slug "$label")
  since=$(timestamp)
  before=$(rtu_field commands_received)
  out=$(malformer -scenario "$scenario" "$@" -repeat "$repeat" -hold 2s)
  sock=$(socket_of "$out")
  port=$(port_of "$out")
  sleep 1
  after=$(rtu_field commands_received)
  detail="client_socket=${sock:-none} port=${port:-none}; RTU commands_received $before -> $after (want +$repeat)"
  if [[ -n "$sock" && "$sock" != reset && -n "$before" && "$after" == $((before + repeat)) ]]; then
    gate_pass "$label: every APDU reaches the RTU and the session is not reset" "$detail"
  else
    gate_fail "$label: every APDU reaches the RTU and the session is not reset" "$detail"
  fi
  if [[ -z "$port" ]]; then
    gate_fail "$label: decision and alert evidence" "no client_port in: $out"
    return
  fi
  if wait_parsing_events "$name" "$port" "$since" '
    ([.[] | select(.proto == "iec104" and .kind == "ics.decision" and .attributes.decision == "allow"
      and .attributes.reason == "rule" and any(.attributes.conformance[]?; . == $code))] | length == $n)
    and ([.[] | select(.proto == "ids" and .kind == "alert" and .attributes.rule_id == "ics-conformance"
      and any(.attributes.conformance[]?; . == $code))] | length == 1 and .[0].attributes.action == "passed")' \
    --arg code "$code" --argjson n "$repeat"; then
    gate_pass "$label: $repeat allow decisions carry $code and the connection raises one 'passed' conformance alert" "parsing-$name.json"
  else
    gate_fail "$label: $repeat allow decisions carry $code and the connection raises one 'passed' conformance alert" "$(parsing_summary "$name")"
  fi
}

# run_parsing_gates applies strict parsing for the reset gates, keeps strict
# under a learn policy for the no-reset gates, then restores the tolerant
# default for the decoded-content gates. It leaves the EU enforce policy
# (tolerant) applied.
run_parsing_gates() {
  local strict_policy learn_policy scen since out sock
  strict_policy=$(jq '.dataPlane.dpiIcsParsing = {"iec104": "strict"}' <<<"$EU_POLICY")
  if apply_config "$strict_policy" "EU enforce policy, strict IEC 104 parsing"; then
    gate_pass "strict IEC 104 parsing (dpiIcsParsing.iec104 = strict) is accepted and applied"
  else
    gate_fail "strict IEC 104 parsing (dpiIcsParsing.iec104 = strict) is accepted and applied" "management API or engine rejected it"
    return
  fi
  sleep 2
  parsing_denied "strict: bad-length (APCI length 2, frame boundary lost)" bad-length malformed "" \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "strict: malformed-dcs (DCS 3, IOA unreadable) at the allowed point" malformed-dcs rule iec104.element \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "strict: unsupported-type (Type ID 104)" unsupported-type rule iec104.unsupported_type \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "strict: role-violation (client sends Type ID 1)" role-violation rule iec104.role \
    -ca "$ALLOWED_CA" -ioa 1002
  parsing_denied "strict: reserved-bits on the allowed command" reserved-bits nonconformant iec104.reserved_bits \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE"

  learn_policy=$(jq '.dataPlane.dpiMode = "learn" | .firewall.rules |= map(.ics.mode = "learn")' <<<"$strict_policy")
  if apply_config "$learn_policy" "EU learn policy, strict parsing"; then
    sleep 2
    for scen in bad-length malformed-dcs unsupported-type; do
      since=$(timestamp)
      out=$(malformer -scenario "$scen" -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -hold 2s)
      sock=$(socket_of "$out")
      sleep 1
      if [[ "$sock" != reset ]] && iec_event_since "$since"; then
        gate_pass "strict learn: $scen raises an IEC104 event and is not reset" "client_socket=$sock"
      else
        gate_fail "strict learn: $scen raises an IEC104 event and is not reset" \
          "client_socket=${sock:-none}; IEC104 malformed/unsupported event: $(iec_event_since "$since" && echo yes || echo no)"
      fi
    done
  else
    fail "could not apply the EU learn policy"
  fi

  if apply_config "$EU_POLICY" "EU enforce policy, tolerant parsing (restore)"; then
    gate_pass "tolerant IEC 104 parsing is the default (no dpiIcsParsing key) and is applied"
  else
    gate_fail "tolerant IEC 104 parsing is the default (no dpiIcsParsing key) and is applied" "could not restore the EU enforce policy"
    return
  fi
  sleep 2
  parsing_denied "tolerant: bad-length (APCI length 2) still resets" bad-length malformed "" \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "tolerant: malformed-dcs (DCS 3, IOA unreadable) falls to the DENY rule" malformed-dcs rule iec104.element \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "tolerant: unsupported-type (Type ID 104) falls to the DENY rule" unsupported-type rule iec104.unsupported_type \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA"
  parsing_denied "tolerant: role-violation (client Type ID 1) falls to the DENY rule" role-violation rule iec104.role \
    -ca "$ALLOWED_CA" -ioa 1002
  parsing_allowed "tolerant: reserved-bits on the allowed command, twice on one connection" reserved-bits iec104.reserved_bits 2 \
    -ca "$ALLOWED_CA" -ioa "$ALLOWED_IOA" -dcs "$DCS_CLOSE"
}
