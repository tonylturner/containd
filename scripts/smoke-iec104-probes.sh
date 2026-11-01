#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Receiver-side denial checks must first prove that the client sent its probe.
# lib60870 uses exit 1 for absent/negative confirmation after a successful send;
# setup failures use exit 2. The malformer emits the marker only on success.

iec_probe_sent() {
  local rc=$1 out=$2
  [[ $rc == 0 || $rc == 1 ]] && grep -Eq '(^|[[:space:]])probe_sent=1([[:space:]]|$)' <<<"$out"
}

assert_not_received() {
  local name=$1 counter=$2 rc=0 before after writes_before writes_after out detail
  shift 2
  before=$(rtu_field "$counter")
  writes_before=$(rtu_field writes_applied)
  out=$("$@" 2>&1) || rc=$?
  if ! iec_probe_sent "$rc" "$out"; then
    fail "$name" "probe did not connect and send: exit $rc; $out"
    return 1
  fi
  sleep 1
  after=$(rtu_field "$counter")
  writes_after=$(rtu_field writes_applied)
  detail="exit $rc; $counter $before -> $after; writes $writes_before -> $writes_after; last_command '$(rtu_field last_command)'; $out"
  if [[ -n "$before" && -n "$writes_before" && "$after" == "$before" && "$writes_after" == "$writes_before" ]]; then
    gate_pass "$name" "$detail"
  else
    gate_fail "$name" "$detail"
  fi
}

iec_stale_probe_ran() {
  local rc=$1 out=$2
  [[ $rc == 0 && $out == stale-retransmit:* ]] && iec_probe_sent "$rc" "$out"
}
