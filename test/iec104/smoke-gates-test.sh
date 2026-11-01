#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Headless negative fixtures for the truth harness. No Docker is required.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$ROOT/scripts/smoke-iec104-probes.sh"
source "$ROOT/scripts/smoke-iec104-observe.sh"
source "$ROOT/scripts/smoke-rule-modes-iec104-lib.sh"
WORK_DIR=$(mktemp -d)
RESULTS_DIR=$WORK_DIR
AUTH_HEADER=unused
BASE=unused
CC_IP=192.0.2.1
RTU_IP=192.0.2.2
RTU_PORT=2404
passed=0
failed=0
harness=0
tests=0
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
sleep() { :; }
log() { :; }
pass() { passed=$((passed+1)); }
gate_pass() { passed=$((passed+1)); }
gate_fail() { failed=$((failed+1)); }
fail() { harness=$((harness+1)); }
rtu_state() { printf '{}'; }
rtu_field() {
  case "$1" in
    commands_received) printf '%s' "$commands";;
    writes_applied) printf '%s' "$writes";;
    last_command) printf 'none';;
  esac
}
probe() { printf '%s\n' "$output"; return "$status"; }

# A timeout, missing binary, connect failure or setup exit must not pass just
# because a disconnected RTU's counters remained unchanged.
for fixture in sent no-marker missing connect setup; do
  commands=3 writes=2 output=probe_sent=1 status=1
  case "$fixture" in
    no-marker) output='no confirmation within 4000 ms';;
    missing) output='malformer: not found'; status=127;;
    connect) output='dial: connection refused'; status=1;;
    setup) status=2;;
  esac
  passed=0 failed=0 harness=0
  if assert_not_received "$fixture" commands_received probe; then rc=0; else rc=$?; fi
  if [[ $fixture == sent ]]; then
    [[ $rc == 0 && $passed == 1 && $failed == 0 && $harness == 0 ]] || die "$fixture denial"
  else
    [[ $rc != 0 && $passed == 0 && $harness == 1 ]] || die "$fixture denial"
  fi
  tests=$((tests+1))
done
for fixture in sent missing empty failed wrong-scenario; do
  status=0 output='stale-retransmit: sent 32 bytes probe_sent=1 client_socket=raw'
  case "$fixture" in
    missing) status=127; output='not found';;
    empty) output='';;
    failed) status=1; output='stale-retransmit: FAILED';;
    wrong-scenario) output='dc-select: sent 16 bytes probe_sent=1';;
  esac
  if iec_stale_probe_ran "$status" "$output"; then rc=0; else rc=$?; fi
  [[ $fixture == sent && $rc == 0 || $fixture != sent && $rc != 0 ]] || die "$fixture stale probe"
  tests=$((tests+1))
done

# Positive and deliberately broken inventories exercise the actual jq gate.
observe_check() { shift 2; "$@" >/dev/null; }
observe_inventory() { :; }
snapshot='{"pairs":[{"controlling":"192.0.2.1:50000","controlled":"192.0.2.2:2404","cas":[{"ca":1,"attemptedCommands":1,"points":[{"ioa":2001,"typeId":46}]}]}]}'
printf '%s\n' "$snapshot" >"$RESULTS_DIR/inventory-denied.json"
for fixture in new unchanged wrong-type wrong-ca wrong-ioa; do
  filter='.pairs[0].cas[0].attemptedCommands=2'
  case "$fixture" in
    unchanged) filter='.';;
    wrong-type) filter+=' | .pairs[0].cas[0].points[0].typeId=45';;
    wrong-ca) filter+=' | .pairs[0].cas[0].ca=2';;
    wrong-ioa) filter+=' | .pairs[0].cas[0].points[0].ioa=2002';;
  esac
  jq "$filter" <<<"$snapshot" >"$RESULTS_DIR/inventory-allowed.json"
  if observe_allowed; then rc=0; else rc=$?; fi
  [[ $fixture == new && $rc == 0 || $fixture != new && $rc != 0 ]] || die "$fixture inventory"
  tests=$((tests+1))
done

# Readback must reject a fake that swaps IDs but leaves monitor first.
CURL=(running)
apply_config() { installed=$1; }
cas_write() { printf '{}'; }
running() {
  if [[ $broken == 1 ]]; then
    jq '.firewall.rules |= (.[:-2] + (.[-2:] | sort_by(.id)))' <<<"$installed"
  else
    printf '%s\n' "$installed"
  fi
}
cfg='{"firewall":{"rules":[{"id":"l4"},{"id":"a-monitor"},{"id":"z-enforce"}]}}'
for order in first last; do
  for broken in 0 1; do
    if iec_modes_install "$cfg" envelope "$order"; then rc=0; else rc=$?; fi
    [[ $order == last && $broken == 1 && $rc != 0 || ( $order == first || $broken == 0 ) && $rc == 0 ]] ||
      die "$order order readback, broken=$broken, rc=$rc"
    tests=$((tests+1))
  done
done
printf 'PASS: %d truth-harness gate fixtures\n' "$tests"
