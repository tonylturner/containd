#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Offline request-contract checks. No Docker, listener or real HTTP requests.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/config-revision.sh
source "$ROOT/scripts/config-revision.sh"
# shellcheck source=scripts/smoke-config.sh
source "$ROOT/scripts/smoke-config.sh"
# shellcheck source=scripts/smoke-dpi-lib-parsing.sh
source "$ROOT/scripts/smoke-dpi-lib-parsing.sh"
# shellcheck source=scripts/smoke-engine-api.sh
source "$ROOT/scripts/smoke-engine-api.sh"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/containd-smoke-config.XXXXXX")
BASE=http://management.invalid/api/v1
AUTH_HEADER='Authorization: Bearer test'
calls="$WORK_DIR/calls"
state="$WORK_DIR/config.revision"
printf '0123456789abcdef.1\n' >"$state"
: >"$calls"
fake_save_status=200
fake_commit_status=200
fake_transport_status=0
fake_body='{"status":"committed","applyId":"apply-test","runningRevision":"running-test","protection":{"ready":false}}'
UPDATED_CFG='{"dataplane":{}}'

pass() { printf 'pass\n' >>"$WORK_DIR/assertions"; }
check_fail() { printf 'fail\n' >>"$WORK_DIR/assertions"; }

# Exercise cas_request's actual header parser and chaining, not a stubbed
# cas_write. The fake requires authentication and the exact previous token.
curl() {
  local method="" url="" out="" dump="" auth="" revision="" data="" status
  local base next
  base=$(cas_revision "$state")
  while (($#)); do
    case $1 in
    -X) method=$2; shift 2 ;;
    -H)
      case $2 in
      "$AUTH_HEADER") auth=$2 ;;
      X-Containd-If-Revision:*) revision=$2 ;;
      'Content-Type: application/json') ;;
      *) return 1 ;;
      esac
      shift 2
      ;;
    -o) out=$2; shift 2 ;;
    -D) dump=$2; shift 2 ;;
    --data-binary) [[ $2 == @- ]] || return 1; data=$(cat); shift 2 ;;
    --max-time|--connect-timeout|-w) shift 2 ;;
    -s|-sS) shift ;;
    http:*) url=$1; shift ;;
    *) echo "unexpected curl argument $1" >&2; return 1 ;;
    esac
  done
  [[ $method == POST && $auth == "$AUTH_HEADER" && $dump == - && -n $out ]] || return 1
  [[ $revision == "X-Containd-If-Revision: $base" ]] || return 1
  case $url in
  "$BASE/config")
    [[ -n $data ]] || return 1
    status=$fake_save_status
    ;;
  "$BASE/config/commit")
    [[ -z $data ]] || return 1
    status=$fake_commit_status
    ;;
  *) echo "unexpected request $url" >&2; return 1 ;;
  esac
  printf '%s %s %s\n' "$method" "$url" "$base" >>"$calls"
  printf '%s\n' "$fake_body" >"$out"
  [[ $fake_transport_status == 0 ]] || return "$fake_transport_status"
  printf 'HTTP/1.1 %s Test\r\n' "$status"
  if [[ $status == 200 ]]; then
    next=${base##*.}
    printf 'X-Containd-Revision: 0123456789abcdef.%s\r\n' "$((next + 1))"
  fi
  printf '\r\n%s' "$status"
}

code=$(cas_write "$state" curl -sS -H "$AUTH_HEADER" -H 'Content-Type: application/json' \
  -X POST "$BASE/config" --data-binary @- -o "$WORK_DIR/save.json" -w '%{http_code}' <<<"$UPDATED_CFG")
[[ $code == 200 && $(wc -l <"$calls") == 1 ]]
[[ $(cas_revision "$state") == 0123456789abcdef.2 ]]
echo 'PASS saving a candidate chains CAS without auto-commit'

smoke_commit_config "$state" "$WORK_DIR/commit.json"
[[ $(wc -l <"$calls") == 2 && $(cas_revision "$state") == 0123456789abcdef.3 ]]
[[ $(tail -n 1 "$calls") == "POST $BASE/config/commit 0123456789abcdef.2" ]]
jq -e '.protection.ready == false' "$WORK_DIR/commit.json" >/dev/null
echo 'PASS explicit commit uses saved authority; acceptance is not readiness'

push_parsing strict '.dataplane.dpiIcsParsing = {"modbus":"strict"}'
[[ $(wc -l <"$calls") == 4 && $(cas_revision "$state") == 0123456789abcdef.5 ]]
[[ $(tail -n 1 "$calls") == "POST $BASE/config/commit 0123456789abcdef.4" ]]
echo 'PASS parsing saves then commits through management with chained CAS'

fake_save_status=412
if push_parsing rejected 'del(.dataplane.dpiIcsParsing)'; then exit 1; fi
[[ $(wc -l <"$calls") == 5 && $(cas_revision "$state") == 0123456789abcdef.5 ]]
[[ $(tail -n 1 "$calls") == "POST $BASE/config 0123456789abcdef.5" ]]
echo 'PASS rejected parsing save never commits or advances the base'

for fake_commit_status in 412 500; do
  before=$(wc -l <"$calls")
  if smoke_commit_config "$state" "$WORK_DIR/rejected.json" 2>"$WORK_DIR/error"; then exit 1; fi
  [[ $(wc -l <"$calls") == $((before + 1)) && $(cas_revision "$state") == 0123456789abcdef.5 ]]
done
echo 'PASS commit conflict and apply failure are not retried or rebased'

fake_commit_status=200
fake_transport_status=28
before=$(wc -l <"$calls")
if smoke_commit_config "$state" "$WORK_DIR/timeout.json" 2>"$WORK_DIR/error"; then exit 1; fi
[[ $(wc -l <"$calls") == $((before + 1)) && $(cas_revision "$state") == 0123456789abcdef.5 ]]
echo 'PASS ambiguous commit transport failure never retries'

fake_transport_status=0
for fake_body in '{"status":"staged"}' '{"status":"committed","applyId":"a"}' 'not JSON'; do
  if smoke_commit_config "$state" "$WORK_DIR/invalid.json" 2>"$WORK_DIR/error"; then exit 1; fi
done
echo 'PASS commit requires committed status and runtime attempt/revision'

printf '*\n' >"$state"
before=$(wc -l <"$calls")
if smoke_commit_config "$state" "$WORK_DIR/invalid-base.json" 2>"$WORK_DIR/error"; then exit 1; fi
[[ $(wc -l <"$calls") == "$before" ]]
echo 'PASS invalid CAS authority sends no commit'

fake_engine_status=0
compose() {
  local arg
  local expected=(exec -T firewall curl -sS --max-time 10 --connect-timeout 5 -w '\n%{http_code}' http://127.0.0.1:8081/metrics)
  [[ $# == "${#expected[@]}" ]] || return 1
  for arg in "${expected[@]}"; do
    [[ $1 == "$arg" ]] || return 1
    shift
  done
  [[ -z $(cat) ]] || return 1
  [[ $fake_engine_status == 0 ]] || return "$fake_engine_status"
  printf 'engine_metric 1\n\n200'
}
[[ $(engine_get firewall /metrics "$WORK_DIR/metrics") == 200 ]]
[[ $(cat "$WORK_DIR/metrics") == 'engine_metric 1' ]]
fake_engine_status=1
[[ $(engine_get firewall /metrics "$WORK_DIR/metrics") == 000 && ! -s $WORK_DIR/metrics ]]
echo 'PASS engine telemetry remains GET-only and exposes transport failure'
