#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live NFLOG lifecycle smoke. Usage: bash scripts/smoke-nflog.sh
#
# CONTAIND_IMAGE          image to test (default containd/containd:dev)
# COMPOSE_PROJECT_NAME    disposable project (default smoke-nflog)
# COMPOSE_FILE            base smoke compose file(s), colon-separated
#                         (default deploy/docker-compose.smoke.yml)
# SMOKE_WAN_NET           first three octets of the WAN subnet (172.32.0)
# SMOKE_LAN_NET           first three octets of the LAN subnet (172.33.0)
# SMOKE_NFLOG_GROUP       NFLOG group (100)
#
# Requires Docker Compose with !override/!reset support, curl, jq, Python 3,
# and a Docker daemon able to bind NFLOG. Only this isolated project is removed.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/containd-smoke-nflog.XXXXXX")
OVERRIDE="$WORK_DIR/isolation.yml"
BASE_COMPOSE_FILES=${COMPOSE_FILE:-"$ROOT/deploy/docker-compose.smoke.yml"}
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-smoke-nflog}"
export CONTAIND_IMAGE="${CONTAIND_IMAGE:-containd/containd:dev}"
export SMOKE_WAN_NET="${SMOKE_WAN_NET:-172.32.0}"
export SMOKE_LAN_NET="${SMOKE_LAN_NET:-172.33.0}"
NFLOG_GROUP=${SMOKE_NFLOG_GROUP:-100}

SMOKE_PROJECT=$COMPOSE_PROJECT_NAME
WAN_NET=$SMOKE_WAN_NET
LAN_NET=$SMOKE_LAN_NET
ENGINE_WAN="${WAN_NET}.2"
ENGINE_LAN="${LAN_NET}.2"
LAN_CLIENT="${LAN_NET}.3"
WAN_SERVER="${WAN_NET}.3"
RULE_ID=nflog-smoke-deny
TEST_PORT=8080
AUTH_HEADER='Authorization: Bearer devtoken'
CURL=(curl --fail --silent --show-error --max-time 10 --connect-timeout 5)
STACK_OWNED=0
DIAGNOSTICS_DONE=0
PHASE=setup
EXPECTED_REVISION=

# shellcheck source=scripts/config-revision.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/config-revision.sh"
# shellcheck source=scripts/smoke-config.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/smoke-config.sh"
# shellcheck source=scripts/smoke-lib.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/smoke-lib.sh"

export SMOKE_PROJECT

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
pass() { log "PASS: $*"; }

api_get() {
  "${CURL[@]}" -H "$AUTH_HEADER" "$BASE$1"
}

cleanup_files() {
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$WORK_DIR"
}

protection_status() {
  api_get /dataplane/protection
}

last_events() {
  api_get '/events?limit=30'
}

diagnostics() {
  local status='unavailable' proc='unavailable' events='unavailable'
  DIAGNOSTICS_DONE=1
  if [[ -n ${BASE:-} ]]; then
    status=$(protection_status 2>&1) || true
    events=$(last_events 2>&1) || true
  fi
  if ((STACK_OWNED)); then
    proc=$(compose exec -T engine cat /proc/net/netfilter/nfnetlink_log 2>&1) || true
  fi
  log "diagnostic protection status (including nflog component): $status" >&2
  log "diagnostic /proc/net/netfilter/nfnetlink_log: $proc" >&2
  log "diagnostic last events: $events" >&2
}

on_exit() {
  local rc=$?
  trap - EXIT
  if ((rc != 0 && STACK_OWNED)); then
    if ((!DIAGNOSTICS_DONE)); then diagnostics; fi
    compose logs --no-color engine >&2 || true
  fi
  if ((STACK_OWNED)); then
    compose down --volumes --remove-orphans || {
      log "cleanup failed for owned project $COMPOSE_PROJECT_NAME" >&2
      ((rc != 0)) || rc=1
    }
  fi
  cleanup_files || {
    log "could not remove temporary files in $WORK_DIR" >&2
    ((rc != 0)) || rc=1
  }
  exit "$rc"
}
trap on_exit EXIT

fail() {
  log "FAIL [$PHASE]: $*" >&2
  diagnostics
  exit 1
}

harness_error() {
  log "HARNESS ERROR: $*" >&2
  exit 2
}

require_tools() {
  local tool
  for tool in docker curl jq python3 awk; do
    command -v "$tool" >/dev/null 2>&1 || harness_error "missing required tool: $tool"
  done
}

valid_prefix() {
  local prefix=$1 octet
  local -a octets=()
  IFS=. read -r -a octets <<<"$prefix"
  [[ ${#octets[@]} == 3 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
  return 0
}

ensure_fresh_project() {
  local existing
  existing=$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME") ||
    harness_error "cannot inspect containers for project $COMPOSE_PROJECT_NAME"
  [[ -z $existing ]] || harness_error "project $COMPOSE_PROJECT_NAME already owns containers"
  existing=$(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME") ||
    harness_error "cannot inspect volumes for project $COMPOSE_PROJECT_NAME"
  [[ -z $existing ]] || harness_error "project $COMPOSE_PROJECT_NAME already owns volumes"
  existing=$(docker network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME") ||
    harness_error "cannot inspect networks for project $COMPOSE_PROJECT_NAME"
  [[ -z $existing ]] || harness_error "project $COMPOSE_PROJECT_NAME already owns networks"
}

write_isolation_override() {
  cat >"$OVERRIDE" <<'YAML'
services:
  engine:
    build: !reset null
    image: ${CONTAIND_IMAGE}
    ports: !override
      - "127.0.0.1::18080"
    volumes: !override
      - nflog-data:/data
      - ../ui/out:/var/lib/ngfw/ui:ro
    networks: !override
      wan_net:
        ipv4_address: ${SMOKE_WAN_NET}.2
      lan_net:
        ipv4_address: ${SMOKE_LAN_NET}.2
  lan_client:
    networks: !override
      lan_net:
        ipv4_address: ${SMOKE_LAN_NET}.3
  lan_target:
    networks: !override
      lan_net:
        ipv4_address: ${SMOKE_LAN_NET}.4
  ot_client:
    networks: !override
      lan_net:
        ipv4_address: ${SMOKE_LAN_NET}.5
  wan_server:
    networks: !override
      wan_net:
        ipv4_address: ${SMOKE_WAN_NET}.3
  modbus_server:
    networks: !override
      wan_net:
        ipv4_address: ${SMOKE_WAN_NET}.4
  av_server:
    networks: !override
      wan_net:
        ipv4_address: ${SMOKE_WAN_NET}.11
  av_target:
    networks: !override
      lan_net:
        ipv4_address: ${SMOKE_LAN_NET}.11
networks:
  wan_net:
    ipam:
      config: !override
        - subnet: ${SMOKE_WAN_NET}.0/24
  lan_net:
    ipam:
      config: !override
        - subnet: ${SMOKE_LAN_NET}.0/24
volumes:
  nflog-data:
YAML
  export COMPOSE_FILE="${BASE_COMPOSE_FILES}:$OVERRIDE"
}

wait_for_management() {
  local ready=0
  for _ in {1..60}; do
    if "${CURL[@]}" "$BASE/health" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  ((ready)) || harness_error "management did not become ready at $BASE/health"
}

read_config() {
  cas_read "$WORK_DIR/config.revision" "${CURL[@]}" -H "$AUTH_HEADER" \
    "$BASE/config/candidate"
}

stage_and_commit() {
  local description=$1 config_file="$WORK_DIR/candidate.json"
  read_config >"$WORK_DIR/read-candidate.json" ||
    harness_error "could not read the candidate configuration"
  if [[ $description == initial ]]; then
    jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" --arg group "$NFLOG_GROUP" \
      --arg source "$LAN_CLIENT/32" --arg target "$WAN_SERVER/32" \
      --arg rule "$RULE_ID" --argjson port "$TEST_PORT" '
      .zones = [{name:"wan"},{name:"lan"}]
      | .interfaces = [
          {name:"wan",device:$wan,zone:"wan"},
          {name:"lan1",device:$lan,zone:"lan"}
        ]
      | .system.mgmt.httpListenAddr = ":18080"
      | .system.mgmt.listenAddr = ":18080"
      | .dataplane = {
          enforcement:true,
          enforceTable:"containd",
          nflogGroup:($group | tonumber)
        }
      | .firewall.defaultAction = "DENY"
      | .firewall.nat = {enabled:false}
      | .firewall.rules = [{
          id:$rule,
          description:"Live NFLOG smoke deny",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:[$source],
          destinations:[$target],
          protocols:[{name:"tcp",port:($port | tostring)}],
          action:"DENY",
          log:true
        }]
    ' "$WORK_DIR/read-candidate.json" >"$config_file" ||
      harness_error "could not generate the NFLOG candidate configuration"
  else
    jq --arg description "NFLOG live smoke $description" \
      '.description = $description' "$WORK_DIR/read-candidate.json" >"$config_file" ||
      harness_error "could not generate the changed NFLOG candidate"
  fi

  cas_write "$WORK_DIR/config.revision" curl -sS --max-time 10 --connect-timeout 5 \
    -H "$AUTH_HEADER" \
    -H 'Content-Type: application/json' -X POST "$BASE/config/candidate" \
    --data-binary @"$config_file" >"$WORK_DIR/stage.json" ||
    harness_error "candidate save transport failed: $(cat "$WORK_DIR/config.revision.response" 2>/dev/null || true)"
  jq -e '.status == "staged"' "$WORK_DIR/stage.json" >/dev/null ||
    harness_error "candidate save was rejected: $(cat "$WORK_DIR/stage.json")"
  smoke_commit_config "$WORK_DIR/config.revision" "$WORK_DIR/commit.json" ||
    harness_error "configuration commit failed; response: $(cat "$WORK_DIR/commit.json" 2>/dev/null || true)"
  EXPECTED_REVISION=$(jq -er '.runningRevision' "$WORK_DIR/commit.json") ||
    harness_error "commit response has no runningRevision"
  pass "committed $description policy at revision $EXPECTED_REVISION"
}

wait_for_protection() {
  local status_file="$WORK_DIR/protection.json"
  for _ in {1..60}; do
    if protection_status >"$status_file" 2>/dev/null &&
      jq -e --arg revision "$EXPECTED_REVISION" '
        .appliedRevision == $revision
        and .ready == true
        and any(.components[]?; .name == "nflog" and .state == "ready")
      ' "$status_file" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "protection did not report ready at committed revision $EXPECTED_REVISION"
}

assert_nflog_bound_and_ready() {
  local proc status_file="$WORK_DIR/protection.json"
  proc=$(compose exec -T engine cat /proc/net/netfilter/nfnetlink_log 2>&1) ||
    fail "could not read /proc/net/netfilter/nfnetlink_log: $proc"
  if ! awk -v group="$NFLOG_GROUP" '$1 == group { found=1 } END { exit !found }' \
    <<<"$proc"; then
    fail "NFLOG group $NFLOG_GROUP is absent from /proc/net/netfilter/nfnetlink_log"
  fi
  protection_status >"$status_file" ||
    fail "could not read protection status after NFLOG bind"
  if ! jq -e --arg revision "$EXPECTED_REVISION" '
    .appliedRevision == $revision
    and .ready == true
    and any(.components[]?; .name == "nflog" and .state == "ready")
  ' "$status_file" >/dev/null; then
    fail "NFLOG group is bound but protection does not report ready at revision $EXPECTED_REVISION: $(jq -c '{appliedRevision,ready,components}' "$status_file")"
  fi
  pass "protection reports nflog ready at $EXPECTED_REVISION and group $NFLOG_GROUP is bound"
}

ensure_listener() {
  local ready=0
  for _ in {1..15}; do
    if compose exec -T wan_server python -c \
      'import sys,urllib.request; assert urllib.request.urlopen("http://127.0.0.1:"+sys.argv[1]+"/", timeout=3).read().startswith(b"server=wan_server")' \
      "$TEST_PORT" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  ((ready)) || harness_error "wan_server has no live TCP listener on port $TEST_PORT"
}

send_denied_tcp() {
  local start_ts=$1 output status=0 source_port result
  output=$(compose exec -T lan_client python - "$LAN_CLIENT" "$WAN_SERVER" "$TEST_PORT" <<'PY'
import socket
import sys

source, target, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
sock.bind((source, 0))
print(f"SRC_PORT={sock.getsockname()[1]}", flush=True)
try:
    sock.connect((target, port))
except TimeoutError:
    print("RESULT=timeout")
except OSError as exc:
    print(f"RESULT=error:{exc}")
else:
    print("RESULT=connected")
finally:
    sock.close()
PY
) || status=$?
  output=$(printf '%s' "$output" | tr -d '\r')
  source_port=$(awk -F= '$1 == "SRC_PORT" {print $2; exit}' <<<"$output")
  result=$(awk -F= '$1 == "RESULT" {print $2; exit}' <<<"$output")
  [[ $status == 0 && $source_port =~ ^[0-9]+$ && -n $result ]] ||
    harness_error "client TCP probe failed (exit $status): $output"
  if [[ $result != timeout ]]; then
    fail "expected denied TCP to time out, got $result (source port $source_port)"
  fi
  pass "L4 DENY blocked TCP connection from source port $source_port"

  for _ in {1..20}; do
    if last_events >"$WORK_DIR/events.json" 2>/dev/null &&
      jq -e --arg rule "$RULE_ID" --arg source "$LAN_CLIENT" --arg target "$WAN_SERVER" \
        --arg since "$start_ts" --argjson sport "$source_port" --argjson port "$TEST_PORT" '
        any(.[]; .kind == "firewall.rule.hit"
          and .attributes.ruleId == $rule
          and .attributes.action == "DENY"
          and .attributes.via == "nflog"
          and .srcIp == $source
          and .dstIp == $target
          and .srcPort == $sport
          and .dstPort == $port
          and .transport == "tcp"
          and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601)
            >= ($since | fromdateiso8601))
        )
      ' "$WORK_DIR/events.json" >/dev/null 2>&1; then
      pass "observed firewall.rule.hit for $RULE_ID after TCP send (source port $source_port)"
      return 0
    fi
    sleep 1
  done
  fail "no matching firewall.rule.hit for $RULE_ID after TCP send (source port $source_port; result=$result)"
}

exercise_phase() {
  local name=$1 start_ts route
  PHASE=$name
  wait_for_protection
  assert_nflog_bound_and_ready
  route_client lan_client "$LAN_CLIENT" "$LAN_NET" "$WAN_NET" "$ENGINE_LAN"
  route=$(compose exec -T lan_client ip route get "$WAN_SERVER" | tr -d '\r') ||
    harness_error "could not inspect lan_client route to $WAN_SERVER"
  grep -Fq "via $ENGINE_LAN" <<<"$route" ||
    harness_error "lan_client route to $WAN_SERVER does not use $ENGINE_LAN: $route"
  pass "lan_client route to $WAN_SERVER uses the engine gateway $ENGINE_LAN"
  ensure_listener
  pass "wan_server has a live TCP listener on port $TEST_PORT"
  start_ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
  send_denied_tcp "$start_ts"
}

restart_engine() {
  PHASE='engine restart'
  log "Restarting the engine service container..."
  compose restart engine || harness_error "could not restart engine container"
  wait_for_management
}

main() {
  local state='' wan_dev='' lan_dev='' status_file="$WORK_DIR/protection.json" response_code
  require_tools
  valid_prefix "$WAN_NET" || harness_error "SMOKE_WAN_NET must be three valid IPv4 octets, got $WAN_NET"
  valid_prefix "$LAN_NET" || harness_error "SMOKE_LAN_NET must be three valid IPv4 octets, got $LAN_NET"
  [[ $WAN_NET != "$LAN_NET" ]] || harness_error "SMOKE_WAN_NET and SMOKE_LAN_NET must differ"
  if [[ ! $NFLOG_GROUP =~ ^[1-9][0-9]{0,4}$ ]] ||
    ((10#$NFLOG_GROUP > 65535)); then
    harness_error "SMOKE_NFLOG_GROUP must be an integer from 1 through 65535"
  fi
  ensure_fresh_project
  write_isolation_override
  STACK_OWNED=1
  compose up -d --no-build || harness_error "could not start isolated smoke project"
  local published
  published=$(compose port engine 18080) || harness_error "could not resolve management port"
  published=${published##*:}
  [[ $published =~ ^[0-9]+$ ]] || harness_error "invalid published management port: $published"
  BASE="http://127.0.0.1:${published}/api/v1"
  wait_for_management

  for _ in {1..20}; do
    state=$(api_get /interfaces/state 2>/dev/null) || state=''
    wan_dev=$(jq -r --arg ip "$ENGINE_WAN" \
      'map(select(.addrs[]? | contains($ip))) | .[0].name // empty' <<<"$state")
    lan_dev=$(jq -r --arg ip "$ENGINE_LAN" \
      'map(select(.addrs[]? | contains($ip))) | .[0].name // empty' <<<"$state")
    [[ -n $wan_dev && -n $lan_dev ]] && break
    sleep 1
  done
  [[ -n $wan_dev && -n $lan_dev ]] ||
    harness_error "could not discover engine interfaces for $ENGINE_WAN and $ENGINE_LAN: $state"
  WAN_DEV=$wan_dev
  LAN_DEV=$lan_dev
  log "Using isolated project $COMPOSE_PROJECT_NAME, image $CONTAIND_IMAGE, WAN $WAN_NET.0/24, LAN $LAN_NET.0/24, NFLOG group $NFLOG_GROUP"

  PHASE='initial commit'
  stage_and_commit initial
  exercise_phase 'initial commit'

  PHASE='changed commit'
  stage_and_commit changed
  exercise_phase 'changed commit'

  PHASE='unchanged commit'
  # The candidate is already the running configuration. Commit it again
  # without staging another write to exercise the no-op promotion path.
  cas_read "$WORK_DIR/config.revision" "${CURL[@]}" -H "$AUTH_HEADER" \
    "$BASE/config/candidate" >"$WORK_DIR/unchanged-candidate.json" ||
    harness_error "could not read candidate before unchanged commit"
  smoke_commit_config "$WORK_DIR/config.revision" "$WORK_DIR/commit.json" ||
    harness_error "unchanged configuration commit failed"
  EXPECTED_REVISION=$(jq -er '.runningRevision' "$WORK_DIR/commit.json") ||
    harness_error "unchanged commit response has no runningRevision"
  pass "committed unchanged policy at revision $EXPECTED_REVISION"
  exercise_phase 'unchanged commit'

  PHASE='protection retry'
  protection_status >"$status_file" || fail "could not read protection status before retry"
  jq -e --arg revision "$EXPECTED_REVISION" '
    .appliedRevision == $revision and (.bootId | type == "string" and length > 0)
      and (.applyId | type == "string" and length > 0)
      and (.desiredRevision | type == "string" and length > 0)
  ' "$status_file" >/dev/null ||
    fail "protection status lacks retry authority fields for revision $EXPECTED_REVISION"
  jq '{bootId, applyId, desiredRevision}' "$status_file" >"$WORK_DIR/retry.json"
  response_code=$(curl -sS --max-time 10 --connect-timeout 5 \
    -H "$AUTH_HEADER" -H 'Content-Type: application/json' \
    -o "$WORK_DIR/retry-response.json" -w '%{http_code}' \
    -X POST "$BASE/dataplane/protection/retry" --data-binary @"$WORK_DIR/retry.json") ||
    fail "protection retry transport failed: $(cat "$WORK_DIR/retry-response.json" 2>/dev/null || true)"
  case "$response_code" in
  202) pass "protection retry accepted" ;;
  409)
    jq -e '.code == "protection_superseded"' "$WORK_DIR/retry-response.json" >/dev/null ||
      fail "protection retry returned an unexpected HTTP 409: $(cat "$WORK_DIR/retry-response.json")"
    pass "protection retry returned a superseded/uncertain conflict; still checking NFLOG"
    ;;
  *) fail "protection retry returned HTTP $response_code: $(cat "$WORK_DIR/retry-response.json")" ;;
  esac
  exercise_phase 'protection retry'

  restart_engine
  pass "engine service container restarted"
  exercise_phase 'engine restart'

  PHASE='full compose restart'
  log "Restarting all services in the isolated Compose project..."
  compose restart || harness_error "could not restart isolated Compose project"
  wait_for_management
  pass "all services in the isolated Compose project restarted"
  exercise_phase 'full compose restart'

  pass "all NFLOG lifecycle phases passed"
}

main "$@"
