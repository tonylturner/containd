#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live Compose-owned interface assignment smoke. Usage: bash scripts/smoke-interfaces.sh
#
# CONTAIND_IMAGE                 image to test (default containd/containd:dev)
# COMPOSE_PROJECT_NAME           disposable project (default smoke-interfaces)
# SMOKE_WAN_NET / SMOKE_LAN_NET  first three subnet octets for project one
#                                (defaults 172.32.0 and 172.33.0)
# SMOKE_FRESH_WAN_NET / SMOKE_FRESH_LAN_NET
#                                subnet prefixes for the fresh project
#                                (defaults 172.34.0 and 172.35.0)
#
# Requires Docker Engine 28.1+, Compose with interface_name support, curl,
# jq, Python 3 and Docker access. It uses ephemeral host ports on 127.0.0.1
# and removes only its two isolated Compose projects and their named volumes.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/containd-smoke-interfaces.XXXXXX")
MAIN_COMPOSE="$WORK_DIR/main.yml"
FRESH_COMPOSE="$WORK_DIR/fresh.yml"
FRESH_MISSING_COMPOSE="$WORK_DIR/fresh-missing-lan.yml"
BASE_PROJECT=${COMPOSE_PROJECT_NAME:-smoke-interfaces}
FRESH_PROJECT="${BASE_PROJECT}-fresh"
export CONTAIND_IMAGE="${CONTAIND_IMAGE:-containd/containd:dev}"
WAN_PREFIX=${SMOKE_WAN_NET:-172.32.0}
LAN_PREFIX=${SMOKE_LAN_NET:-172.33.0}
FRESH_WAN_PREFIX=${SMOKE_FRESH_WAN_NET:-172.34.0}
FRESH_LAN_PREFIX=${SMOKE_FRESH_LAN_NET:-172.35.0}

WAN_SERVER=
ENGINE_WAN=
ENGINE_LAN=
CURRENT_WAN_PREFIX=
CURRENT_LAN_PREFIX=
EXPECTED_REVISION=
CURRENT_PROJECT=
CURRENT_COMPOSE=
MANAGEMENT_VIA_EXEC=0
BASE=
PHASE=setup
STACK_OWNED=0
MAIN_OWNED=0
FRESH_OWNED=0
FAIL_REPORTED=0
HARNESS_REPORTED=0
DIAGNOSTICS_DONE=0
MAIN_VOLUME=
AUTH_HEADER='Authorization: Bearer devtoken'
CURL=(curl --fail --silent --show-error --max-time 10 --connect-timeout 5)

# shellcheck source=scripts/config-revision.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/config-revision.sh"
# shellcheck source=scripts/smoke-config.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/smoke-config.sh"
# shellcheck source=scripts/smoke-lib.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/smoke-lib.sh"

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
pass() { log "PASS: $*"; }

use_stack() {
  CURRENT_PROJECT=$1
  CURRENT_COMPOSE=$2
  SMOKE_PROJECT=$CURRENT_PROJECT
  COMPOSE_FILE=$CURRENT_COMPOSE
  export SMOKE_PROJECT COMPOSE_FILE
}

api_get() {
  if ((MANAGEMENT_VIA_EXEC)); then
    compose exec -T engine curl --fail --silent --show-error \
      --max-time 10 --connect-timeout 5 -H "$AUTH_HEADER" \
      "http://127.0.0.1:18080$1"
    return
  fi
  "${CURL[@]}" -H "$AUTH_HEADER" "$BASE$1"
}

# A status read that races a state transition returns 502 with an
# inconsistent-observation view; reread briefly before failing.
protection_status() {
  local _
  for _ in 1 2 3 4 5; do
    api_get /dataplane/protection && return 0
    sleep 0.2
  done
  return 1
}

cleanup_files() {
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$WORK_DIR"
}

diagnostics() {
  local status='unavailable' links='unavailable' nft='unavailable'
  DIAGNOSTICS_DONE=1
  if [[ -n $BASE ]]; then
    status=$(protection_status 2>&1) || true
  fi
  if ((STACK_OWNED)); then
    links=$(compose exec -T engine ip -br link 2>&1) || true
    compose exec -T engine nft list ruleset >"$WORK_DIR/nft-ruleset.txt" 2>&1 || true
    if [[ -f $WORK_DIR/nft-ruleset.txt ]]; then
      nft=$(awk 'NR <= 180' "$WORK_DIR/nft-ruleset.txt")
    fi
  fi
  log "diagnostic GET /api/v1/dataplane/protection: $status" >&2
  log "diagnostic appliance ip -br link: $links" >&2
  log "diagnostic nft list ruleset excerpt (first 180 lines): $nft" >&2
  if ((STACK_OWNED)); then
    compose logs --no-color engine >&2 || true
  fi
}

cleanup_project() {
  local project=$1 compose_file=$2
  use_stack "$project" "$compose_file"
  compose down --volumes --remove-orphans
}

on_exit() {
  local rc=$?
  trap - EXIT
  if ((rc != 0)); then
    if ((!DIAGNOSTICS_DONE)); then diagnostics; fi
    if ((!FAIL_REPORTED && !HARNESS_REPORTED)); then
      log "HARNESS ERROR: an unexpected command failed (exit $rc)" >&2
    fi
  fi
  if ((MAIN_OWNED)); then
    cleanup_project "$BASE_PROJECT" "$MAIN_COMPOSE" || {
      log "cleanup failed for owned project $BASE_PROJECT" >&2
      if ((rc == 0)); then rc=1; fi
    }
  fi
  if ((FRESH_OWNED)); then
    cleanup_project "$FRESH_PROJECT" "$FRESH_COMPOSE" || {
      log "cleanup failed for owned project $FRESH_PROJECT" >&2
      if ((rc == 0)); then rc=1; fi
    }
  fi
  cleanup_files || {
    log "could not remove temporary files in $WORK_DIR" >&2
    if ((rc == 0)); then rc=1; fi
  }
  exit "$rc"
}
trap on_exit EXIT

fail() {
  log "FAIL [$PHASE]: $*" >&2
  FAIL_REPORTED=1
  diagnostics
  exit 1
}

harness_error() {
  log "HARNESS ERROR [$PHASE]: $*" >&2
  HARNESS_REPORTED=1
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
}

ensure_project_is_fresh() {
  local project=$1 existing
  existing=$(docker ps -aq --filter "label=com.docker.compose.project=$project") ||
    harness_error "cannot inspect containers for project $project"
  [[ -z $existing ]] || harness_error "project $project already owns containers"
  existing=$(docker volume ls -q --filter "label=com.docker.compose.project=$project") ||
    harness_error "cannot inspect volumes for project $project"
  [[ -z $existing ]] || harness_error "project $project already owns volumes"
  existing=$(docker network ls -q --filter "label=com.docker.compose.project=$project") ||
    harness_error "cannot inspect networks for project $project"
  [[ -z $existing ]] || harness_error "project $project already owns networks"
}

check_engine_version() {
  local version major minor
  version=$(docker version --format '{{.Server.Version}}') ||
    harness_error "cannot read Docker Engine version"
  [[ $version =~ ^([0-9]+)\.([0-9]+) ]] ||
    harness_error "cannot parse Docker Engine version: $version"
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  if ((major < 28 || (major == 28 && minor < 1))); then
    harness_error "Docker Engine 28.1+ is required for named network attachments (found $version)"
  fi
  log "Docker Engine $version"
}

write_compose() {
  local file=$1 wan_prefix=$2 lan_prefix=$3
  local include_engine_lan=$4 engine_networks
  if [[ $include_engine_lan == true ]]; then
    engine_networks="      wan_net:
        interface_name: wan
        priority: 100
        ipv4_address: ${wan_prefix}.2
      lan_net:
        interface_name: lan1
        priority: 50
        ipv4_address: ${lan_prefix}.2"
  else
    engine_networks="      wan_net:
        interface_name: wan
        priority: 100
        ipv4_address: ${wan_prefix}.2"
  fi
  cat >"$file" <<YAML
services:
  engine:
    image: "\${CONTAIND_IMAGE}"
    user: "0"
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]
    environment:
      CONTAIND_PROFILE: training
      CONTAIND_MGMT_ADDR: ":18080"
      CONTAIND_MGMT_HTTPS_ADDR: ":18443"
      CONTAIND_ENGINE_URL: http://127.0.0.1:8081
      CONTAIND_ADMIN_TOKEN: devtoken
      CONTAIND_LAB_MODE: "1"
      CONTAIND_JWT_SECRET: ""
      CONTAIND_CONFIG_DB: /data/config.db
      CONTAIND_AUDIT_DB: /data/audit.db
      CONTAIND_USERS_DB: /data/users.db
      CONTAIND_TELEMETRY_DB: /data/telemetry.db
    volumes:
      - data:/data
    ports:
      - "127.0.0.1::18080"
    networks:
$engine_networks
    command: ["all"]

  lan_client:
    image: python:3-alpine
    command: ["sleep", "infinity"]
    user: "0"
    cap_add: [NET_ADMIN]
    networks:
      lan_net:
        ipv4_address: ${lan_prefix}.3
    depends_on: [engine]

  wan_probe:
    image: python:3-alpine
    command: ["sleep", "infinity"]
    user: "0"
    cap_add: [NET_ADMIN]
    networks:
      wan_net:
        ipv4_address: ${wan_prefix}.4
    depends_on: [engine]

  wan_server:
    image: python:3-alpine
    cap_add: [NET_ADMIN]
    command:
      - python3
      - -u
      - -c
      - |
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"interfaces-smoke\\n")

            def log_message(self, *_):
                pass

        def serve(port):
            ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

        for port in (18080, 18081):
            Thread(target=serve, args=(port,), daemon=True).start()
        ThreadingHTTPServer(("0.0.0.0", 18082), Handler).serve_forever()
    networks:
      wan_net:
        ipv4_address: ${wan_prefix}.3
    depends_on: [engine]

volumes:
  data: {}

networks:
  wan_net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "false"
    ipam:
      config:
        - subnet: ${wan_prefix}.0/24
  lan_net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "false"
    ipam:
      config:
        - subnet: ${lan_prefix}.0/24
YAML
  [[ -s $file ]]
}

check_compose_file() {
  local file=$1 project=$2
  use_stack "$project" "$file"
  compose config >/dev/null ||
    harness_error "Compose rejected interface assignment topology in $file"
}

capture_volume() {
  local project=$1 volume
  volume=$(docker volume ls -q --filter "label=com.docker.compose.project=$project") ||
    harness_error "cannot list project $project volumes"
  [[ -n $volume && $volume != *$'\n'* ]] ||
    harness_error "expected exactly one owned data volume for project $project, got: $volume"
  printf '%s' "$volume"
}

start_stack() {
  local project=$1 file=$2
  use_stack "$project" "$file"
  STACK_OWNED=1
  compose up -d ||
    harness_error "could not start owned Compose project $project"
}

wait_for_management() {
  local ready=0 published
  published=$(compose port engine 18080) ||
    harness_error "could not resolve ephemeral management port"
  published=${published##*:}
  [[ $published =~ ^[0-9]+$ ]] ||
    harness_error "invalid ephemeral management port: $published"
  BASE="http://127.0.0.1:${published}/api/v1"
  for _ in {1..60}; do
    if "${CURL[@]}" "$BASE/health" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  ((ready)) || harness_error "management did not become ready at $BASE/health"
}

read_candidate() {
  cas_read "$WORK_DIR/config.revision" "${CURL[@]}" -H "$AUTH_HEADER" \
    "$BASE/config/candidate"
}

configure_policy() {
  local description=$1 lan_prefix=$2 wan_prefix=$3 config_file
  config_file="$WORK_DIR/candidate.json"
  read_candidate >"$WORK_DIR/current-candidate.json" ||
    harness_error "could not read candidate configuration"
  jq -e '
    (.description != "interfaces-smoke-main")
    and ([.firewall.rules[]? | select((.id // "") | startswith("interfaces-smoke-"))] | length == 0)
  ' "$WORK_DIR/current-candidate.json" >/dev/null ||
    harness_error "new project contains stale interface-smoke configuration"
  jq --arg description "$description" \
    --arg lan_client "${lan_prefix}.3/32" --arg wan_server "${wan_prefix}.3/32" \
    --arg wan_probe "${wan_prefix}.4/32" '
      .description = $description
      | .zones = [{name:"wan"},{name:"lan"}]
      | .interfaces = [{name:"wan",zone:"wan"},{name:"lan1",zone:"lan"}]
      | .system.mgmt.httpListenAddr = ":18080"
      | .system.mgmt.listenAddr = ":18080"
      | .dataplane = {enforcement:true,enforceTable:"containd"}
      | .firewall.defaultAction = "DENY"
      | .firewall.nat = {enabled:false}
      | .firewall.rules = [
          {
            id:"interfaces-smoke-allow",
            description:"Allow the LAN test service",
            sourceZones:["lan"],destZones:["wan"],
            sources:[$lan_client],destinations:[$wan_server],
            protocols:[{name:"tcp",port:"18080"}],action:"ALLOW"
          },
          {
            id:"interfaces-smoke-deny",
            description:"Deny the second LAN test port",
            sourceZones:["lan"],destZones:["wan"],
            sources:[$lan_client],destinations:[$wan_server],
            protocols:[{name:"tcp",port:"18081"}],action:"DENY"
          },
          {
            id:"interfaces-smoke-wan-guard",
            description:"Prove attached WAN policy remains installed",
            sourceZones:["wan"],destZones:["wan"],
            sources:[$wan_probe],destinations:[$wan_server],
            protocols:[{name:"tcp",port:"18081"}],action:"DENY"
          }
        ]
    ' "$WORK_DIR/current-candidate.json" >"$config_file" ||
    harness_error "could not generate the interface assignment policy"
  cas_write "$WORK_DIR/config.revision" curl -sS --max-time 10 --connect-timeout 5 \
    -H "$AUTH_HEADER" -H 'Content-Type: application/json' \
    -X POST "$BASE/config/candidate" --data-binary @"$config_file" \
    >"$WORK_DIR/stage.json" ||
    harness_error "candidate save failed: $(cat "$WORK_DIR/config.revision.response" 2>/dev/null || true)"
  jq -e '.status == "staged"' "$WORK_DIR/stage.json" >/dev/null ||
    harness_error "candidate save was rejected: $(cat "$WORK_DIR/stage.json")"
  smoke_commit_config "$WORK_DIR/config.revision" "$WORK_DIR/commit.json" ||
    harness_error "policy commit failed: $(cat "$WORK_DIR/commit.json" 2>/dev/null || true)"
  EXPECTED_REVISION=$(jq -er '.runningRevision' "$WORK_DIR/commit.json") ||
    harness_error "commit response has no runningRevision"
  pass "committed $description policy at running revision $EXPECTED_REVISION"

  read_candidate >"$WORK_DIR/saved-candidate.json" ||
    harness_error "could not reread committed candidate"
  jq -e '
    ([.interfaces[].name] | sort) == ["lan1","wan"]
    and all(.interfaces[]; has("device") | not)
    and any(.firewall.rules[]; .id == "interfaces-smoke-allow")
    and any(.firewall.rules[]; .id == "interfaces-smoke-deny")
  ' "$WORK_DIR/saved-candidate.json" >/dev/null ||
    fail "committed configuration does not bind exactly the wan and lan1 rows by name"
}

wait_for_protection_ready() {
  local status_file="$WORK_DIR/protection.json" ready=0
  for _ in {1..60}; do
    if protection_status >"$status_file" 2>/dev/null &&
      jq -e --arg revision "$EXPECTED_REVISION" '
        .desiredRevision == $revision
        and .appliedRevision == $revision
        and .ready == true
        and .state == "protecting"
        and any(.components[]?; .name == "interface-attachment" and .state == "ready")
      ' "$status_file" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  ((ready)) || fail "protection did not become ready at running revision $EXPECTED_REVISION: $(jq -c '{state,ready,desiredRevision,appliedRevision,components}' "$status_file" 2>/dev/null)"
}

wait_for_protection_degraded() {
  local status_file="$WORK_DIR/protection.json" ready=0
  for _ in {1..60}; do
    if protection_status >"$status_file" 2>/dev/null &&
      jq -e --arg revision "$EXPECTED_REVISION" '
        .desiredRevision == $revision
        and .appliedRevision == $revision
        and .state == "degraded"
        and .ready == false
        and any(.components[]?;
          .name == "interface-attachment"
          and .state == "degraded"
          and .reason == "zone lan has no attached interface: lan1")
      ' "$status_file" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  ((ready)) || fail "protection did not report the exact missing-lan1 degradation: $(jq -c '{state,ready,desiredRevision,appliedRevision,components}' "$status_file" 2>/dev/null)"
}

assert_device_names() {
  local links
  links=$(compose exec -T engine ip -br link) ||
    harness_error "could not inspect appliance links"
  [[ $(link_count wan <<<"$links") == 1 ]] ||
    fail "appliance does not have exactly one device named wan: $links"
  [[ $(link_count lan1 <<<"$links") == 1 ]] ||
    fail "appliance does not have exactly one device named lan1: $links"
  pass "appliance exposes the named devices wan and lan1: $(tr '\n' ';' <<<"$links")"
}

link_count() {
  local name=$1
  awk -v expected="$name" '
    { name = $1; sub(/@.*/, "", name); if (name == expected) count++ }
    END { print count+0 }
  '
}

device_index() {
  local device=$1 output
  output=$(compose exec -T engine ip -o link show dev "$device") || return 1
  awk -F: '{gsub(/[[:space:]]/,"",$1); print $1}' <<<"$output"
}

prepare_routes() {
  compose exec -T lan_client ip route replace "${CURRENT_WAN_PREFIX}.0/24" \
    via "$ENGINE_LAN" dev eth0 ||
    harness_error "could not route LAN test traffic through lan1"
  compose exec -T wan_server ip route replace "${CURRENT_LAN_PREFIX}.0/24" \
    via "$ENGINE_WAN" dev eth0 ||
    harness_error "could not route WAN server replies through wan"
  compose exec -T wan_probe ip route replace "$WAN_SERVER/32" \
    via "$ENGINE_WAN" dev eth0 ||
    harness_error "could not route the WAN policy probe through wan"
}

ensure_listeners() {
  compose exec -T wan_server python3 -c '
import socket
for port in (18080, 18081, 18082):
    with socket.create_connection(("127.0.0.1", port), timeout=2):
        pass
' >/dev/null ||
    harness_error "wan_server does not have live TCP listeners on all test ports"
}

rule_packets() {
  local rule_id=$1
  api_get /firewall/counters >"$WORK_DIR/counters.json" || return 1
  jq -er --arg rule "$rule_id" \
    '.rules[] | select(.ruleId == $rule) | .packets' \
    "$WORK_DIR/counters.json"
}

assert_counter_increased() {
  local rule_id=$1 before=$2 after
  after=$(rule_packets "$rule_id") ||
    fail "could not read the exact $rule_id counter after the traffic probe"
  [[ $before =~ ^[0-9]+$ && $after =~ ^[0-9]+$ ]] ||
    fail "invalid $rule_id packet counter (before=$before after=$after)"
  ((after > before)) ||
    fail "traffic did not increment exact rule $rule_id (counter $before -> $after)"
  pass "exact rule counter $rule_id increased ($before -> $after packets)"
}

send_allowed_request() {
  local before output
  before=$(rule_packets interfaces-smoke-allow) ||
    fail "could not read ALLOW counter before traffic"
  output=$(compose exec -T lan_client python3 - "$WAN_SERVER" 18080 <<'PY'
import socket
import sys

target, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((target, port), timeout=4) as sock:
        sock.sendall(b"GET / HTTP/1.0\r\nHost: smoke\r\n\r\n")
        sock.settimeout(4)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks)
    if b"200 OK" in response and b"interfaces-smoke" in response:
        print("RESULT=allowed-response")
    else:
        print("RESULT=unexpected-response:" + repr(response[:160]))
except OSError as exc:
    print("RESULT=error:" + repr(exc))
PY
  ) || harness_error "LAN allow probe container command failed"
  [[ $output == *"RESULT=allowed-response"* ]] ||
    fail "LAN-to-WAN ALLOW traffic did not receive the live service response: $output"
  pass "LAN-to-WAN ALLOW traffic reached the live server"
  assert_counter_increased interfaces-smoke-allow "$before"
}

send_denied_request() {
  local rule_id=$1 service=$2 target=$3 port=$4 before output
  before=$(rule_packets "$rule_id") ||
    fail "could not read DENY counter $rule_id before traffic"
  output=$(compose exec -T "$service" python3 - "$target" "$port" <<'PY'
import socket
import sys

target, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((target, port), timeout=4):
        print("RESULT=connected")
except TimeoutError:
    print("RESULT=timeout")
except OSError as exc:
    print("RESULT=error:" + repr(exc))
PY
  ) || harness_error "DENY probe container command failed"
  [[ $output == *"RESULT=timeout"* ]] ||
    fail "$rule_id traffic did not time out at the firewall: $output"
  pass "DENY traffic timed out as expected for $rule_id"
  assert_counter_increased "$rule_id" "$before"
}

exercise_lan_policy() {
  prepare_routes
  ensure_listeners
  send_allowed_request
  send_denied_request interfaces-smoke-deny lan_client "$WAN_SERVER" 18081
}

assert_revision_unchanged() {
  local revision=$1 status_file="$WORK_DIR/protection.json"
  protection_status >"$status_file" ||
    fail "could not read protection while checking the running revision"
  jq -e --arg revision "$revision" '
    .desiredRevision == $revision
    and .appliedRevision == $revision
    and .runningRevision == $revision
  ' "$status_file" >/dev/null ||
    fail "running/applied revision changed: $(jq -c '{desiredRevision,appliedRevision,runningRevision,state}' "$status_file")"
}

assert_missing_config_persisted() {
  read_candidate >"$WORK_DIR/missing-candidate.json" ||
    fail "management could not read config while lan1 was detached"
  jq -e '
    .description == "interfaces-smoke-fresh"
    and ([.interfaces[].name] | sort) == ["lan1","wan"]
    and any(.firewall.rules[]; .id == "interfaces-smoke-allow")
  ' "$WORK_DIR/missing-candidate.json" >/dev/null ||
    fail "the committed config was rolled back while lan1 was missing"
}

probe_remaining_wan_policy() {
  prepare_routes
  ensure_listeners
  send_denied_request interfaces-smoke-wan-guard wan_probe "$WAN_SERVER" 18081
}

main() {
  local main_wan_index main_lan_index
  local reversed_wan_index reversed_lan_index fresh_network engine_id

  require_tools
  [[ $BASE_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
    harness_error "COMPOSE_PROJECT_NAME must contain lowercase letters, digits, '_' or '-' and start alphanumerically"
  [[ $FRESH_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
    harness_error "derived fresh project name is invalid: $FRESH_PROJECT"
  local prefix
  for prefix in "$WAN_PREFIX" "$LAN_PREFIX" "$FRESH_WAN_PREFIX" "$FRESH_LAN_PREFIX"; do
    valid_prefix "$prefix" ||
      harness_error "network prefix must be three valid IPv4 octets: $prefix"
  done
  [[ $WAN_PREFIX != "$LAN_PREFIX" && $FRESH_WAN_PREFIX != "$FRESH_LAN_PREFIX" ]] ||
    harness_error "WAN and LAN subnet prefixes must differ"
  [[ $WAN_PREFIX != "$FRESH_WAN_PREFIX" && $WAN_PREFIX != "$FRESH_LAN_PREFIX" &&
    $LAN_PREFIX != "$FRESH_WAN_PREFIX" && $LAN_PREFIX != "$FRESH_LAN_PREFIX" ]] ||
    harness_error "the second project's subnets must differ from the first project's subnets"
  ensure_project_is_fresh "$BASE_PROJECT"
  ensure_project_is_fresh "$FRESH_PROJECT"
  check_engine_version

  write_compose "$MAIN_COMPOSE" "$WAN_PREFIX" "$LAN_PREFIX" true
  write_compose "$FRESH_COMPOSE" "$FRESH_WAN_PREFIX" "$FRESH_LAN_PREFIX" true
  write_compose "$FRESH_MISSING_COMPOSE" "$FRESH_WAN_PREFIX" "$FRESH_LAN_PREFIX" false
  check_compose_file "$MAIN_COMPOSE" "$BASE_PROJECT"
  check_compose_file "$FRESH_COMPOSE" "$FRESH_PROJECT"
  check_compose_file "$FRESH_MISSING_COMPOSE" "$FRESH_PROJECT"

  PHASE='phase 1: initial named attachments'
  log "Starting first isolated project $BASE_PROJECT..."
  MAIN_OWNED=1
  start_stack "$BASE_PROJECT" "$MAIN_COMPOSE"
  STACK_OWNED=1
  WAN_SERVER="${WAN_PREFIX}.3"
  ENGINE_WAN="${WAN_PREFIX}.2"
  ENGINE_LAN="${LAN_PREFIX}.2"
  CURRENT_WAN_PREFIX=$WAN_PREFIX
  CURRENT_LAN_PREFIX=$LAN_PREFIX
  wait_for_management
  configure_policy interfaces-smoke-main "$LAN_PREFIX" "$WAN_PREFIX"
  wait_for_protection_ready
  assert_device_names
  main_wan_index=$(device_index wan) || harness_error "cannot read wan link index"
  main_lan_index=$(device_index lan1) || harness_error "cannot read lan1 link index"
  pass "initial attachment order: wan index $main_wan_index, lan1 index $main_lan_index"
  exercise_lan_policy
  pass "phase 1 passed: ALLOW and DENY traffic matched exact rule counters with ready protection"
  MAIN_VOLUME=$(capture_volume "$BASE_PROJECT")

  PHASE='phase 2: reversed attachment order'
  log "Normalizing the phase-1 baseline, then reconnecting the zone networks in reverse order..."
  engine_id=$(compose ps -q engine) ||
    harness_error "could not find the owned engine container for attachment reordering"
  [[ -n $engine_id ]] || harness_error "engine container ID is empty during attachment reordering"

  # Compose does not guarantee the startup endpoint order. If it started the
  # phase-1 stack LAN-first, normalize only that unexpected order so the
  # required LAN-then-WAN reconnect below is guaranteed to reverse its baseline.
  if ((main_wan_index > main_lan_index)); then
    MANAGEMENT_VIA_EXEC=1
    docker network disconnect "${BASE_PROJECT}_wan_net" "$engine_id" ||
      harness_error "could not disconnect the initial WAN endpoint to normalize the phase-1 baseline"
    docker network disconnect "${BASE_PROJECT}_lan_net" "$engine_id" ||
      harness_error "could not disconnect the initial LAN endpoint to normalize the phase-1 baseline"
    api_get /health >/dev/null ||
      harness_error "management loopback was unreachable while normalizing the phase-1 baseline"
    docker network connect --ip "$ENGINE_WAN" \
      --driver-opt com.docker.network.endpoint.ifname=wan \
      "${BASE_PROJECT}_wan_net" "$engine_id" ||
      harness_error "could not attach WAN first to normalize the phase-1 baseline"
    docker network connect --ip "$ENGINE_LAN" \
      --driver-opt com.docker.network.endpoint.ifname=lan1 \
      "${BASE_PROJECT}_lan_net" "$engine_id" ||
      harness_error "could not attach LAN second to normalize the phase-1 baseline"
    MANAGEMENT_VIA_EXEC=0
    wait_for_management
    wait_for_protection_ready
    assert_device_names
    main_wan_index=$(device_index wan) || harness_error "cannot read normalized phase-1 wan link index"
    main_lan_index=$(device_index lan1) || harness_error "cannot read normalized phase-1 lan1 link index"
  fi
  ((main_wan_index < main_lan_index)) ||
    harness_error "phase-1 baseline did not follow the controlled WAN-then-LAN order (wan $main_wan_index, lan1 $main_lan_index)"
  pass "phase-1 reference attachment order: wan index $main_wan_index, lan1 index $main_lan_index"

  docker network disconnect "${BASE_PROJECT}_wan_net" "$engine_id" ||
    harness_error "could not disconnect the phase-1 WAN network from the engine"
  docker network disconnect "${BASE_PROJECT}_lan_net" "$engine_id" ||
    harness_error "could not disconnect the phase-1 LAN network from the engine"
  MANAGEMENT_VIA_EXEC=1
  api_get /health >/dev/null ||
    harness_error "management loopback was unreachable with both zone networks detached"
  log "Using docker exec to the engine loopback while the published host path is detached"
  docker network connect --ip "$ENGINE_LAN" \
    --driver-opt com.docker.network.endpoint.ifname=lan1 \
    "${BASE_PROJECT}_lan_net" "$engine_id" ||
    harness_error "could not reconnect the LAN network first with endpoint name lan1"
  docker network connect --ip "$ENGINE_WAN" \
    --driver-opt com.docker.network.endpoint.ifname=wan \
    "${BASE_PROJECT}_wan_net" "$engine_id" ||
    harness_error "could not reconnect the WAN network second with endpoint name wan"
  MANAGEMENT_VIA_EXEC=0
  wait_for_management

  assert_revision_unchanged "$EXPECTED_REVISION"
  wait_for_protection_ready
  assert_device_names
  reversed_wan_index=$(device_index wan) || harness_error "cannot read wan link index after recreation"
  reversed_lan_index=$(device_index lan1) || harness_error "cannot read lan1 link index after recreation"
  if ((main_wan_index < main_lan_index)); then
    ((reversed_wan_index > reversed_lan_index)) ||
      harness_error "phase-2 connect order did not reverse the phase-1 index order (wan $main_wan_index->$reversed_wan_index, lan1 $main_lan_index->$reversed_lan_index)"
  else
    ((reversed_wan_index < reversed_lan_index)) ||
      harness_error "phase-2 connect order did not reverse the phase-1 index order (wan $main_wan_index->$reversed_wan_index, lan1 $main_lan_index->$reversed_lan_index)"
  fi
  pass "phase-2 attachments reversed the phase-1 index order (wan $main_wan_index->$reversed_wan_index, lan1 $main_lan_index->$reversed_lan_index)"
  exercise_lan_policy
  assert_revision_unchanged "$EXPECTED_REVISION"
  pass "phase 2 passed: named interfaces preserved verdicts and counters without changing the running revision"
  cleanup_project "$BASE_PROJECT" "$MAIN_COMPOSE"
  MAIN_OWNED=0
  STACK_OWNED=0

  PHASE='phase 3: fresh project and data volume'
  ensure_project_is_fresh "$FRESH_PROJECT"
  log "Starting fresh isolated project $FRESH_PROJECT on different subnets..."
  FRESH_OWNED=1
  start_stack "$FRESH_PROJECT" "$FRESH_COMPOSE"
  STACK_OWNED=1
  WAN_SERVER="${FRESH_WAN_PREFIX}.3"
  ENGINE_WAN="${FRESH_WAN_PREFIX}.2"
  ENGINE_LAN="${FRESH_LAN_PREFIX}.2"
  CURRENT_WAN_PREFIX=$FRESH_WAN_PREFIX
  CURRENT_LAN_PREFIX=$FRESH_LAN_PREFIX
  wait_for_management
  local fresh_volume
  fresh_volume=$(capture_volume "$FRESH_PROJECT")
  [[ $fresh_volume != "$MAIN_VOLUME" ]] ||
    fail "second project reused the first project's data volume $fresh_volume"
  configure_policy interfaces-smoke-fresh "$FRESH_LAN_PREFIX" "$FRESH_WAN_PREFIX"
  wait_for_protection_ready
  assert_device_names
  exercise_lan_policy
  pass "phase 3 passed: fresh policy used its own volume, subnets and named rows"

  PHASE='phase 4: missing lan1 attachment'
  log "Recreating $FRESH_PROJECT without the engine's lan1 network attachment..."
  compose down --remove-orphans
  use_stack "$FRESH_PROJECT" "$FRESH_MISSING_COMPOSE"
  start_stack "$FRESH_PROJECT" "$FRESH_MISSING_COMPOSE"
  wait_for_management
  wait_for_protection_degraded
  assert_revision_unchanged "$EXPECTED_REVISION"
  assert_missing_config_persisted
  "${CURL[@]}" "$BASE/health" >/dev/null ||
    fail "management liveness endpoint became unreachable while lan1 was missing"
  local missing_links
  missing_links=$(compose exec -T engine ip -br link) ||
    harness_error "could not inspect links in missing-network phase"
  [[ $(link_count wan <<<"$missing_links") == 1 ]] ||
    fail "wan attachment is absent during missing-network phase: $missing_links"
  [[ $(link_count lan1 <<<"$missing_links") == 0 ]] ||
    fail "lan1 is present before the late-attachment step: $missing_links"
  pass "protection degraded for exactly zone lan / row lan1; management and committed revision remain intact"
  probe_remaining_wan_policy
  pass "phase 4 passed: missing attachment stayed visible without rollback while attached WAN policy counted real traffic"

  PHASE='phase 5: late named attachment'
  fresh_network="${FRESH_PROJECT}_lan_net"
  engine_id=$(compose ps -q engine) ||
    harness_error "could not find the owned engine container for late attachment"
  [[ -n $engine_id ]] || harness_error "engine container ID is empty"
  log "Attaching $fresh_network to engine with Docker endpoint name lan1..."
  docker network connect --ip "$ENGINE_LAN" \
    --driver-opt com.docker.network.endpoint.ifname=lan1 \
    "$fresh_network" "$engine_id" ||
    fail "Docker Engine could not create the late lan1 endpoint on $fresh_network"
  wait_for_protection_ready
  assert_revision_unchanged "$EXPECTED_REVISION"
  assert_device_names
  exercise_lan_policy
  assert_revision_unchanged "$EXPECTED_REVISION"
  pass "phase 5 passed: Docker Engine late attachment cleared the fault without a commit and enforced both LAN rules"
  pass "all five interface-assignment smoke phases passed"
}

main "$@"
