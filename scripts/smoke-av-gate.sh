#!/usr/bin/env bash
set -euo pipefail

# Smoke-test the antivirus scanning gate on a live engine with the EICAR
# test file, using the compose harness of scripts/smoke-forward.sh.
# Requirements: docker compose, jq, curl.
#
# The harness installs a forward policy (default deny, lan_client -> wan on
# tcp/8080 and tcp/8082), SNAT lan->wan and a DNAT port forward from the
# engine's WAN address to av_target:80, then enables the native clamd with
# FreshClam off and one local signature, the MD5 of the EICAR test file,
# uploaded as a custom definition, so no network is needed. The scan
# selection intercepts lan->wan tcp/8080 and wan->lan tcp/80 (the port
# forward's effective destination). Every policy is staged with POST
# /config and applied with POST /config/commit, as an operator would.
# test/data-smoke/av/ holds the origins (av_server on the WAN side,
# av_target on the LAN side) and the client; the EICAR string is assembled
# at runtime and never written to a log.
#
# The checks, each under the policy named in its ID:
# - open (fail-open, scanner ready): the EICAR download and upload are
#   refused with 403 and no EICAR byte reaches the client, the origin never
#   receives the upload, clean objects pass whole, the origin sees the
#   engine's WAN address (masquerade) and a detection event names the
#   client; the DNAT forward refuses EICAR and delivers clean with the
#   target seeing the engine's LAN address (return-path masquerade); the
#   unselected port 8082 delivers EICAR untouched without a gate event.
# - closed (fail-closed, scanner ready): the same refusals and deliveries.
# - unavailable-open / unavailable-closed: the backend is a remote ICAP
#   server that refuses connections (av_server, port 1344), so nothing can
#   be scanned; fail-open passes everything unscanned, fail-closed refuses
#   downloads and uploads, and management stays reachable.
# - unavailable-ics: fail-closed with lan_client marked as an ICS asset
#   passes the unscanned objects.
# - excluded: an exclude entry for lan_client wins over the include entry,
#   EICAR passes and the gate records no object event for it.
#
# Exit status: 0 when every check passes, 1 when a check fails, 2 on a
# harness error (missing tool, failed compose or exec, dead listener,
# broken client route, a policy that does not save, commit or become
# ready), which never counts as a pass or as a detected failure.
#
# SMOKE_MUTATION=no-gate commits every policy with an empty scan selection,
# so the gate intercepts nothing; the run must fail every refusal check.
# When SMOKE_RESULT_FILE is set, the IDs of the failed checks are written
# there, one per line. SMOKE_AV_READY_TIMEOUT (seconds, default 180) bounds
# each wait for the gate to reach the state a policy implies.

COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.smoke.yml}
# Compose project and harness subnets. When another smoke stack owns the
# default networks, set a unique project, list an override file that moves
# the subnets in COMPOSE_FILE, and set the matching prefixes here
# (see test/data-smoke/README.md).
SMOKE_PROJECT=${SMOKE_PROJECT:-deploy}
WAN_NET=${SMOKE_WAN_NET:-172.30.0}
LAN_NET=${SMOKE_LAN_NET:-172.31.0}
BASE=${BASE:-http://localhost:18080/api/v1}
TOKEN=${TOKEN:-devtoken}
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
CURL="curl -sf --max-time 30 --connect-timeout 5"
SMOKE_SKIP_UP=${SMOKE_SKIP_UP:-0}
SMOKE_BUILD=${SMOKE_BUILD:-1}
SMOKE_MUTATION=${SMOKE_MUTATION:-}
SMOKE_RESULT_FILE=${SMOKE_RESULT_FILE:-}
PROBE_TIMEOUT=${SMOKE_PROBE_TIMEOUT:-10}
READY_TIMEOUT=${SMOKE_AV_READY_TIMEOUT:-180}
DNAT_PORT=${DNAT_PORT:-8088}
TESTS_PASSED=0
TESTS_EXPECTED=25
FAILED_CHECKS=""
FINISHED=0

ENGINE_WAN="${WAN_NET}.2"
ENGINE_LAN="${LAN_NET}.2"
LAN_CLIENT="${LAN_NET}.3"
AV_SERVER="${WAN_NET}.11"
AV_TARGET="${LAN_NET}.11"
# A remote ICAP server that is down: av_server answers no ICAP port, so the
# engine's connection is refused and every scan is an unscanned outcome.
ICAP_DOWN="${AV_SERVER}:1344"
# MD5 and size of the EICAR test file, the one signature clamd loads.
EICAR_MD5=44d88612fea8a8f36de82e1278abb02f
EICAR_SIZE=68
ICS_ASSET_ID=smoke-ics-client

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}
log() { echo "[$(timestamp)] $*"; }
pass() {
  TESTS_PASSED=$((TESTS_PASSED + 1))
  log "PASS [$1]: $2"
}
# check_fail records a failed check and lets the run continue, so one run
# reports every failed check.
check_fail() {
  FAILED_CHECKS="${FAILED_CHECKS}$1"$'\n'
  log "FAIL [$1]: $2"
}
harness_error() {
  log "HARNESS ERROR: $*" >&2
  exit 2
}

WORK_DIR=$(mktemp -d)
# shellcheck source=scripts/smoke-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/smoke-lib.sh"
trap on_exit EXIT

case "$SMOKE_MUTATION" in
  "" | no-gate) ;;
  *) harness_error "SMOKE_MUTATION must be empty or no-gate, got: $SMOKE_MUTATION" ;;
esac
if [[ -n "$SMOKE_RESULT_FILE" ]]; then
  : >"$SMOKE_RESULT_FILE"
fi

ensure_tools() {
  for bin in docker jq curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      harness_error "missing required tool: $bin"
    fi
  done
}

wait_for_http() {
  local url=$1
  for _ in $(seq 1 30); do
    if $CURL "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  harness_error "timed out waiting for $url"
}

discover_iface() {
  local state=$1 ip=$2
  echo "$state" | jq -r --arg ip "$ip" '
    map(select(.addrs[]? | contains($ip))) | .[0].name // empty
  '
}

assert_route_via() {
  local service=$1 dst=$2 gateway=$3 route
  route=$(compose exec -T "$service" ip route get "$dst" | tr -d '\r')
  if ! echo "$route" | grep -q "via ${gateway} "; then
    harness_error "$service route to $dst not via engine: $route"
  fi
}

# fetch SERVICE get IP PORT PATH | fetch SERVICE post IP PORT PATH eicar|clean
# prints the outcome of one HTTP exchange from SERVICE through
# test/data-smoke/av/client.py: "status=... bytes=... complete=... eicar=...
# line=...", "timeout", "refused", "reset", "closed" or "unreachable". A
# client that cannot run is a harness error, never an outcome.
fetch() {
  local service=$1 method=$2 ip=$3 port=$4 path=$5 out status=0
  shift 5
  out=$(compose exec -T "$service" python /opt/av/client.py "$method" "$ip" "$port" "$path" "$PROBE_TIMEOUT" "$@" 2>"$WORK_DIR/client.err") || status=$?
  out=$(printf '%s' "$out" | tr -d '\r')
  if [[ $status -ne 0 ]]; then
    harness_error "client $service $method -> $ip:$port$path did not run (exit $status): $(tr -d '\r' <"$WORK_DIR/client.err")"
  fi
  case "$out" in
    "status="* | timeout | refused | reset | closed | unreachable) printf '%s\n' "$out" ;;
    *) harness_error "client $service $method -> $ip:$port$path printed no outcome: $out" ;;
  esac
}

# outcome_field OUTCOME KEY prints KEY's value from a client outcome line.
# "line" holds the rest of the line.
outcome_field() {
  local word rest=$1
  if [[ $2 == line ]]; then
    printf '%s\n' "${rest#*line=}"
    return 0
  fi
  for word in $1; do
    if [[ $word == "$2="* ]]; then
      printf '%s\n' "${word#*=}"
      return 0
    fi
  done
  return 0
}

# reply_field LINE KEY prints KEY's value from an origin reply line
# ("server=NAME port=PORT client=IP ...").
reply_field() {
  local word
  for word in $1; do
    if [[ $word == "$2="* ]]; then
      printf '%s\n' "${word#*=}"
      return 0
    fi
  done
  return 0
}

# eicar_path CASE is the EICAR object's URL for one case. The gate
# remembers a URL whose download was infected and refuses it for ten
# minutes before contacting the origin, so each case fetches its own URL
# and is decided by its own policy, not by an earlier detection.
eicar_path() {
  printf '/eicar.txt?case=%s\n' "$1"
}

# expect_refused ID DESCRIPTION OUTCOME passes when the gate answered 403
# and no EICAR byte reached the client.
expect_refused() {
  local id=$1 desc=$2 outcome=$3
  if [[ "$(outcome_field "$outcome" status)" == 403 && "$(outcome_field "$outcome" eicar)" == no ]]; then
    pass "$id" "$desc refused ($outcome)"
  else
    check_fail "$id" "$desc was not refused with 403 and no EICAR bytes ($outcome)"
  fi
}

# expect_delivered ID DESCRIPTION OUTCOME EICAR passes when a complete 200
# response arrived whose EICAR content matches EICAR (yes or no).
expect_delivered() {
  local id=$1 desc=$2 outcome=$3 eicar=$4
  if [[ "$(outcome_field "$outcome" status)" == 200 && "$(outcome_field "$outcome" complete)" == yes && "$(outcome_field "$outcome" eicar)" == "$eicar" ]]; then
    pass "$id" "$desc delivered ($outcome)"
  else
    check_fail "$id" "$desc was not delivered whole with eicar=$eicar ($outcome)"
  fi
}

# expect_listener SOURCE IP PORT NAME is the control probe for an origin:
# SOURCE shares the origin's network segment (or is the engine), so the
# firewall does not forward the connection. A silent origin is a harness
# error, since every refusal would then have the wrong cause.
expect_listener() {
  local source=$1 ip=$2 port=$3 name=$4 reply status=0
  if [[ $source == engine ]]; then
    reply=$(compose exec -T engine curl -sS --connect-timeout "$PROBE_TIMEOUT" --max-time 10 "http://${ip}:${port}/" 2>"$WORK_DIR/control.err") || status=$?
    if [[ $status -ne 0 ]]; then
      harness_error "control probe engine -> $ip:$port failed (exit $status): $(tr -d '\r' <"$WORK_DIR/control.err")"
    fi
    reply=$(printf '%s' "$reply" | tr -d '\r')
  else
    reply=$(outcome_field "$(fetch "$source" get "$ip" "$port" /)" line)
  fi
  if [[ "$(reply_field "$reply" server)" != "$name" || "$(reply_field "$reply" port)" != "$port" ]]; then
    harness_error "control probe $source -> $ip:$port: want $name listening, got: $reply"
  fi
  log "Control: $name answers on $ip:$port from $source ($reply)"
}

# origin_log SERVICE prints the origin's request log, one JSON object per
# line, empty before its first request.
origin_log() {
  compose exec -T "$1" sh -c 'cat /tmp/av-requests.jsonl 2>/dev/null || true' | tr -d '\r'
}

# origin_last_client SERVICE PATH prints the client address the origin saw
# on its latest request for PATH, or nothing.
origin_last_client() {
  origin_log "$1" | jq -r --arg path "$2" 'select((.path | split("?")[0]) == $path) | .client' | tail -n 1
}

# origin_upload_count SERVICE MD5 counts the POST bodies with MD5 the origin
# received.
origin_upload_count() {
  origin_log "$1" | jq -r --arg md5 "$2" 'select(.method == "POST" and .md5 == $md5) | .md5' | grep -c . || true
}

api_get() {
  $CURL -H "$AUTH_HEADER" "${BASE}$1"
}

# av_status prints the av entry of the services status.
av_status() {
  api_get /services/status | jq -c '.av'
}

# events prints the engine's av events as a JSON array (a filtered query
# answers a page object whose events field holds them).
events() {
  api_get '/events?protocol=av&limit=5000' | jq -c 'if type == "array" then . else (.events // []) end'
}

# event_count KIND_REGEX SRC_IP [ORIGINAL_DESTINATION] counts the gate
# object events of those kinds for connections from SRC_IP; with a third
# argument, only those recorded with that pre-DNAT destination.
event_count() {
  local kind=$1 src=$2 original=${3:-}
  events | jq -r --arg kind "$kind" --arg src "$src" --arg original "$original" '
    [.[] | select((.kind | test($kind)) and .srcIp == $src
      and ($original == "" or .attributes.original_destination == $original))] | length'
}

# wait_gate STATE READY polls the AV status until the gate reports STATE
# and the scanner readiness READY (true or false), with no pending reload.
wait_gate() {
  local state=$1 ready=$2 status deadline
  deadline=$((SECONDS + READY_TIMEOUT))
  while :; do
    status=$(av_status)
    if [[ "$(printf '%s' "$status" | jq -r '[.gate.state, (.ready | tostring), (.reload_pending // false | tostring)] | join(" ")')" == "$state $ready false" ]]; then
      log "Gate is $state, scanner ready=$ready: $(printf '%s' "$status" | jq -c '{mode, ready, error: (.error // ""), gate: {state: .gate.state, admit: .gate.admit, fail_policy: .gate.fail_policy, scanner: .gate.scanner}}')"
      return 0
    fi
    if ((SECONDS >= deadline)); then
      harness_error "gate did not reach state $state with scanner ready=$ready within ${READY_TIMEOUT}s: $status"
    fi
    sleep 2
  done
}

# apply_policy SCANNER FAIL_POLICY ICS EXCLUDE stages the harness
# configuration with the named AV policy and commits it. SCANNER is
# clamav or icap-down, ICS and EXCLUDE are true or false and mark
# lan_client as an ICS asset or exclude it from the selection.
apply_policy() {
  local scanner=$1 fail_policy=$2 ics=$3 exclude=$4 updated code resp headers
  log "Committing policy: scanner=$scanner failPolicy=$fail_policy icsClient=$ics excludeClient=$exclude${SMOKE_MUTATION:+ mutation=$SMOKE_MUTATION}..."
  updated=$(echo "$CFG" | jq --arg wan "$WAN_DEV" --arg lan "$LAN_DEV" --arg dnatPort "$DNAT_PORT" \
    --arg avTarget "$AV_TARGET" --arg lanClient "$LAN_CLIENT" --arg icapDown "$ICAP_DOWN" \
    --arg assetID "$ICS_ASSET_ID" --arg scanner "$scanner" --arg failPolicy "$fail_policy" \
    --argjson ics "$ics" --argjson exclude "$exclude" --arg mutation "$SMOKE_MUTATION" '
    .interfaces |= map(
      if .name=="wan" then .device=$wan
      elif .name=="lan1" then .device=$lan | .zone="lan"
      else . end)
    | .system.mgmt.httpListenAddr=":18080"
    | .system.mgmt.listenAddr=":18080"
    | .dataPlane.enforcement = true
    | .dataPlane.enforceTable = "containd"
    | .firewall.nat.enabled = true
    | .firewall.nat.egressZone = "wan"
    | .firewall.nat.sourceZones = ["lan"]
    | .firewall.nat.portForwards = [
        {
          id:"av-http",
          enabled:true,
          description:("WAN:" + $dnatPort + " -> av_target:80"),
          ingressZone:"wan",
          proto:"tcp",
          listenPort:($dnatPort | tonumber),
          destIP:$avTarget,
          destPort:80,
          allowedSources:[]
        }
      ]
    # The harness owns the whole forward policy, so a rule left behind by
    # an earlier run or the default config cannot open a denied flow.
    | .firewall.defaultAction = "DENY"
    | .firewall.rules = [
        {
          id:"allow-lan-client-av",
          sourceZones:["lan"],
          destZones:["wan"],
          sources:[($lanClient + "/32")],
          protocols:[{name:"tcp", port:"8080"}, {name:"tcp", port:"8082"}],
          action:"ALLOW"
        }
      ]
    | .assets = ((.assets // []) | map(select(.id != $assetID))) + [
        {id:$assetID, name:"smoke ICS client", type:"HMI", zone:"lan", ips:[$lanClient]}
      ]
    | .services.av = {
        enabled: true,
        mode: (if $scanner == "icap-down" then "icap" else "clamav" end),
        failPolicy: $failPolicy,
        timeoutSec: 5,
        httpDownload: true,
        httpUpload: true,
        icap: {servers: (if $scanner == "icap-down" then [{address: $icapDown}] else [] end)},
        clamav: {freshclamEnabled: false},
        scan: {
          include: (if $mutation == "no-gate" then [] else [
            {sourceZones:["lan"], destZones:["wan"], destPorts:["8080"]},
            {sourceZones:["wan"], destZones:["lan"], destPorts:["80"]}
          ] end),
          exclude: (if $exclude then [{sources:[($lanClient + "/32")]}] else [] end),
          icsAssets: (if $ics then [$assetID] else [] end)
        }
      }
  ')
  resp="$WORK_DIR/cfg_resp"
  code=$(echo "$updated" | $CURL -w "%{http_code}" -H "$AUTH_HEADER" -H "Content-Type: application/json" -X POST "${BASE}/config" --data-binary @- -o "$resp" 2>"$WORK_DIR/cfg_err" || true)
  if [[ "$code" != "200" ]]; then
    harness_error "config save failed (HTTP $code): body=$(cat "$resp"), err=$(cat "$WORK_DIR/cfg_err")"
  fi
  headers="$WORK_DIR/commit_headers"
  code=$($CURL -w "%{http_code}" -D "$headers" -H "$AUTH_HEADER" -X POST "${BASE}/config/commit" -o "$resp" 2>"$WORK_DIR/commit_err" || true)
  if [[ "$code" != "200" || "$(jq -r '.status' "$resp" 2>/dev/null)" != "committed" ]]; then
    harness_error "commit failed (HTTP $code): body=$(cat "$resp"), err=$(cat "$WORK_DIR/commit_err")"
  fi
  if grep -qi '^X-Containd-Warnings:' "$headers"; then
    log "Commit warnings: $(grep -i '^X-Containd-Warnings:' "$headers" | tr -d '\r')"
  fi
}

# upload_definition installs the EICAR MD5 as a custom ClamAV definition
# through the management API.
upload_definition() {
  local resp="$WORK_DIR/defs_resp" code
  printf '%s:%s:Smoke.EICAR.Test\n' "$EICAR_MD5" "$EICAR_SIZE" >"$WORK_DIR/eicar.hdb"
  code=$($CURL -w "%{http_code}" -H "$AUTH_HEADER" -X POST "${BASE}/services/av/defs" -F "file=@${WORK_DIR}/eicar.hdb;filename=eicar.hdb" -o "$resp" 2>"$WORK_DIR/defs_err" || true)
  if [[ "$code" != "200" ]]; then
    harness_error "definition upload failed (HTTP $code): body=$(cat "$resp"), err=$(cat "$WORK_DIR/defs_err")"
  fi
  log "Custom definition installed: $(jq -c . "$resp")"
}

# download_checks PREFIX runs the selected-port download and upload checks
# from lan_client against av_server:8080 with the EICAR objects refused and
# the clean ones delivered.
download_checks() {
  local prefix=$1 outcome before after seen
  log "Testing $prefix: lan_client GET EICAR from av_server:8080 (should be refused)..."
  before=$(event_count '^service\.av\.detected$' "$LAN_CLIENT")
  outcome=$(fetch lan_client get "$AV_SERVER" 8080 "$(eicar_path "$prefix")")
  expect_refused "$prefix-download-eicar" "EICAR download" "$outcome"
  if [[ $prefix == open ]]; then
    seen=$(origin_last_client av_server /eicar.txt)
    if [[ "$seen" == "$ENGINE_WAN" ]]; then
      pass open-download-source "av_server saw the engine's WAN address $ENGINE_WAN as the source of the gated download (masquerade)"
    else
      check_fail open-download-source "av_server saw source '${seen}' for /eicar.txt, want the engine's WAN address $ENGINE_WAN (lan_client is $LAN_CLIENT)"
    fi
    after=$(event_count '^service\.av\.detected$' "$LAN_CLIENT")
    if ((after > before)); then
      pass open-download-event "a detection event names lan_client $LAN_CLIENT ($before -> $after events)"
    else
      check_fail open-download-event "no detection event for lan_client $LAN_CLIENT ($before -> $after events)"
    fi
  fi
  log "Testing $prefix: lan_client GET clean file from av_server:8080 (should pass whole)..."
  outcome=$(fetch lan_client get "$AV_SERVER" 8080 /clean.txt)
  seen=$(reply_field "$(outcome_field "$outcome" line)" client)
  if [[ "$(outcome_field "$outcome" status)" == 200 && "$(outcome_field "$outcome" complete)" == yes && "$(outcome_field "$outcome" eicar)" == no && "$seen" == "$ENGINE_WAN" ]]; then
    pass "$prefix-download-clean" "clean download delivered whole, av_server saw $ENGINE_WAN ($outcome)"
  else
    check_fail "$prefix-download-clean" "clean download was not delivered whole from the engine's WAN address $ENGINE_WAN ($outcome)"
  fi
  log "Testing $prefix: lan_client POST EICAR to av_server:8080 (should be refused before the origin sees it)..."
  before=$(origin_upload_count av_server "$EICAR_MD5")
  outcome=$(fetch lan_client post "$AV_SERVER" 8080 /upload eicar)
  after=$(origin_upload_count av_server "$EICAR_MD5")
  if [[ "$(outcome_field "$outcome" status)" == 403 && "$after" == "$before" ]]; then
    pass "$prefix-upload-eicar" "EICAR upload refused, av_server received no EICAR body ($outcome)"
  else
    check_fail "$prefix-upload-eicar" "EICAR upload was not refused with 403 before the origin saw it (EICAR uploads at origin $before -> $after; $outcome)"
  fi
  log "Testing $prefix: lan_client POST clean body to av_server:8080 (should pass)..."
  outcome=$(fetch lan_client post "$AV_SERVER" 8080 /upload clean)
  seen=$(reply_field "$(outcome_field "$outcome" line)" client)
  if [[ "$(outcome_field "$outcome" status)" == 200 && "$(reply_field "$(outcome_field "$outcome" line)" method)" == POST && "$seen" == "$ENGINE_WAN" ]]; then
    pass "$prefix-upload-clean" "clean upload delivered, av_server saw $ENGINE_WAN ($outcome)"
  else
    check_fail "$prefix-upload-clean" "clean upload was not delivered from the engine's WAN address $ENGINE_WAN ($outcome)"
  fi
}

ensure_tools

if [[ "$SMOKE_SKIP_UP" != "1" ]]; then
  log "Bringing up smoke harness ($COMPOSE_FILE)..."
  if [[ "$SMOKE_BUILD" == "1" ]]; then
    compose up -d --build
  else
    compose up -d
  fi
fi

log "Waiting for management plane..."
wait_for_http "${BASE}/health"

log "Fetching interface state..."
STATE=""
for _ in $(seq 1 10); do
  STATE=$($CURL -H "$AUTH_HEADER" "${BASE}/interfaces/state" || true)
  if [[ -n "$STATE" && "$STATE" != "[]" ]]; then
    break
  fi
  sleep 2
done
WAN_DEV=$(discover_iface "$STATE" "$ENGINE_WAN")
LAN_DEV=$(discover_iface "$STATE" "$ENGINE_LAN")
if [[ -z "$WAN_DEV" || -z "$LAN_DEV" ]]; then
  harness_error "failed to discover wan/lan devices from interface state: $STATE"
fi
log "Detected wan=${WAN_DEV}, lan=${LAN_DEV}"

log "Fetching current config..."
CFG=$($CURL -H "$AUTH_HEADER" "${BASE}/config")

log "Uploading the EICAR signature as a custom definition..."
upload_definition

apply_policy clamav open false false
wait_gate open true

log "Enforced gate chains:"
for chain in gate_pre gate_admit; do
  compose exec -T engine nft list chain inet containd_policy "$chain" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
done

log "Verifying mgmt API still reachable..."
$CURL "${BASE}/health" >/dev/null

log "Setting test client routes (cross-subnet and default via the engine)..."
route_client lan_client "$LAN_CLIENT" "$LAN_NET" "$WAN_NET" "$ENGINE_LAN"
route_client av_target "$AV_TARGET" "$LAN_NET" "$WAN_NET" "$ENGINE_LAN"
route_client av_server "$AV_SERVER" "$WAN_NET" "$LAN_NET" "$ENGINE_WAN"
assert_route_via lan_client "$AV_SERVER" "$ENGINE_LAN"
assert_route_via av_target "$AV_SERVER" "$ENGINE_LAN"
assert_route_via av_server "$AV_TARGET" "$ENGINE_WAN"

log "Control probes: origins answer on their own segment..."
expect_listener engine "$AV_SERVER" 8080 av_server
expect_listener engine "$AV_SERVER" 8082 av_server
expect_listener lan_client "$AV_TARGET" 80 av_target

download_checks open

log "Testing open: DNAT WAN:${DNAT_PORT} -> av_target:80 from av_server, EICAR (should be refused)..."
BEFORE=$(event_count '^service\.av\.detected$' "$AV_SERVER" "${ENGINE_WAN}:${DNAT_PORT}")
OUTCOME=$(fetch av_server get "$ENGINE_WAN" "$DNAT_PORT" "$(eicar_path dnat)")
expect_refused dnat-download-eicar "EICAR download through the port forward" "$OUTCOME"
AFTER=$(event_count '^service\.av\.detected$' "$AV_SERVER" "${ENGINE_WAN}:${DNAT_PORT}")
if ((AFTER > BEFORE)); then
  pass dnat-download-event "a detection event names av_server $AV_SERVER with original destination ${ENGINE_WAN}:${DNAT_PORT} ($BEFORE -> $AFTER events)"
else
  check_fail dnat-download-event "no detection event for av_server $AV_SERVER with original destination ${ENGINE_WAN}:${DNAT_PORT} ($BEFORE -> $AFTER events)"
fi
log "Testing open: DNAT WAN:${DNAT_PORT} -> av_target:80 from av_server, clean file (should pass whole)..."
OUTCOME=$(fetch av_server get "$ENGINE_WAN" "$DNAT_PORT" /clean.txt)
SEEN=$(reply_field "$(outcome_field "$OUTCOME" line)" client)
if [[ "$(outcome_field "$OUTCOME" status)" == 200 && "$(outcome_field "$OUTCOME" complete)" == yes && "$(reply_field "$(outcome_field "$OUTCOME" line)" server)" == av_target && "$SEEN" == "$ENGINE_LAN" ]]; then
  pass dnat-download-clean "clean download through the port forward reached av_target, which saw the engine's LAN address $ENGINE_LAN ($OUTCOME)"
else
  check_fail dnat-download-clean "clean download through the port forward was not delivered whole by av_target from the engine's LAN address $ENGINE_LAN ($OUTCOME)"
fi

log "Testing open: lan_client GET EICAR from av_server:8082, a port outside the selection (should pass untouched)..."
BEFORE=$(event_count '^service\.av\.(detected|scanned)$' "$LAN_CLIENT")
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8082 "$(eicar_path unselected)")
expect_delivered unselected-port-eicar "EICAR download on the unselected port 8082" "$OUTCOME" yes
AFTER=$(event_count '^service\.av\.(detected|scanned)$' "$LAN_CLIENT")
if [[ "$AFTER" == "$BEFORE" ]]; then
  pass unselected-port-no-event "no gate object event for the unselected port ($BEFORE events for $LAN_CLIENT)"
else
  check_fail unselected-port-no-event "the gate recorded object events for the unselected port ($BEFORE -> $AFTER events for $LAN_CLIENT)"
fi

apply_policy clamav closed false false
wait_gate open true
download_checks closed

apply_policy icap-down open false false
wait_gate pending false
log "Testing unavailable-open: lan_client GET EICAR and clean from av_server:8080 (should pass unscanned)..."
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 "$(eicar_path unavailable-open)")
expect_delivered unavailable-open-eicar "EICAR download with the scanner unavailable under fail-open" "$OUTCOME" yes
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 /clean.txt)
expect_delivered unavailable-open-clean "clean download with the scanner unavailable under fail-open" "$OUTCOME" no

apply_policy icap-down closed false false
wait_gate pending false
log "Testing unavailable-closed: lan_client GET EICAR and clean, POST clean to av_server:8080 (should all be refused)..."
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 "$(eicar_path unavailable-closed)")
expect_refused unavailable-closed-eicar "EICAR download with the scanner unavailable under fail-closed" "$OUTCOME"
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 /clean.txt)
expect_refused unavailable-closed-clean "clean download with the scanner unavailable under fail-closed" "$OUTCOME"
OUTCOME=$(fetch lan_client post "$AV_SERVER" 8080 /upload clean)
expect_refused unavailable-closed-upload "clean upload with the scanner unavailable under fail-closed" "$OUTCOME"
log "Testing unavailable-closed: management API still answers (harness path and lan_client -> ${ENGINE_LAN}:18080)..."
MGMT_HARNESS=$($CURL -w "%{http_code}" -o /dev/null "${BASE}/health" || true)
OUTCOME=$(fetch lan_client get "$ENGINE_LAN" 18080 /api/v1/health)
if [[ "$MGMT_HARNESS" == 200 && "$(outcome_field "$OUTCOME" status)" == 200 ]]; then
  pass mgmt-reachable "management health answers 200 on the harness path and from lan_client ($OUTCOME)"
else
  check_fail mgmt-reachable "management health: harness path HTTP $MGMT_HARNESS, from lan_client: $OUTCOME"
fi

apply_policy icap-down closed true false
wait_gate pending false
log "Testing unavailable-ics: lan_client is an ICS asset, GET EICAR and clean from av_server:8080 (should pass unscanned)..."
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 "$(eicar_path unavailable-ics)")
expect_delivered unavailable-ics-eicar "EICAR download to an ICS asset with the scanner unavailable under fail-closed" "$OUTCOME" yes
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 /clean.txt)
expect_delivered unavailable-ics-clean "clean download to an ICS asset with the scanner unavailable under fail-closed" "$OUTCOME" no

apply_policy clamav open false true
wait_gate open true
log "Testing excluded: lan_client is excluded from the selection, GET EICAR from av_server:8080 (should pass untouched)..."
BEFORE=$(event_count '^service\.av\.(detected|scanned)$' "$LAN_CLIENT")
OUTCOME=$(fetch lan_client get "$AV_SERVER" 8080 "$(eicar_path excluded)")
expect_delivered excluded-eicar "EICAR download from an excluded source" "$OUTCOME" yes
AFTER=$(event_count '^service\.av\.(detected|scanned)$' "$LAN_CLIENT")
if [[ "$AFTER" == "$BEFORE" ]]; then
  pass excluded-no-event "no gate object event for the excluded source ($BEFORE events for $LAN_CLIENT)"
else
  check_fail excluded-no-event "the gate recorded object events for the excluded source ($BEFORE -> $AFTER events for $LAN_CLIENT)"
fi

FAILED_COUNT=$(printf '%s' "$FAILED_CHECKS" | grep -c . || true)
if [[ -n "$SMOKE_RESULT_FILE" ]]; then
  printf '%s' "$FAILED_CHECKS" >"$SMOKE_RESULT_FILE"
fi
if ((TESTS_PASSED + FAILED_COUNT != TESTS_EXPECTED)); then
  harness_error "ran $((TESTS_PASSED + FAILED_COUNT)) checks, TESTS_EXPECTED is $TESTS_EXPECTED"
fi
FINISHED=1
if ((FAILED_COUNT > 0)); then
  log "Failed checks${SMOKE_MUTATION:+ (mutation ${SMOKE_MUTATION})}:"
  printf '%s' "$FAILED_CHECKS" | sed 's/^/  - /'
  log "AV status: $(av_status)"
  printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$RED" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
  exit 1
fi
printf "[%s] %bSmoke test complete. Tests passed: %s/%s%b\n" "$(timestamp)" "$GREEN" "$TESTS_PASSED" "$TESTS_EXPECTED" "$RESET"
