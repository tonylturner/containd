#!/usr/bin/env bash
# NFQUEUE preflight helpers, sourced by preflight-iec104.sh after run-state
# initialization; not a standalone script. Requires the caller's Docker Compose,
# jq and Python 3 tools, project/image names and results paths.
# Records results and tears down run-owned resources via the caller's EXIT trap.
# See test/iec104/README.md#nfqueue-kernel-preflight.

compose() {
  docker compose --project-name "$PROJECT" --project-directory "$ROOT" -f "$COMPOSE_FILE" "$@"
}

add_error() {
  local message=$1
  local tmp="$RESULTS_FILE.tmp"
  jq --arg message "$message" '.errors += [$message]' "$RESULTS_FILE" >"$tmp"
  mv "$tmp" "$RESULTS_FILE"
}

record_case() {
  local name=$1 status=$2 assertion=$3 metrics=${4:-'{}'}
  local stats error_count new_errors
  if [[ "$SCENARIO_VERDICT_FAILED" -eq 1 ]]; then
    status=FAIL
    assertion+="; at least one verdict submission failed or timed out (not retried)"
    metrics=$(jq -cn --argjson metrics "$metrics" \
      --argjson failures "$SCENARIO_VERDICT_FAILURES" \
      '$metrics + {verdict_submission_failures:$failures}')
  fi
  if stats=$(fw GET /stats); then
    error_count=$(jq -r '.verdict_errors | length' <<<"$stats")
    if [[ "$error_count" -gt "$CASE_VERDICT_ERRORS" ]]; then
      new_errors=$(jq -c --argjson from "$CASE_VERDICT_ERRORS" '.verdict_errors[$from:]' <<<"$stats")
      status=FAIL
      assertion+="; SetVerdict reported $(jq -r 'length' <<<"$new_errors") error(s)"
      metrics=$(jq -cn --argjson metrics "$metrics" --argjson errors "$new_errors" \
        '$metrics + {setverdict_errors:$errors}')
    fi
    CASE_VERDICT_ERRORS=$error_count
  else
    status=FAIL
    assertion+="; could not retrieve NFQUEUE stats to check verdict errors"
  fi
  local tmp="$RESULTS_FILE.tmp"
  jq --arg name "$name" --arg status "$status" --arg assertion "$assertion" \
    --argjson metrics "$metrics" \
    '.scenarios += [{name:$name,status:$status,assertion:$assertion,metrics:$metrics}]' \
    "$RESULTS_FILE" >"$tmp"
  mv "$tmp" "$RESULTS_FILE"
  printf '%-48s %s\n' "$name" "$status"
  if [[ "$status" == "FAIL" ]]; then
    CASE_FAILURES=$((CASE_FAILURES + 1))
  fi
  if [[ "$CURRENT_SCENARIO" == "$name" ]]; then
    CURRENT_SCENARIO=""
    SCENARIO_VERDICT_FAILED=0
    SCENARIO_VERDICT_FAILURES='[]'
  fi
}

record_evidence() {
  local key=$1 value=$2
  local tmp="$RESULTS_FILE.tmp"
  jq --arg key "$key" --argjson value "$value" \
    '.evidence[$key]=$value' "$RESULTS_FILE" >"$tmp"
  mv "$tmp" "$RESULTS_FILE"
}

begin_scenario() {
  CURRENT_SCENARIO=$1
  SCENARIO_VERDICT_FAILED=0
  SCENARIO_VERDICT_FAILURES='[]'
}

record_latency_evidence() {
  local stats=$1 latencies
  latencies=$(jq -cn \
    --argjson setverdict "$(jq -c .setverdict_latency <<<"$stats")" \
    --argjson handler "$(jq -c .verdict_handler_latency <<<"$stats")" \
    '{
      setverdict:{
        count:$setverdict.count,
        verdict_latency_max_ms:$setverdict.max_ms,
        verdict_latency_p99_ms:$setverdict.p99_ms
      },
      http_verdict_handler:{
        count:$handler.count,
        verdict_latency_max_ms:$handler.max_ms,
        verdict_latency_p99_ms:$handler.p99_ms
      }
    }')
  record_evidence verdict_latency "$latencies"
}

observe_failed_verdict() {
  local id=$1 prefix=$2 events='{"events":[]}' completed=false event stats metrics
  for _ in $(seq 1 150); do
    if ! events=$(fw GET /events); then
      break
    fi
    if jq -e --argjson id "$id" \
      'any(.events[]; .id == $id and ((.verdict // "") != "" or (.verdict_error // "") != ""))' \
      <<<"$events" >/dev/null; then
      completed=true
      break
    fi
    sleep 0.1
  done
  event=$(jq -c --argjson id "$id" '[.events[] | select(.id == $id)] | first // null' <<<"$events")
  if ! stats=$(fw GET /stats); then
    stats='{}'
  else
    record_latency_evidence "$stats"
    record_evidence setverdict_semantics "$(jq -cn \
      --arg source 'go-nfqueue v2.0.3 SetVerdict sends without a kernel ACK; nil means submitted without a local Send error, not confirmed disposition.' \
      --argjson stats "$stats" \
      '{observed_source_semantics:$source,observed_run_stats:$stats}')"
  fi
  metrics=$(jq -cn --argjson id "$id" --arg prefix "$prefix" \
    --argjson completed "$completed" --argjson event "$event" --argjson stats "$stats" \
    '{packet_id:$id,prefix:$prefix,observer_wait_limit_ms:15000,handler_completed_after_client_timeout:$completed,packet_event:$event,setverdict_latency:$stats.setverdict_latency,verdict_handler_latency:$stats.verdict_handler_latency,verdict_errors:$stats.verdict_errors,request_retried:false}')
  printf '%s\n' "$metrics"
}

note_failed_verdict() {
  local id=$1 prefix=$2 observation
  observation=$(observe_failed_verdict "$id" "$prefix")
  SCENARIO_VERDICT_FAILED=1
  SCENARIO_VERDICT_FAILURES=$(jq -cn \
    --argjson existing "$SCENARIO_VERDICT_FAILURES" \
    --argjson failure "$observation" '$existing + [$failure]')
  record_evidence failed_verdict_observation "$observation"
  if jq -e '.handler_completed_after_client_timeout == true' \
    <<<"$observation" >/dev/null; then
    printf 'POST /verdict failed or timed out for packet %s; handler was observed to finish; not retried\\n' \
      "$id" >&2
    return 0
  fi
  printf 'POST /verdict failed for packet %s and handler remained unresolved; not retried\\n' \
    "$id" >&2
  return 1
}

wait_verdict_events() {
  local ids_json=$1 events
  for _ in $(seq 1 150); do
    if ! events=$(fw GET /events); then
      return 1
    fi
    if jq -e --argjson ids "$ids_json" \
      '. as $snapshot | all($ids[]; . as $id | any($snapshot.events[]; .id == $id and ((.verdict // "") != "" or (.verdict_error // "") != "")))' \
      <<<"$events" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

call() {
  local service=$1 base=$2 method=$3 path=$4 body=${5-}
  if [[ -n "$body" ]]; then
    compose exec -T "$service" /usr/local/bin/preflight ctl "$base" "$method" "$path" "$body"
  else
    compose exec -T "$service" /usr/local/bin/preflight ctl "$base" "$method" "$path"
  fi
}

fw() {
  call firewall http://127.0.0.1:8081 "$@"
}

endpoint() {
  local service=$1
  shift
  call "$service" http://127.0.0.1:8080 "$@"
}

set_rule() {
  local prefix=$1 direction=$2 action=$3 delay_ms=$4
  local body
  body=$(jq -cn --arg prefix "$prefix" --arg direction "$direction" --arg action "$action" \
    --argjson delay "$delay_ms" \
    '{prefix:$prefix,direction:$direction,action:$action,delay_ms:$delay}')
  fw POST /rule "$body" >/dev/null
}

start_capture() {
  local name=$1 side
  CURRENT_CAPTURE=$name
  for side in client server; do
    # The single-quoted command is interpreted inside the endpoint container; $1 and $2 are its arguments.
    # shellcheck disable=SC2016
    compose exec -T "$side" sh -c \
      'tcpdump -i eth0 -U -w "/results/$1-$2.pcap" tcp port 2404 >/tmp/$1-$2-tcpdump.log 2>&1 & echo $! > /tmp/$1-$2-tcpdump.pid' \
      sh "$name" "$side"
  done
  sleep 0.2
  for side in client server; do
    # shellcheck disable=SC2016
    compose exec -T "$side" sh -c 'test -s "/results/$1-$2.pcap"' sh "$name" "$side"
  done
}

stop_capture() {
  local name=${1:-$CURRENT_CAPTURE} side tmp
  [[ -n "$name" ]] || return 0
  for side in client server; do
    # shellcheck disable=SC2016
    compose exec -T "$side" sh -c \
      'p=$(cat "/tmp/$1-$2-tcpdump.pid"); kill -INT "$p"; n=0; while kill -0 "$p" 2>/dev/null; do n=$((n+1)); [ "$n" -lt 60 ] || exit 1; sleep 0.1; done; test -s "/results/$1-$2.pcap"' \
      sh "$name" "$side"
  done
  tmp="$RESULTS_FILE.tmp"
  jq --arg client "$name-client.pcap" --arg server "$name-server.pcap" \
    '.pcaps += [$client,$server]' "$RESULTS_FILE" >"$tmp"
  mv "$tmp" "$RESULTS_FILE"
  CURRENT_CAPTURE=""
}

new_connection() {
  local response
  response=$(endpoint client POST /connect '{}')
  CLIENT_ID=$(jq -er '.id' <<<"$response")
  # shellcheck disable=SC2034  # consumed by the caller's RST/reconnect scenarios
  CLIENT_PORT=$(jq -er '.local_addr | capture(":(?<port>[0-9]+)$").port | tonumber' <<<"$response")
  local server_connections
  for _ in $(seq 1 50); do
    server_connections=$(endpoint server GET /connections)
    if jq -e --argjson id "$CLIENT_ID" 'any(.[]; .id == $id)' \
      <<<"$server_connections" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_held() {
  local prefix=$1 count=$2 response
  for _ in $(seq 1 80); do
    response=$(fw GET /held)
    if jq -e --arg prefix "$prefix" --argjson count "$count" \
      '[.held[] | select(.prefix | startswith($prefix))] | length >= $count' \
      <<<"$response" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

held_id() {
  local prefix=$1 response
  response=$(fw GET /held)
  jq -er --arg prefix "$prefix" \
    '[.held[] | select(.prefix | startswith($prefix)) | .id] | first' <<<"$response"
}

release_held() {
  local prefix=$1 id body
  if ! id=$(held_id "$prefix"); then
    record_case "$CURRENT_SCENARIO" FAIL "Could not identify held packet for prefix $prefix"
    fatal "Could not identify held packet for explicit verdict submission"
  fi
  body=$(jq -cn --argjson id "$id" '{id:$id,action:"accept"}')
  if fw POST /verdict "$body" >/dev/null; then
    return 0
  else
    if ! note_failed_verdict "$id" "$prefix"; then
      fatal "Held-packet verdict submission did not complete after its client failure"
    fi
    return 0
  fi
}

release_all_held() {
  local prefix=$1 held ids id body
  for _ in $(seq 1 30); do
    if ! held=$(fw GET /held); then
      return 1
    fi
    if ! ids=$(jq -r --arg prefix "$prefix" \
      '.held[] | select(.prefix | startswith($prefix)) | .id' <<<"$held"); then
      return 1
    fi
    if [[ -z "$ids" ]]; then
      return 0
    fi
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      body=$(jq -cn --argjson id "$id" '{id:$id,action:"accept"}')
      if fw POST /verdict "$body" >/dev/null; then
        :
      else
        if ! note_failed_verdict "$id" "$prefix"; then
          return 1
        fi
      fi
    done <<<"$ids"
    sleep 0.05
  done
  return 1
}

wait_received() {
  local service=$1 id=$2 expected=$3 response
  for _ in $(seq 1 80); do
    response=$(endpoint "$service" GET "/conn?id=$id")
    if jq -e --arg expected "$expected" '.received == $expected' \
      <<<"$response" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_event_verdict() {
  local prefix=$1 verdict=$2 response
  for _ in $(seq 1 80); do
    response=$(fw GET /events)
    if jq -e --arg prefix "$prefix" --arg verdict "$verdict" \
      'any(.events[]; .matched and (.prefix | startswith($prefix)) and .verdict == $verdict)' \
      <<<"$response" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

hold_time_ms() {
  local prefix=$1 verdict=$2 response
  response=$(fw GET /events)
  jq -r --arg prefix "$prefix" --arg verdict "$verdict" \
    '[.events[] | select(.matched and (.prefix | startswith($prefix)) and .verdict == $verdict) | .hold_ms] | max // 0' \
    <<<"$response"
}

close_endpoint() {
  local service=$1 id=$2
  endpoint "$service" POST "/close?id=$id" '{}' >/dev/null
}

stop_capture_or_fail() {
  if ! stop_capture; then
    add_error "Failed to stop or flush one of the endpoint pcaps for ${CURRENT_CAPTURE:-unknown scenario}"
    exit 1
  fi
}

finish() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ -n "$CURRENT_CAPTURE" && $STACK_ATTEMPTED -eq 1 ]]; then
    if ! stop_capture >/dev/null 2>&1; then
      add_error "Capture teardown failed for $CURRENT_CAPTURE"
      rc=1
    fi
  fi
  if [[ $STACK_ATTEMPTED -eq 1 ]]; then
    if ! compose down --timeout 10 --volumes --remove-orphans --rmi local >/dev/null 2>&1; then
      add_error "docker compose down failed for project $PROJECT"
      compose down --timeout 10 --volumes --remove-orphans --rmi local >/dev/null 2>&1
      rc=1
    fi
    if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
      if ! docker image rm "$IMAGE_NAME" >/dev/null 2>&1; then
        add_error "Could not remove run-owned image $IMAGE_NAME"
        rc=1
      fi
    fi
    local remaining
    remaining=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT}_" || true)
    if [[ -n "$remaining" ]]; then
      add_error "Run-owned Docker networks remain after compose down: $remaining"
      rc=1
    fi
  fi

  if [[ -f "$RESULTS_FILE" ]]; then
    local tmp
    for name in "${REQUIRED_CASES[@]}"; do
      if ! jq -e --arg name "$name" 'any(.scenarios[]; .name == $name)' \
        "$RESULTS_FILE" >/dev/null 2>&1; then
        tmp="$RESULTS_FILE.tmp"
        jq --arg name "$name" \
          '.scenarios += [{name:$name,status:"NOT_RUN",assertion:"Harness stopped before this required scenario",metrics:{}}]' \
          "$RESULTS_FILE" >"$tmp"
        mv "$tmp" "$RESULTS_FILE"
        rc=1
      fi
    done
    if [[ $CASE_FAILURES -gt 0 ]]; then rc=1; fi
    tmp="$RESULTS_FILE.tmp"
    jq --arg status "$([[ $rc -eq 0 ]] && printf PASS || printf FAIL)" \
      --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '.status=$status | .finished_at=$finished' "$RESULTS_FILE" >"$tmp"
    mv "$tmp" "$RESULTS_FILE"
    printf '\nPASS/FAIL table\n'
    jq -r '.scenarios[] | [.status,.name,.assertion] | @tsv' "$RESULTS_FILE" \
      | while IFS=$'\t' read -r status name assertion; do
          printf '%-10s %-48s %s\n' "$status" "$name" "$assertion"
        done
    printf '\nResults: %s\n' "$RESULTS_FILE"
    printf 'Status: %s\n' "$(jq -r .status "$RESULTS_FILE")"
  fi
  exit "$rc"
}
trap finish EXIT

fatal() {
  local message=$1
  printf 'FATAL: %s\n' "$message" >&2
  if [[ -n "$CURRENT_SCENARIO" ]] &&
    ! jq -e --arg name "$CURRENT_SCENARIO" 'any(.scenarios[]; .name == $name)' \
      "$RESULTS_FILE" >/dev/null 2>&1; then
    record_case "$CURRENT_SCENARIO" FAIL "$message" '{"fatal":true}'
  fi
  add_error "$message"
  exit 1
}
