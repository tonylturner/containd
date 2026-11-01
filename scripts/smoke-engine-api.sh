#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by the smoke scripts. While enforcing, the engine admits its
# API only from loopback (and from the address it is bound to in split mode).
# The harnesses use the credential-free loopback path inside the firewall container
# with the caller's `compose` function, never through a published port.

# engine_api SERVICE PATH OUT [CURL_ARG...] calls the engine API in the
# compose service SERVICE, writes the response body to OUT and prints the
# HTTP status, or 000 when no response arrived. Request bodies come from
# stdin (pass --data-binary @-).
engine_api() {
  local service=$1 path=$2 out=$3 resp
  shift 3
  if ! resp=$(compose exec -T "$service" curl -sS --max-time 10 --connect-timeout 5 \
    -w '\n%{http_code}' "$@" "http://127.0.0.1:8081${path}"); then
    : >"$out"
    printf '000'
    return 0
  fi
  printf '%s\n' "${resp%$'\n'*}" >"$out"
  printf '%s' "${resp##*$'\n'}"
}

# engine_apply_id prints a fresh opaque runtime apply ID. One apply sequence
# (/internal/config, then /internal/apply_rules) sends one ID; the engine
# rejects an ID once a newer apply has superseded it.
engine_apply_id() {
  printf 'smoke-%s-%s-%s' "$(date +%s)" "$RANDOM" "$RANDOM"
}

# engine_apply SERVICE PATH OUT APPLY_ID posts the JSON document on stdin to
# the runtime apply route PATH as part of apply APPLY_ID.
engine_apply() {
  engine_api "$1" "$2" "$3" -X POST -H 'Content-Type: application/json' \
    -H "X-Containd-Apply-Id: $4" --data-binary @-
}

# engine_get SERVICE PATH OUT fetches PATH.
engine_get() {
  engine_api "$1" "$2" "$3" </dev/null
}
