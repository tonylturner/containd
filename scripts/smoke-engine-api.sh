#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by the smoke scripts. While enforcing, the engine admits its
# API only from loopback (and from the address it is bound to in split mode).
# The harnesses use the credential-free loopback path inside the firewall container
# with the caller's `compose` function, never through a published port.

# engine_get SERVICE PATH OUT reads engine telemetry in the compose service
# SERVICE, writes the response body to OUT and prints its HTTP status (or 000
# when no response arrived). Configuration belongs to management save/commit,
# not a harness-owned engine apply sequence.
engine_get() {
  local service=$1 path=$2 out=$3 resp
  if ! resp=$(compose exec -T "$service" curl -sS --max-time 10 --connect-timeout 5 \
    -w '\n%{http_code}' "http://127.0.0.1:8081${path}" </dev/null); then
    : >"$out"
    printf '000'
    return 0
  fi
  printf '%s\n' "${resp%$'\n'*}" >"$out"
  printf '%s' "${resp##*$'\n'}"
}
