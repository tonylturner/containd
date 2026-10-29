#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the Compose smoke harness. Sourcing this file defines
# functions only; callers retain their shell options and install their traps.

# COMPOSE_FILE is a colon-separated list, as in docker compose itself, so an
# override file can follow the base harness file. SMOKE_PROJECT names the stack.
compose() {
  local files=() args=() file
  IFS=: read -r -a files <<<"$COMPOSE_FILE"
  for file in "${files[@]}"; do
    args+=(-f "$file")
  done
  docker compose --project-name "$SMOKE_PROJECT" "${args[@]}" "$@"
}

# route_client SERVICE ADDR NET PEER_NET GATEWAY sends SERVICE's traffic for
# the other harness subnet, and its default route, through the engine.
route_client() {
  local service=$1 addr=$2 net=$3 peer_net=$4 gateway=$5
  compose exec -T "$service" ip route flush table main
  compose exec -T "$service" ip route add "${net}.0/24" dev eth0 scope link src "$addr"
  compose exec -T "$service" ip route add "${peer_net}.0/24" via "$gateway" dev eth0
  compose exec -T "$service" ip route add default via "$gateway" dev eth0
}

# EXIT handler for harnesses with WORK_DIR, FINISHED and log(). DPI uses its
# own cleanup trap instead, without translating command failures to exit 2.
on_exit() {
  local rc=$?
  rm -rf "$WORK_DIR"
  # Only the final summary decides between pass and failed checks; any
  # other non-zero exit (set -e, a failed exec) is a harness error.
  if [[ $FINISHED -ne 1 && $rc -ne 0 ]]; then
    if [[ $rc -ne 2 ]]; then
      log "HARNESS ERROR: a harness command failed (exit $rc)" >&2
    fi
    exit 2
  fi
}
