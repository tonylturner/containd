#!/usr/bin/env bash
set -euo pipefail

# Prove that scripts/smoke-forward.sh detects a broken firewall: run it
# against a deliberately permissive forward policy and with masquerade of
# LAN traffic disabled. Each run must fail with exit status 1 and exactly the checks the
# mutation breaks. A pass, a harness error (exit 2) or a different set of
# failed checks fails this script.
#
# Takes the same environment as smoke-forward.sh (COMPOSE_FILE,
# SMOKE_PROJECT, SMOKE_WAN_NET, SMOKE_LAN_NET, BASE, SMOKE_SKIP_UP,
# SMOKE_BUILD). The runs leave the mutated policy in the stack's candidate
# config; the next smoke-forward.sh run replaces it.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RESULT_DIR=$(mktemp -d)
trap 'rm -rf "$RESULT_DIR"' EXIT
UNDETECTED=0

# run_mutation NAME EXPECTED_CHECK... runs the harness with SMOKE_MUTATION=NAME.
run_mutation() {
  local name=$1 result="$RESULT_DIR/$1" status=0 got="" want
  shift
  want=$(printf '%s\n' "$@" | sort | tr '\n' ' ')
  echo "==> smoke-forward.sh with SMOKE_MUTATION=$name (must fail: $want)"
  SMOKE_MUTATION=$name SMOKE_RESULT_FILE=$result bash scripts/smoke-forward.sh || status=$?
  if [[ -f "$result" ]]; then
    got=$(sort "$result" | tr '\n' ' ')
  fi
  if [[ $status -eq 1 && "$got" == "$want" ]]; then
    echo "==> mutation $name detected: failed checks $got"
  else
    echo "==> mutation $name NOT detected as expected: exit $status (want 1), failed checks '${got}' (want '${want}')" >&2
    UNDETECTED=$((UNDETECTED + 1))
  fi
}

run_mutation permissive deny-lan-wan-8082 deny-lan-target-wan deny-wan-lan-80 deny-wan-lan-22 dnat-no-allow
# The stack is up after the first run; do not rebuild it for the second.
export SMOKE_BUILD=0
run_mutation no-masquerade lan-wan-snat

if ((UNDETECTED > 0)); then
  echo "Forwarding smoke mutations: $UNDETECTED of 2 not detected" >&2
  exit 1
fi
echo "Forwarding smoke mutations: both detected"
