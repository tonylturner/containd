#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Smoke-test the public Compose quickstart (deploy/docker-compose.yml): start
# it, wait for health, rotate the bootstrap password, auto-assign interfaces
# and check that the monitoring APIs answer with JSON. CI runs it against the
# image it builds. Requirements: Docker with Compose, curl, jq and Python 3.
#
# Environment:
#   CONTAIND_IMAGE              image to test (Compose default when unset)
#   QUICKSTART_COMPOSE_OVERRIDE optional isolation override file
#   COMPOSE_PROJECT_NAME        Compose project (default containd-quickstart)
#   CONTAIND_JWT_SECRET         JWT secret (a random one when unset)
#   CONTAIND_PUBLISH_HTTP_PORT  published management port (default 8080)
# Compose also reads its other inputs, such as the CONTAIND_PUBLISH_*_PORT
# and CONTAIND_*_SUBNET variables, from the environment.
# The project and its volumes are removed on exit; on failure the container
# log is printed first.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE_FILE_PATH="$ROOT/deploy/docker-compose.yml"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-containd-quickstart}"
if [ -z "${CONTAIND_JWT_SECRET:-}" ]; then
  CONTAIND_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  export CONTAIND_JWT_SECRET
fi
api="http://localhost:${CONTAIND_PUBLISH_HTTP_PORT:-8080}/api/v1"
scratch="$(mktemp -d)"
# shellcheck source=scripts/config-revision.sh
source "$ROOT/scripts/config-revision.sh"
cookie="$scratch/cookie"
routing="$scratch/routing.json"
passed=0

compose() {
  local -a args=(-f "$COMPOSE_FILE_PATH")
  if [[ -n ${QUICKSTART_COMPOSE_OVERRIDE:-} ]]; then
    args+=(-f "$QUICKSTART_COMPOSE_OVERRIDE")
  fi
  docker compose "${args[@]}" "$@"
}

cleanup() {
  if [ "$passed" -ne 1 ]; then
    compose logs --no-color containd || true
  fi
  compose down -v || true
  rm -rf "$scratch"
}
trap cleanup EXIT

compose up -d
cid="$(compose ps -q containd)"
if [ -z "$cid" ]; then
  echo "failed to resolve quickstart container id" >&2
  exit 1
fi

status=""
for _ in $(seq 1 40); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
  if [ "$status" = "healthy" ]; then
    break
  fi
  sleep 3
done
if [ "$status" != "healthy" ]; then
  echo "quickstart container never became healthy (status=$status)" >&2
  exit 1
fi

curl -fsS "$api/health" | jq -e '.status == "ok"' >/dev/null
quickstart_password="$(python3 -c 'import secrets; print("Ci" + secrets.token_hex(8) + "Aa1")')"
curl -fsS -c "$cookie" \
  -H 'Content-Type: application/json' \
  -d '{"username":"containd","password":"containd"}' \
  "$api/auth/login" >/dev/null
curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -d "{\"currentPassword\":\"containd\",\"newPassword\":\"${quickstart_password}\"}" \
  "$api/auth/me/password" >/dev/null
curl -fsS -c "$cookie" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"containd\",\"password\":\"${quickstart_password}\"}" \
  "$api/auth/login" >/dev/null
cas_read "$scratch/config.revision" curl -fsS -b "$cookie" "$api/config/candidate" >"$scratch/candidate.json"
cas_write "$scratch/config.revision" curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"auto"}' \
  "$api/interfaces/assign" | jq -e '.interfaces | type == "array" and length > 0' >/dev/null
cas_write "$scratch/config.revision" curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -X PATCH \
  -d '{"alias":"wan-ci"}' \
  "$api/interfaces/wan" | jq -e '.alias == "wan-ci"' >/dev/null
cas_read "$scratch/config.revision" curl -fsS -b "$cookie" \
  "$api/routing" > "$routing"
cas_write "$scratch/config.revision" curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -d @"$routing" \
  "$api/routing" | jq -e 'type == "object" and ((.gateways // []) | type == "array")' >/dev/null
curl -fsS -b "$cookie" \
  "$api/interfaces/state" | jq -e 'type == "array" and length > 0' >/dev/null
curl -fsS -b "$cookie" \
  "$api/flows?limit=5" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/stats/protocols" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/stats/top-talkers?n=5" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/conntrack?limit=5" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/anomalies?limit=5" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/inventory" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/learn/datasets" | jq -e '.items | type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  "$api/signatures" | jq -e 'type == "array"' >/dev/null
curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}' \
  "$api/simulation" | jq -e '.running == true' >/dev/null
curl -fsS -b "$cookie" \
  -H 'Content-Type: application/json' \
  -d '{"action":"stop"}' \
  "$api/simulation" | jq -e '.running == false' >/dev/null
passed=1
echo "quickstart smoke passed"
