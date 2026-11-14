#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real TCP/NFQUEUE checks, with private data, images and no published ports.
set -Eeuo pipefail
ROOT=$(git rev-parse --show-toplevel)
case "${1:-}" in delivery|envelope|management) ;; *) echo 'usage: smoke-ds34.sh delivery|envelope|management' >&2; exit 2 ;; esac
COMPOSE_PROJECT_NAME="pairing-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
export COMPOSE_PROJECT_NAME
SMOKE_PROJECT=$COMPOSE_PROJECT_NAME
COMPOSE_FILE="$ROOT/test/ds34/compose.yml"
export DS34_RESULTS=${DS34_RESULTS:-$ROOT/build/$COMPOSE_PROJECT_NAME}
mkdir -p "$DS34_RESULTS"
[[ -z "$(ls -A "$DS34_RESULTS")" ]] || { echo "evidence directory must be empty: $DS34_RESULTS" >&2; exit 1; }
DS34_RESULTS=$(cd "$DS34_RESULTS" && pwd)
export DS34_RESULTS
# shellcheck source=scripts/smoke-lib.sh
source "$ROOT/scripts/smoke-lib.sh"
# Select unused address space, without changing any pre-existing network.
read -r DS34_LAN DS34_WAN < <(python3 - <<'PY'
import ipaddress, json, random, subprocess
ids = subprocess.check_output(['docker','network','ls','-q'], text=True).split()
networks = json.loads(subprocess.check_output(['docker','network','inspect',*ids])) if ids else []
used = [ipaddress.ip_network(c['Subnet']) for n in networks for c in (n['IPAM'].get('Config') or []) if c.get('Subnet')]
for octet in random.sample(range(32,240),208):
    nets = [ipaddress.ip_network(f'10.{octet}.{third}.0/24') for third in (240,241)]
    if not any(a.overlaps(b) for a in nets for b in used if a.version==b.version):
        print(f'10.{octet}.240 10.{octet}.241'); break
else:
    raise SystemExit('no unused private subnet pair')
PY
)
export DS34_LAN DS34_WAN
export DS34_RESERVATION="{\"subnet\":\"$DS34_LAN.0/24\",\"sources\":[\"$DS34_LAN.10\"],\"listen\":\":18080\"}"
export DS34_IMAGE="$COMPOSE_PROJECT_NAME:local"
STARTED=0
BUILT=0
PEER_BUILT=0
export DS34_PEER_IMAGE="$COMPOSE_PROJECT_NAME:peer"
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ $STARTED == 1 ]]; then
    compose logs --no-color >"$DS34_RESULTS/compose.log" 2>&1 || rc=1
    compose down --volumes || rc=1
  fi
  if [[ $BUILT == 1 ]]; then docker image rm "$DS34_IMAGE" >"$DS34_RESULTS/image-cleanup.log" 2>&1 || rc=1; fi
  if [[ $PEER_BUILT == 1 ]]; then docker image rm "$DS34_PEER_IMAGE" >"$DS34_RESULTS/peer-image-cleanup.log" 2>&1 || rc=1; fi
  echo "Evidence: $DS34_RESULTS"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ARCH=$(docker info --format '{{.Architecture}}')
case "$ARCH" in aarch64|arm64) ARCH=arm64 ;; x86_64|amd64) ARCH=amd64 ;; *) exit 1 ;; esac
GOFLAGS=-mod=mod GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$DS34_RESULTS/containd" ./cmd/containd
cp "$ROOT/test/ds34/entrypoint.sh" "$DS34_RESULTS/entrypoint.sh"
docker build -f "$ROOT/test/ds34/Dockerfile" -t "$DS34_IMAGE" "$DS34_RESULTS" >"$DS34_RESULTS/build.log" 2>&1
BUILT=1
docker build -f "$ROOT/test/ds34/peers/tcp/Dockerfile.j60870" -t "$DS34_PEER_IMAGE" "$ROOT/test/ds34/peers/tcp" >"$DS34_RESULTS/peer-build.log" 2>&1
PEER_BUILT=1
STARTED=1
compose up -d
route_client master "$DS34_LAN.10" "$DS34_LAN" "$DS34_WAN" "$DS34_LAN.2"
route_client outstation "$DS34_WAN.10" "$DS34_WAN" "$DS34_LAN" "$DS34_WAN.2"
route_client upstream "$DS34_WAN.11" "$DS34_WAN" "$DS34_LAN" "$DS34_WAN.2"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/test/ds34/run.py" "$1"
