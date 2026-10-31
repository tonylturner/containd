#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Receiver-verified monitor/enforce checks in fresh, isolated AF_PACKET and
# NFQUEUE stacks. Requires Docker Compose >=2.24.4 (!override), jq, Python, Go.
# Build the current firewall once; every run gets its own ports, subnets, data,
# networks and image tag. Queue mode intentionally has no engine-down bypass.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STAMP=$(date -u +%Y%m%d-%H%M%S)-$$
RESULTS=${RULE_MODES_RESULTS:-$ROOT/build/rule-modes-$STAMP}
IMAGE=${RULE_MODES_IMAGE:-containd/containd:rule-modes-$STAMP}
mkdir -p "$RESULTS"
docker build -f "$ROOT/build/Dockerfile.mgmt" -t "$IMAGE" "$ROOT"
PROJECT="rule-modes-$STAMP"
COMPOSE_FILE="$ROOT/deploy/docker-compose.smoke.yml:$RESULTS/override.yml"
export COMPOSE_FILE
# shellcheck source=scripts/smoke-lib.sh
source "$ROOT/scripts/smoke-lib.sh"
cleanup() {
  compose down --volumes --remove-orphans --timeout 10
}
trap cleanup EXIT
for capture in afpacket nfqueue; do
  SMOKE_PROJECT="$PROJECT-$capture"
  export SMOKE_PROJECT
  mkdir -p "$RESULTS/$capture/data"
  python3 - "$RESULTS/override.yml" "$RESULTS/$capture/data" "$IMAGE" <<'PY'
import pathlib,sys
out,data,image=sys.argv[1:]
services={'engine':('wan_net',2,'lan_net',2),'lan_client':('lan_net',3),'lan_target':('lan_net',4),'wan_server':('wan_net',3),'ot_client':('lan_net',5),'modbus_server':('wan_net',4),'av_server':('wan_net',11),'av_target':('lan_net',11)}
lines=['services:']
for name,coords in services.items():
    lines+=['  '+name+':']
    if name=='engine':
        lines+=['    image: '+image,'    ports: !override ["127.0.0.1::18080"]','    volumes:','      - '+str(pathlib.Path(data).resolve())+':/data']
    lines+=['    networks:']
    for i in range(0,len(coords),2):
        net,n=coords[i:i+2]
        prefix='10.235.0' if net=='wan_net' else '10.236.0'
        lines+=['      '+net+':','        ipv4_address: '+prefix+'.'+str(n)]
lines+=['networks:','  wan_net:','    ipam:','      config: !override [{subnet: "10.235.0.0/24"}]','  lan_net:','    ipam:','      config: !override [{subnet: "10.236.0.0/24"}]']
pathlib.Path(out).write_text('\n'.join(lines)+'\n')
PY
  compose up -d --force-recreate
  BASE="http://127.0.0.1:$(compose port engine 18080 | awk -F: '{print $NF}')/api/v1"
  export BASE
  SMOKE_SKIP_UP=1 SMOKE_BUILD=0 SMOKE_WAN_NET=10.235.0 SMOKE_LAN_NET=10.236.0 \
    SMOKE_RULE_MODES_ONLY=1 SMOKE_DPI_CAPTURE=$capture bash "$ROOT/scripts/smoke-dpi.sh" \
    >"$RESULTS/$capture/modbus.log" 2>&1
  compose logs --no-color >"$RESULTS/$capture/compose.log"
  cleanup
  # IEC truth harness already owns isolated ports, networks and tmpfs /data.
  SMOKE_RULE_MODES_ONLY=1 SMOKE_DPI_CAPTURE=$capture IEC104_FIREWALL_IMAGE=$IMAGE \
    IEC104_PROJECT="$PROJECT-iec-$capture" IEC104_CC_SUBNET=10.237.0 IEC104_RTU_SUBNET=10.238.0 \
    IEC104_RESULTS_DIR="$RESULTS/$capture/iec104" bash "$ROOT/scripts/smoke-iec104.sh"
done
RULE_MODES_IMAGE=$IMAGE RULE_MODES_RESULTS="$RESULTS/migration" bash "$ROOT/scripts/smoke-rule-modes-migration.sh"
printf 'Rule modes smoke complete; evidence: %s\n' "$RESULTS"
