#!/usr/bin/env bash
# Repro for the nflog re-bind race: hammer the engine's /internal/config
# (the endpoint every mgmt commit calls) and watch for
# service.nflog.unavailable. Usage: repro.sh [pairs] [sleep-seconds]
set -euo pipefail
ENGINE=${ENGINE:-http://localhost:18081}
PAIRS=${1:-25}
GAP=${2:-0.2}
body='{"enforcement":true,"enforceTable":"containd","nflogGroup":100,"dpiEnabled":true}'
post() { curl -sf -H 'Content-Type: application/json' -X POST "$ENGINE/internal/config" --data "$body" >/dev/null; }
tripped=0
for n in $(seq 1 "$PAIRS"); do
  post; post
  sleep "$GAP"
  if curl -sf "$ENGINE/internal/events?limit=500" | grep -q service.nflog.unavailable; then
    echo "TRIPPED after $n pairs"
    curl -sf "$ENGINE/internal/events?limit=500" | jq -c '[.[]|select(.kind=="service.nflog.unavailable")]|.[0]' 2>/dev/null || true
    tripped=1
    break
  fi
done
[ "$tripped" = 0 ] && echo "CLEAN after $PAIRS pairs"
exit $tripped
