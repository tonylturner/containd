#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Genuine published-image upgrades on fresh private data. See test/upgrade/README.md.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${UPGRADE_IMAGE:?set UPGRADE_IMAGE to a uniquely tagged candidate built from this checkout}"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-upgrade-$(date -u +%Y%m%d%H%M%S)-$$}
export UPGRADE_RESULTS=${UPGRADE_RESULTS:-$ROOT/build/$COMPOSE_PROJECT_NAME}
exec python3 "$ROOT/test/upgrade/run.py" "$@"
