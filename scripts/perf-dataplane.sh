#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# All Docker operations, deadlines and teardown are owned by the coordinator.
set -euo pipefail
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 "$ROOT/test/perf/harness.py" "$@"
