#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
python3 -m unittest discover -s "$ROOT/test/perf" -p '*_test.py' -v
# Unknown arguments must fail before any Docker call.
if bash "$ROOT/scripts/perf-dataplane.sh" --not-a-profile >/dev/null 2>&1; then
  echo 'unknown profile unexpectedly succeeded' >&2
  exit 1
fi
