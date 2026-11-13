#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Focused entry point into the shared genuine-image upgrade driver.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${RULE_MODES_IMAGE:?set RULE_MODES_IMAGE to the branch-built firewall image}"
export UPGRADE_IMAGE=$RULE_MODES_IMAGE
if [[ -n ${RULE_MODES_RESULTS:-} ]]; then export UPGRADE_RESULTS=$RULE_MODES_RESULTS; fi
exec bash "$ROOT/scripts/smoke-upgrade.sh" --from-version 0.1.35 --profile training
