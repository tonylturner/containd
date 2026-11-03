#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit running-intent promotion for management-driven smoke harnesses.
# Requires config-revision.sh plus the caller's BASE and AUTH_HEADER.
# Saving a candidate is deliberately separate; never commit a rejected save.

# smoke_commit_config REVISION_FILE RESPONSE_FILE commits the saved candidate
# using its acknowledged CAS token. Only the coordinator delivers engine state.
# A committed response is not a certificate of runtime readiness; callers must
# observe the state or traffic their scenario requires.
smoke_commit_config() {
  local state=$1 out=$2 code
  # Allow the bounded forward apply and compensation to finish. Do not retry
  # an ambiguous transport failure or silently replace the draft's CAS base.
  if ! code=$(cas_write "$state" curl -sS --max-time 90 --connect-timeout 5 \
    -H "$AUTH_HEADER" -X POST "${BASE}/config/commit" -o "$out" -w '%{http_code}'); then
    echo "config commit transport or revision failure; inspect $out" >&2
    return 1
  fi
  if [[ $code != 200 ]] || ! jq -e '
    .status == "committed"
    and (.applyId | type == "string" and length > 0)
    and (.runningRevision | type == "string" and length > 0)
  ' "$out" >/dev/null; then
    echo "config commit failed (HTTP $code): $(cat "$out")" >&2
    return 1
  fi
}
