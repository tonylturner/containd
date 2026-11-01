#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Configuration snapshots and their following writes share a caller-owned token
# file. Keep separate files for independent drafts; ordinary monitoring reads
# must not replace a draft's base. Never retry a conflict automatically.

cas_revision() {
  local revision
  revision=$(cat "$1") || return
  if [[ ! $revision =~ ^[0-9a-f]{16}\.[1-9][0-9]*$ || ${#revision} -gt 64 ]]; then
    echo "missing or invalid configuration revision in $1" >&2
    return 1
  fi
  printf '%s' "$revision"
}

# COMMAND is curl, or a function that forwards curl arguments (including an
# in-container curl). Capture headers on stdout so the token file stays local.
# The remaining stdout, including curl -w output, is passed through unchanged.
# The response headers are also available as TOKEN_FILE.headers.
cas_request() {
  local state=$1 expected=$2 rc=0 line status="" revision=""
  shift 2
  if [[ -n $expected ]]; then
    set -- "$@" -H "X-Containd-If-Revision: $expected"
  fi
  "$@" -D - >"$state.response" || rc=$?
  # Do not emit a misleading curl -w 200 after a partial/failed transfer.
  [[ $rc == 0 ]] || return "$rc"
  : >"$state.headers"
  {
    while IFS= read -r line; do
      printf '%s\n' "$line" >>"$state.headers"
      line=${line%$'\r'}
      if [[ $line == HTTP/* ]]; then
        read -r _ status _ <<<"$line"
      elif [[ -z $line ]]; then
        # curl may emit an interim response before the final headers.
        [[ $status == 1?? ]] || break
      elif [[ $(printf '%s' "${line%%:*}" | tr '[:upper:]' '[:lower:]') == x-containd-revision ]]; then
        revision=${line#*:}
        revision=${revision# }
      fi
    done
    if [[ $status == 2?? ]]; then
      if [[ ! $revision =~ ^[0-9a-f]{16}\.[1-9][0-9]*$ || ${#revision} -gt 64 ]]; then
        echo "successful configuration response has no valid revision" >&2
        return 1
      fi
      printf '%s\n' "$revision" >"$state"
    fi
    cat
  } <"$state.response"
  return "$rc"
}

cas_read() {
  local state=$1
  shift
  cas_request "$state" "" "$@"
}

cas_write() {
  local state=$1 revision
  shift
  revision=$(cas_revision "$state") || return
  cas_request "$state" "$revision" "$@"
}
