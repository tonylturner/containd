#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/config-revision.sh
source "$ROOT/scripts/config-revision.sh"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/containd-revision.XXXXXX")
state="$scratch/revision"
fake_counter=1
fake_status=200
fake_expected=""
fake_with_revision=1
fake_transport_status=0
fake_interim=0
calls="$scratch/calls"

fake_curl() {
  printf 'call\n' >>"$calls"
  local sent="" dump=""
  while (($#)); do
    case $1 in
    -H)
      sent=$2
      shift 2
      ;;
    -D)
      dump=$2
      shift 2
      ;;
    *)
      echo "unexpected argument: $1" >&2
      return 1
      ;;
    esac
  done
  [[ $dump == - && $sent == "$fake_expected" ]] || return 1
  if [[ $fake_interim == 1 ]]; then printf 'HTTP/1.1 100 Continue\r\n\r\n'; fi
  printf 'HTTP/1.1 %s Test\r\n' "$fake_status"
  if [[ $fake_with_revision == 1 ]]; then
    printf 'x-containd-revision: 0123456789abcdef.%s\r\n' "$fake_counter"
  fi
  printf 'X-Containd-Warnings: test warning\r\n\r\n{"body":"unchanged"}\n%s' "$fake_status"
  return "$fake_transport_status"
}

cas_read "$state" fake_curl >"$scratch/body"
[[ $(cat "$scratch/body") == $'{"body":"unchanged"}\n200' ]] || exit 1
[[ $(cas_revision "$state") == 0123456789abcdef.1 ]] || exit 1
grep -q 'X-Containd-Warnings: test warning' "$state.headers" || exit 1
echo "PASS snapshot body, status and headers preserved"

fake_expected="X-Containd-If-Revision: $(cas_revision "$state")"
fake_counter=$((fake_counter + 1))
fake_interim=1
cas_write "$state" fake_curl >"$scratch/body"
[[ $(cas_revision "$state") == 0123456789abcdef.2 ]] || exit 1
[[ $(cat "$scratch/body") == $'{"body":"unchanged"}\n200' ]] || exit 1
echo "PASS staged acknowledgement advances the chain, including 100 Continue"

fake_expected="X-Containd-If-Revision: $(cas_revision "$state")"
fake_counter=$((fake_counter + 1))
cas_write "$state" fake_curl >"$scratch/body"
[[ $(cas_revision "$state") == 0123456789abcdef.3 ]] || exit 1
echo "PASS second write uses the first acknowledgement"

fake_expected="X-Containd-If-Revision: $(cas_revision "$state")"
fake_status=412
fake_with_revision=0
cas_write "$state" fake_curl >"$scratch/body"
[[ $(cas_revision "$state") == 0123456789abcdef.3 ]] || exit 1
[[ $(wc -l <"$calls") -eq 4 ]] || exit 1
[[ $(cat "$scratch/body") == $'{"body":"unchanged"}\n412' ]] || exit 1
echo "PASS rejected write preserves base and is never retried"

fake_status=200
if cas_write "$state" fake_curl >"$scratch/body" 2>"$scratch/error"; then
  echo "missing response revision accepted" >&2
  exit 1
fi
[[ ! -s $scratch/body && $(cas_revision "$state") == 0123456789abcdef.3 ]] || exit 1
echo "PASS missing response authority fails without a success status"

fake_with_revision=1
fake_counter=$((fake_counter + 1))
fake_transport_status=23
if cas_write "$state" fake_curl >"$scratch/body"; then
  echo "transport error ignored" >&2
  exit 1
fi
[[ ! -s $scratch/body && $(cas_revision "$state") == 0123456789abcdef.3 ]] || exit 1
echo "PASS failed transport never advances the base"

printf '*\n' >"$state"
before=$(wc -l <"$calls")
if cas_write "$state" fake_curl >"$scratch/body" 2>"$scratch/error"; then
  echo "invalid base accepted" >&2
  exit 1
fi
[[ $(wc -l <"$calls") -eq $before ]] || exit 1
echo "PASS malformed base sends no write"
