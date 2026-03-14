#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: bash scripts/semgrep-verify.sh

Runs Semgrep with the curated containd baseline. The baseline currently allows
two appliance-specific findings:
  - internal loopback/self-signed HTTPS for the in-app CLI transport
  - host-preserving HTTP->HTTPS appliance upgrade redirects

Any additional finding fails the script.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -ne 0 ]; then
    echo "unknown option: $1" >&2
    usage >&2
    exit 1
fi

allowed_findings='[
  {
    "check_id": "problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification",
    "path": "api/http/cli_handlers.go"
  },
  {
    "check_id": "go.lang.security.injection.open-redirect.open-redirect",
    "path": "pkg/app/mgmt/tls_support.go"
  }
]'

json_out="$(mktemp "${TMPDIR:-/tmp}/containd-semgrep.XXXXXX.json")"
log_out="$(mktemp "${TMPDIR:-/tmp}/containd-semgrep.XXXXXX.log")"
cleanup() {
    rm -f "$json_out" "$log_out"
}
trap cleanup EXIT

cd "$repo_root"

run_semgrep() {
    if command -v semgrep >/dev/null 2>&1; then
        semgrep --config auto --json >"$json_out" 2>"$log_out"
        return $?
    fi
    if command -v docker >/dev/null 2>&1; then
        docker run --rm \
            -v "$repo_root:/src" \
            -w /src \
            returntocorp/semgrep \
            semgrep --config auto --json >"$json_out" 2>"$log_out"
        return $?
    fi
    echo "semgrep is not installed and docker is unavailable" >&2
    return 2
}

set +e
run_semgrep
semgrep_exit=$?
set -e

if [ "$semgrep_exit" -ne 0 ] && [ "$semgrep_exit" -ne 1 ]; then
    cat "$log_out" >&2
    exit "$semgrep_exit"
fi

allowlisted_count="$(jq --argjson allow "$allowed_findings" '
  [ .results[]
    | . as $result
    | select(any($allow[]; .check_id == $result.check_id and .path == $result.path))
  ] | length
' "$json_out")"

unexpected="$(jq --argjson allow "$allowed_findings" '
  [
    .results[]
    | . as $result
    | select((any($allow[]; .check_id == $result.check_id and .path == $result.path) | not))
    | {
        severity: .extra.severity,
        check_id: .check_id,
        path: .path,
        line: .start.line,
        message: .extra.message
      }
  ]
' "$json_out")"

unexpected_count="$(printf '%s\n' "$unexpected" | jq 'length')"

if [ "$unexpected_count" -ne 0 ]; then
    printf 'Unexpected Semgrep findings: %s\n' "$unexpected_count" >&2
    printf '%s\n' "$unexpected" | jq -r '.[] | "\(.severity)\t\(.check_id)\t\(.path):\(.line)\t\(.message)"' >&2
    exit 1
fi

printf 'Semgrep clean. Allowlisted findings: %s\n' "$allowlisted_count"
