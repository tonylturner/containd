#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

threshold=20
top=30

usage() {
    cat <<EOF
Usage: bash scripts/complexity-report.sh [--over 20] [--top 30]

Reports current gocyclo hotspots without failing the full local verify flow.

Options:
  --over N   Report functions with complexity greater than N (default: 20)
  --top N    Show at most N results after sorting by complexity (default: 30)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --over)
            shift
            threshold="${1:-}"
            if [ -z "$threshold" ]; then
                echo "--over requires a value" >&2
                exit 1
            fi
            ;;
        --top)
            shift
            top="${1:-}"
            if [ -z "$top" ]; then
                echo "--top requires a value" >&2
                exit 1
            fi
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

cd "$repo_root"

run_gocyclo() {
    if command -v gocyclo >/dev/null 2>&1; then
        gocyclo -over "$threshold" .
        return
    fi
    GOFLAGS= go run github.com/fzipp/gocyclo/cmd/gocyclo@latest -over "$threshold" .
}

tmp_out="$(mktemp "${TMPDIR:-/tmp}/containd-gocyclo.XXXXXX")"
tmp_err="$(mktemp "${TMPDIR:-/tmp}/containd-gocyclo.XXXXXX.err")"
cleanup() {
    rm -f "$tmp_out"
    rm -f "$tmp_err"
}
trap cleanup EXIT

set +e
run_gocyclo >"$tmp_out" 2>"$tmp_err"
gocyclo_exit=$?
set -e

if [ "$gocyclo_exit" -ne 0 ] && [ "$gocyclo_exit" -ne 1 ]; then
    cat "$tmp_err" >&2
    exit "$gocyclo_exit"
fi

if [ ! -s "$tmp_out" ]; then
    echo "No functions over complexity threshold $threshold."
    exit 0
fi

echo "Cyclomatic complexity hotspots (threshold > $threshold, top $top):"
sort -rn "$tmp_out" | sed -n "1,${top}p"
