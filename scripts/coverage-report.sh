#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

top_n=15
profile_out=""
keep_artifacts=0

usage() {
    cat <<'EOF'
Usage: bash scripts/coverage-report.sh [--top N] [--profile-out PATH] [--keep-artifacts]

Runs `go test ./... -cover` and prints a repo-local coverage summary:
  - total statement coverage
  - category averages
  - lowest-coverage packages

Options:
  --top N             Number of lowest-coverage packages to print (default: 15)
  --profile-out PATH  Copy the generated coverprofile to PATH
  --keep-artifacts    Keep the temporary log/profile directory and print its path
  -h, --help          Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --top)
            shift
            if [ "$#" -eq 0 ]; then
                echo "--top requires a value" >&2
                exit 1
            fi
            top_n="$1"
            ;;
        --profile-out)
            shift
            if [ "$#" -eq 0 ]; then
                echo "--profile-out requires a path" >&2
                exit 1
            fi
            profile_out="$1"
            ;;
        --keep-artifacts)
            keep_artifacts=1
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

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/containd-coverage.XXXXXX")"
log_file="$tmpdir/go-test-cover.log"
profile_file="$tmpdir/coverage.out"
package_file="$tmpdir/packages.tsv"
category_file="$tmpdir/categories.tsv"

cleanup() {
    if [ "$keep_artifacts" -eq 0 ]; then
        rm -rf "$tmpdir"
    fi
}
trap cleanup EXIT

cd "$repo_root"

printf '==> go test coverage\n'
GOFLAGS='' go test ./... -covermode=count -coverprofile="$profile_file" 2>&1 | tee "$log_file"

awk '
/coverage: [0-9.]+% of statements/ {
    pkg = ($1 == "ok" || $1 == "?" || $1 == "FAIL") ? $2 : $1
    cov = $0
    sub(/^.*coverage: /, "", cov)
    sub(/% of statements.*$/, "", cov)
    printf "%s\t%s\n", pkg, cov
}
' "$log_file" > "$package_file"

if [ ! -s "$package_file" ]; then
    echo "failed to parse package coverage from go test output" >&2
    exit 1
fi

if [ -n "$profile_out" ]; then
    cp "$profile_file" "$profile_out"
fi

total_coverage="$(go tool cover -func "$profile_file" | awk '/^total:/{print $NF}')"

awk -F '\t' '
function category(pkg) {
    if (pkg ~ /\/api\//) return "API"
    if (pkg ~ /\/cmd\//) return "Commands"
    if (pkg ~ /\/pkg\/app\//) return "App"
    if (pkg ~ /\/pkg\/cli$/ || pkg ~ /\/pkg\/cli\//) return "CLI"
    if (pkg ~ /\/pkg\/cp\//) return "Control Plane"
    if (pkg ~ /\/pkg\/dp\//) return "Dataplane"
    if (pkg ~ /\/pkg\/mp\//) return "Management Plane"
    if (pkg ~ /\/pkg\/common\// || pkg ~ /\/pkg\/common$/) return "Common"
    return "Other"
}
{
    c = category($1)
    sum[c] += $2
    count[c]++
}
END {
    for (c in sum) {
        printf "%s\t%.1f\t%d\n", c, sum[c] / count[c], count[c]
    }
}
' "$package_file" | sort > "$category_file"

printf '\nTotal statement coverage: %s\n' "$total_coverage"

printf '\nCategory averages:\n'
awk -F '\t' '{ printf "  %-18s %5.1f%% (%d packages)\n", $1, $2, $3 }' "$category_file"

printf '\nLowest-coverage packages (top %s):\n' "$top_n"
sort -t $'\t' -k2,2n -k1,1 "$package_file" | head -n "$top_n" | awk -F '\t' '{ printf "  %-70s %5.1f%%\n", $1, $2 }'

if [ "$keep_artifacts" -eq 1 ]; then
    printf '\nArtifacts kept under: %s\n' "$tmpdir"
fi
