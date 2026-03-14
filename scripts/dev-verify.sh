#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

with_trivy=0
with_semgrep=0
with_coverage=0
with_race=0

usage() {
    cat <<'EOF'
Usage: bash scripts/dev-verify.sh [--with-trivy] [--with-semgrep] [--with-coverage] [--with-race]

Runs the standard local verification set for containd:
  - go vet ./...
  - golangci-lint run
  - staticcheck
  - ineffassign
  - shellcheck on repo shell entrypoints
  - go test ./...
  - ui lint
  - mkdocs build

If golangci-lint or shellcheck are not installed locally, the script falls
back to the official container images for those tools. If staticcheck or
ineffassign are not installed locally, the script falls back to `go run`.

Optional:
  --with-trivy   Also run the repo filesystem vulnerability scan.
  --with-semgrep Also run the curated Semgrep security scan.
  --with-coverage Also run the package coverage summary workflow.
  --with-race    Also run the targeted race-regression package set.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-trivy)
            with_trivy=1
            ;;
        --with-semgrep)
            with_semgrep=1
            ;;
        --with-coverage)
            with_coverage=1
            ;;
        --with-race)
            with_race=1
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

run_step() {
    printf '\n==> %s\n' "$1"
}

shellcheck_targets=(
    scripts/bootstrap-starter.sh
    scripts/containd
    scripts/containd-connect
    scripts/coverage-report.sh
    scripts/dev-verify.sh
    scripts/perf-baseline.sh
    scripts/quickstart.sh
    scripts/semgrep-verify.sh
    scripts/smoke-dpi.sh
    scripts/smoke-forward.sh
    scripts/smoketest
)

cd "$repo_root"

run_step "go vet"
go vet ./...

run_step "golangci-lint"
if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run
elif command -v docker >/dev/null 2>&1; then
    docker run --rm \
        -v "$repo_root:/app" \
        -w /app \
        golangci/golangci-lint:v2.11.3 \
        golangci-lint run
else
    echo "golangci-lint is not installed and docker is unavailable" >&2
    exit 1
fi

run_step "staticcheck"
if command -v staticcheck >/dev/null 2>&1; then
    staticcheck ./...
else
    GOFLAGS='' go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...
fi

run_step "ineffassign"
if command -v ineffassign >/dev/null 2>&1; then
    ineffassign ./...
else
    GOFLAGS='' go run github.com/gordonklaus/ineffassign@latest ./...
fi

run_step "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${shellcheck_targets[@]}"
elif command -v docker >/dev/null 2>&1; then
    docker run --rm \
        -v "$repo_root:/mnt" \
        -w /mnt \
        koalaman/shellcheck-alpine:stable \
        shellcheck -x "${shellcheck_targets[@]}"
else
    echo "shellcheck is not installed and docker is unavailable" >&2
    exit 1
fi

run_step "go test"
go test ./...

run_step "ui lint"
(
    cd ui
    npm run lint
)

run_step "docs build"
mkdocs build -f docs/mkdocs.yml -d /tmp/containd-dev-verify-docs

if [ "$with_trivy" -eq 1 ]; then
    run_step "trivy fs"
    if command -v trivy >/dev/null 2>&1; then
        trivy fs \
            --scanners vuln \
            --severity HIGH,CRITICAL \
            --ignorefile .trivyignore \
            --skip-dirs ui/node_modules \
            --skip-dirs .git \
            --skip-dirs .gocache \
            --skip-dirs .gomodcache \
            --skip-dirs docs/public \
            .
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm \
            -v "$repo_root:/src" \
            -w /src \
            -v "$repo_root/.trivyignore:/root/.trivyignore:ro" \
            ghcr.io/aquasecurity/trivy:0.62.1 \
            fs \
            --scanners vuln \
            --severity HIGH,CRITICAL \
            --ignorefile /root/.trivyignore \
            --skip-dirs ui/node_modules \
            --skip-dirs .git \
            --skip-dirs .gocache \
            --skip-dirs .gomodcache \
            --skip-dirs docs/public \
            .
    else
        echo "trivy is not installed and docker is unavailable" >&2
        exit 1
    fi
fi

if [ "$with_semgrep" -eq 1 ]; then
    run_step "semgrep"
    bash scripts/semgrep-verify.sh
fi

if [ "$with_coverage" -eq 1 ]; then
    run_step "coverage"
    bash scripts/coverage-report.sh
fi

if [ "$with_race" -eq 1 ]; then
    run_step "targeted race tests"
    go test -race ./api/http ./pkg/app/engine ./pkg/cp/services ./pkg/mp/sshserver
fi

printf '\nAll requested verification steps passed.\n'
