#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

bench_time="100x"
profile=0
out_dir="${TMPDIR:-/tmp}/containd-perf"

usage() {
    cat <<EOF
Usage: bash scripts/perf-baseline.sh [--bench-time 100x] [--profile] [--out-dir DIR]

Runs the current dataplane performance baseline:
  - pkg/dp/engine benchmarks
  - pkg/dp/dpi benchmarks
  - pkg/dp/itdpi benchmarks

Options:
  --bench-time VALUE   Passed to go test -benchtime (default: 100x)
  --profile            Also collect cpu and memory profiles for the benchmark packages
  --out-dir DIR        Output directory for profiles (default: ${TMPDIR:-/tmp}/containd-perf)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bench-time)
            shift
            bench_time="${1:-}"
            if [ -z "$bench_time" ]; then
                echo "--bench-time requires a value" >&2
                exit 1
            fi
            ;;
        --profile)
            profile=1
            ;;
        --out-dir)
            shift
            out_dir="${1:-}"
            if [ -z "$out_dir" ]; then
                echo "--out-dir requires a value" >&2
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

printf '\n==> Dataplane benchmark baseline\n'
go test ./pkg/dp/engine ./pkg/dp/dpi ./pkg/dp/itdpi -run=^$ -bench=. -benchmem -benchtime="$bench_time"

if [ "$profile" -eq 1 ]; then
    mkdir -p "$out_dir"

    printf '\n==> Profiling pkg/dp/engine\n'
    go test ./pkg/dp/engine \
        -run=^$ \
        -bench=. \
        -benchtime="$bench_time" \
        -cpuprofile "$out_dir/engine.cpu.pprof" \
        -memprofile "$out_dir/engine.mem.pprof"

    printf '\n==> Profiling pkg/dp/dpi\n'
    go test ./pkg/dp/dpi \
        -run=^$ \
        -bench=. \
        -benchtime="$bench_time" \
        -cpuprofile "$out_dir/dpi.cpu.pprof" \
        -memprofile "$out_dir/dpi.mem.pprof"

    printf '\n==> Profiling pkg/dp/itdpi\n'
    go test ./pkg/dp/itdpi \
        -run=^$ \
        -bench=. \
        -benchtime="$bench_time" \
        -cpuprofile "$out_dir/itdpi.cpu.pprof" \
        -memprofile "$out_dir/itdpi.mem.pprof"

    cat <<EOF

Profiles written to:
  $out_dir/engine.cpu.pprof
  $out_dir/engine.mem.pprof
  $out_dir/dpi.cpu.pprof
  $out_dir/dpi.mem.pprof
  $out_dir/itdpi.cpu.pprof
  $out_dir/itdpi.mem.pprof

Inspect with:
  go tool pprof $out_dir/engine.cpu.pprof
  go tool pprof $out_dir/dpi.cpu.pprof
  go tool pprof $out_dir/itdpi.cpu.pprof
EOF
fi
