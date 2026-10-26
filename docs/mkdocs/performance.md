# Performance Baseline

Use the dataplane decoder benchmarks to compare packet-path changes before
and after a refactor. These microbenchmarks do not measure whole-appliance
throughput or latency under live traffic.

## Benchmark Scope

The baseline covers:

- the engine packet path in `pkg/dp/engine`
- TCP reassembly in `pkg/dp/dpi`
- representative IT-DPI decoders in `pkg/dp/itdpi`
  - DNS
  - HTTP
  - TLS

The benchmark entry points live in:

- `pkg/dp/dpi/reassembly_bench_test.go`
- `pkg/dp/engine/bench_test.go`
- `pkg/dp/itdpi/bench_test.go`

## Run The Baseline

From the repo root:

```bash
bash scripts/perf-baseline.sh
```

This runs:

```bash
go test ./pkg/dp/engine ./pkg/dp/dpi ./pkg/dp/itdpi -run=^$ -bench=. -benchmem -benchtime=100x
```

## Capture Profiles

To collect CPU and memory profiles for the current benchmark packages:

```bash
bash scripts/perf-baseline.sh --profile
```

By default, profiles are written under `${TMPDIR:-/tmp}/containd-perf`.

Inspect them with:

```bash
go tool pprof "${TMPDIR:-/tmp}/containd-perf/dpi.cpu.pprof"
go tool pprof "${TMPDIR:-/tmp}/containd-perf/itdpi.cpu.pprof"
```

## How To Use This

Use the baseline when changing:

- packet parsing
- engine packet handling
- TCP reassembly
- decoder helper logic
- allocation-heavy dataplane paths

Recommended workflow:

1. run the baseline before the change
2. make the dataplane change
3. rerun the baseline
4. if a benchmark regresses, capture a profile before merging

## Limitations

The baseline does not cover:

- long-running multi-packet protocol sessions beyond the current single-packet engine and reassembly benchmarks
- UI route performance
- automated regression thresholds in CI

Compare runs on the same host and toolchain, and inspect allocation counts
as well as timing. Microbenchmark results alone do not establish live
forwarding capacity.
