# Performance Baseline

`containd` now includes a small, repeatable performance baseline for the dataplane decoder path. The goal is not to claim final performance numbers; it is to make regressions visible and give contributors one obvious command to run before and after dataplane work.

## Current Baseline

The baseline currently covers:

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
go tool pprof /tmp/containd-perf/dpi.cpu.pprof
go tool pprof /tmp/containd-perf/itdpi.cpu.pprof
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

## Current Limitations

This is an initial baseline, not a full performance program.

It does not yet cover:

- long-running multi-packet protocol sessions beyond the current single-packet engine and reassembly benchmarks
- UI route performance
- automated regression thresholds in CI

Those are the next maturity steps once the basic benchmark workflow is in regular use.
