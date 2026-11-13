# Performance Baseline

Use the dataplane decoder benchmarks to compare packet-path changes before
and after a refactor. These microbenchmarks do not measure whole-appliance
throughput or latency under live traffic.

## Benchmark Scope

The baseline covers:

- the engine packet path in `pkg/dp/engine`
- bounded engine state churn at 2×, 10× and 100× offered flow-slot cardinality
- TCP reassembly in `pkg/dp/dpi`
- representative IT-DPI decoders in `pkg/dp/itdpi`
  - DNS
  - HTTP
  - TLS

The benchmark entry points live in:

- `pkg/dp/dpi/reassembly_bench_test.go`
- `pkg/dp/engine/bench_test.go`
- `pkg/dp/engine/state_churn_bench_test.go`
- `pkg/dp/engine/packet_accounting_bench_test.go`
- `pkg/dp/engine/stream_fail_closed_test.go`
- `pkg/dp/engine/transport_bench_test.go`
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

`BenchmarkStateChurn` reports `postGC-heap-B`: process-wide `HeapAlloc` after
forced garbage collection with the populated engine still live. Compare the
plateau across offered cardinalities on the same host and toolchain; this is
not an inspection-byte charge or a whole-process memory bound. Each iteration
advances an injected clock beyond flow expiry before offering another wave.

For a focused short run:

```bash
go test ./pkg/dp/engine -run=^$ -bench=^BenchmarkStateChurn -benchtime=3x -benchmem
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

- live kernel conntrack lookup latency (transport benchmarks use fakes)
- long-running protocol sessions under live capture; reassembly benchmarks use synthetic in-order and gap-fill payloads
- UI route performance
- automated regression thresholds in CI

Compare runs on the same host and toolchain, and inspect allocation counts
as well as timing. Microbenchmark results alone do not establish live
forwarding capacity.

## Live inline ICS measurements

`bash scripts/perf-dataplane.sh` measures **Docker Desktop lab measurements**,
not bare-metal appliance sizing or physical wire rate. It routes an IPv4 client
on an isolated LAN through the real combined appliance to a peer on an isolated
WAN, without NAT. Only management is published, on an ephemeral loopback port.
HTTP inline figures wait for HTTP inline steering.

Prerequisites are native arm64 macOS, Docker Desktop, Compose with
`interface_name` support, Python 3.12+, and sufficient shared-VM headroom. Do not
stop other workloads or change Docker Desktop settings to improve a result.
The script builds uniquely tagged product and harness images from this checkout;
it does not modify product Dockerfiles or install benchmark rules in nftables.
The endpoint image pins its arm64 base digests, Go version and measurement tools.

Run the short plumbing check first:

```bash
COMPOSE_PROJECT_NAME="containd-perf-smoke-$(date +%s)" \
  bash scripts/perf-dataplane.sh --smoke
```

Smoke uses one-second warmup and three-second measurement windows, one repetition
per workload/mode. Every main/probe hold must succeed without application errors,
queue drops or cap hits; DPI-on decode proof must be positive, not vacuously zero.
Its artifacts are explicitly **not publishable figures**.

For a full run, record the settings currently displayed in Docker Desktop
without changing them. Supply its version, backend, network mode, allocated
CPUs, memory and swap; for example, replace the values below with your settings:

```bash
export PERF_DESKTOP_SETTINGS_JSON='{"version":"your version","backend":"your backend","network":"your network mode","cpus":16,"memory_gib":31.5,"swap_gib":1}'
COMPOSE_PROJECT_NAME="containd-perf-full-$(date +%s)" \
  bash scripts/perf-dataplane.sh
```

Every project name must start with `containd-perf-` and be unused. The script
collision-checks private subnets, uses fresh data and appliance state for every
independent trial, and removes only its own containers, networks and data volume,
including on failure or interruption. Logs and ownership-check evidence remain
under `build/perf/<project>/`, along with `bundle.json` (schema 1), raw snapshots,
load histograms and `figures.md`. Preserve the entire directory with published
results; a summary table alone is not reproducible evidence.

### Modes and workload

- **NFQUEUE traversal / monitor inspection:** identical monitor transport scopes
  and separate L4 admission, with only `dataplane.dpiEnabled` toggled. Mock is
  false and exclusions are empty. Both directions traverse the production queue.
- **Inline enforcement:** read-only ICS ALLOW rules, DPI on. Its matched
  monitor/L4 DPI-off reference is **not the identical policy**. Enforce with
  DPI off is never run. IEC 104 uses safe-read admission, including STARTDT
  and S acknowledgements; these frames have no ASDU type or common address.

The fixed protocol-aware workload is Modbus FC3 reading registers 0–1, DNP3
class-0 reads with validated link/data CRCs, transport and application sequence
numbers, and IEC 104 STARTDT followed by C_RD_NA_1 reads and M_SP_NA_1 replies,
with advancing I-frame sequence numbers and S acknowledgements. Connections are
persistent, TCP_NODELAY is enabled, and each session has one outstanding
transaction. A separate 10 tx/s application probe runs during load. A same-side
endpoint control is recorded as calibration, never as a routed result.

### Measurement definitions

- **Application goodput:** decimal Mbps = eight times complete validated request
  plus reply bytes divided by the monotonic measured duration and 1,000,000.
  Protocol headers are included, TCP/IP headers excluded; IEC supervisory/setup
  frames are excluded. Only successful, fully validated transactions count.
  Request and reply byte totals are also retained separately.
- **Forward L3 Mbps / IP skb/s:** peer network-namespace `IpExtInOctets` and
  `IpInReceives` deltas bracket the steady window. These include IP headers and
  all client-to-peer IP traffic, including the independent probe and TCP ACKs.
  Outbound counters are retained separately. Offload settings are recorded, not
  changed: observed IP skbs are not physical wire packets. Bounded premeasurement
  tcpdump captures supply path and packet-size evidence, including capture-drop
  reports; empty captures are rejected. Retransmission counters are retained.
- **Latency:** client monotonic request start to complete validated reply,
  application RTT p50/p95/p99 in milliseconds, excluding setup and warmup.
  Mergeable histograms use one-percent logarithmic upper bounds from one
  microsecond, with 1,802 fixed bins and an explicit overflow count. A p99 with
  fewer than 10,000 successes is labelled insufficient samples. Timeout is two
  seconds. Errors, timeouts, resets and missed offered slots remain visible;
  success-only quantiles are not an error-free latency guarantee. Pacing is
  closed loop and self-throttles under load (coordinated omission); late slots
  are counted, not caught up in bursts.
- **Sessions:** client connections that finish protocol setup and a validated
  transaction, then remain simultaneously open and transact throughout the
  steady hold. Peer application-ready/established counts, scoped `ss`, engine
  state and conntrack observations are retained independently. Directional
  engine flows are not TCP sessions. The independent probe adds one socket,
  explicitly outside the headline N.
- **Sustainable:** a full 60-second steady hold with all N application-ready
  sessions completing transactions at no less than 99% of the offered rate
  (the load is closed-loop, so a shortfall means saturation), zero
  application errors/timeouts, zero
  unexpected NFQUEUE drops and zero cap-hit deltas. Effective state limits,
  occupancies and all refused/evicted/truncated ledger hits are recorded.
  This workload does not replace distinct-host-pair or incomplete-frame cap
  pressure tests.

The full profile explores geometric N/rate points (1 at 100 tx/s, 8 and 32 at
1,000 tx/s), narrowing a discovered failure interval once. It then confirms the
selected sustainable point with five independent repetitions of each mode,
using ten-second warmup, at least sixty-second measurement, and alternating
monitor off/on order. Exploratory observations are retained separately, not
mixed into replicated headline medians/ranges. Session results say **highest
confirmed N / first failing N**, or **at least N tested, budget-limited**, never
maximum capacity. Client or peer CPU saturation marks endpoint-limited results.

The wall-time ceiling is ninety minutes, including builds, setup and host sleep;
the budget uses macOS's continuous monotonic clock, not active uptime. The
appliance is limited to four CPUs and 2 GiB; each endpoint to two CPUs and
512 MiB. A preflight VM `MemAvailable` below 4 GiB, any owned-container OOM kill or
budget expiry aborts the run and still tears down. Partial runs retain evidence
but omit incompletely replicated headline rows. Resource samples every five
seconds retain cgroup CPU/current/peak memory and engine RSS/Go heap. Other
containers, the shared VM scheduler, host power/thermal state and virtual
network offloads remain sources of noise.

Readiness includes routes and interfaces, installed policy/protection, queue
binding, a live but denied control listener and an appliance-down negative
probe. Decoder proof is the workload protocol's `eventCount` delta from
`GET /api/v1/stats/protocols`: on must cover at least all successful main/probe
transactions; off must be zero. `packetCount` and `byteCount` are captured
transport accounting, not decode counts. NFQUEUE delivered-ID sequence/drop
snapshots prove traffic traversed the queue in both modes.

### Results

First published run: `containd-perf-full-1794599562`, 2026-11-13, source
`7056ca15` (merged to `main` in 0.1.44 development), full profile, five
repetitions per row.

- **Host:** MacBook Pro Mac15,9, Apple M3 Max (16 cores: 12 performance,
  4 efficiency), 128 GB, macOS 27.0.1; the run held a `caffeinate` assertion
  against idle sleep.
- **Docker:** Docker Desktop 4.92.0 (240144), Engine 29.8.0, LinuxKit kernel
  7.0.12, default Apple Virtualization backend and networking; VM 16 CPUs,
  31.5 GiB, 1 GiB swap, 22 unrelated containers running.
- **Limits:** appliance 4 CPUs / 2 GiB; client and peer 2 CPUs / 512 MiB each.
  Default traffic-state limits. IPv4, MTU 1500, no NAT, TCP_NODELAY, one
  outstanding transaction per session, plus a 10 tx/s probe.
- **Images:** appliance `sha256:9198e87cac44`, harness
  `sha256:aeb0f3532a95`, both linux/arm64 built from the source above.

These are **Docker Desktop lab measurements** on a shared developer VM, not
appliance sizing. Offered load was capped at 1,000 tx/s; none of these rows is
a maximum.

| Workload / mode / DPI / N | tx/s median [range] | RTT p50/p95/p99 ms | Appliance CPU / peak MiB |
|---|---|---|---|
| Modbus / monitor / off / 32 | 999.99 [999.91–1000.00] | 0.38 / 0.63 / 1.33 | 0.69 / 68.7 |
| Modbus / monitor / on / 32 | 999.98 [996.95–1000.00] | 0.40 / 1.87 / 6.61 | 0.77 / 87.9 |
| Modbus / enforce / on / 32 | 999.98 [999.45–1000.00] | 0.41 / 0.73 / 1.55 | 0.61 / 87.3 |
| DNP3 / monitor / off / 32 | 999.97 [995.37–999.99] | 0.46 / 0.96 / 2.19 | 0.63 / 66.4 |
| DNP3 / monitor / on / 32 | 999.98 [998.99–999.99] | 0.52 / 1.47 / 5.05 | 0.82 / 101.2 |
| DNP3 / enforce / on / 32 | 999.99 [995.28–999.99] | 0.54 / 3.10 / 10.76 | 0.76 / 107.8 |
| IEC 104 / monitor / off / 4 | 996.20 [974.25–999.96] | 0.61 / 1.78 / 4.10 | 0.85 / 66.7 |
| IEC 104 / monitor / on / 4 | 997.25 [984.50–999.91] | 0.68 / 1.22 / 2.62 | 0.95 / 91.9 |
| IEC 104 / enforce / on / 4 | 991.45 [882.18–997.95] | 0.67 / 2.47 / 5.42 | 1.10 / 115.3 |

Every row had zero application errors, timeouts, NFQUEUE drops and cap hits.
DPI-off rows decoded zero events; DPI-on rows decoded at least one event per
transaction. Goodput is 0.20 Mbps (Modbus), 0.33 Mbps (DNP3) and 0.25 Mbps
(IEC 104) at 1,000 tx/s. Latency columns are medians of the five repetitions.

- **Modbus and DNP3:** 32 sessions at 1,000 tx/s held in every mode and every
  repetition. Decoding adds up to 0.2 appliance cores and under 0.1 ms
  at the median; it widens the tail.
- **IEC 104:** each transaction is about four queued packets, against two for
  Modbus and DNP3. At 1,000 tx/s the appliance uses about one core in all three
  modes, DPI off included, and some repetitions fall below 99% of the
  offered rate. This is consistent with the single NFQUEUE queue being the
  bottleneck (inferred, not profiled). No IEC 104 session count is confirmed
  sustainable at 1,000 tx/s; 4 sessions is the first failing point and the
  limit is not decoding, since DPI-off rows also fall short. An exploratory
  8-session DPI-on run reached 968 tx/s.

| Workload | Highest confirmed N at 1,000 tx/s | First failing N |
|---|---|---|
| Modbus/TCP | 32 (all modes) | not reached |
| DNP3/TCP | 32 (all modes) | not reached |
| IEC 104 | none | 4 (all modes) |

The raw bundle (`bundle.json`, per-trial snapshots, captures and histograms)
for this run is kept with the release evidence, not in the repository.
Reproduce with the full command above; results on other hosts will differ.
