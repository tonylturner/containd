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
per workload/mode. Its artifacts are explicitly **not publishable figures**.

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
  DPI off is never run.

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
  sessions completing transactions, zero application errors/timeouts, zero
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

The wall-time ceiling is ninety minutes, including builds and setup. The
appliance is limited to four CPUs and 2 GiB; each endpoint to two CPUs and
512 MiB. A preflight VM `MemFree` below 4 GiB, any owned-container OOM kill or
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

No full-run figures are published yet. Produce the versioned raw bundle and
replicated tables with the full command above. Publish its run ID, source SHA,
image IDs/digests/platforms, redacted applied configuration/revision, effective
caps, host model/chip/core/RAM/power state, Docker/Desktop/VM configuration,
endpoint limits, tool versions and exact workload beside any figures.

| Workload / DPI / mode / N / offered tx/s | Goodput Mbps | Successful tx/s | RTT p50/p95/p99 ms | Errors/timeouts | Cap hits | CPU / peak memory | Repeats / range |
|---|---|---|---|---|---|---|---|

| Workload / DPI / mode | Highest confirmed N | First failing N | Hold | Success / latency at N | Limiting resource | Effective caps / peak memory |
|---|---|---|---|---|---|---|
