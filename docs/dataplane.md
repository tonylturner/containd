# Data Plane Overview

This document tracks the data-plane design and current scaffolding.

## Current scaffolding
- Capture manager (`pkg/dp/capture`): placeholder that validates interfaces and will host RX workers (NFQUEUE/AF_PACKET planned).
- Engine harness (`pkg/dp/engine`): starts capture, hot-swaps immutable rule snapshots, runs native IDS over DPI events, and exposes `ShouldInspect` for selective DPI steering.
- Rule snapshots (`pkg/dp/rules`): immutable bundles with firewall entries, IDS rules, and default action; evaluator supports allow/deny matching on zones, CIDRs, protocol/port with ranges; ICS/identity predicates stubbed.

## Pipeline (planned)
1) Kernel enforcement via nftables/conntrack for fast path; userspace compiles/installs rules.
2) Selective capture (NFQUEUE/AF_PACKET) for DPI/IDS flows.
3) Flow tracker (5-tuple + direction, timestamps, state) for enrichment and IDS.
4) Rule evaluation against immutable snapshot; actions: allow/drop/reset, tag, rate-limit; IPS verdicts update nftables sets and conntrack.
5) DPI/ICS decoders:
   - TCP reassembly when needed.
   - Protocol-specific parsers emitting `dpi.Event`.
6) IDS/IPS engine consuming DPI events and flow context for signatures/behavioral rules.

## Rule model (initial)
- Source/dest zones, CIDRs, protocol+port (ranges). Default action fallback.
- Snapshot swapping is atomic (pointer swap in engine).
- Future extensions: ICS attributes (e.g., Modbus function code), identity, schedules, verdict sets for nftables and eBPF fast paths.

## Next steps
- Implement capture workers and flow tracking.
- Compile policies to nftables rules/sets; add verdict integration (IPS updates).
- Extend evaluator for ICS/identity-aware predicates.
- Integrate DPI decoders into flow processing and rule context enrichment.
- Surface metrics/telemetry for throughput and drop counters; optional eBPF probes.
