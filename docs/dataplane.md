# Data Plane Overview

This document tracks the data-plane design and current scaffolding.

## Current scaffolding
- Capture manager (`pkg/dp/capture`): placeholder that validates interfaces and will host RX workers.
- Engine harness (`pkg/dp/engine`): starts capture, hot-swaps immutable rule snapshots, and exposes evaluation hook.
- Rule snapshots (`pkg/dp/rules`): immutable bundles with firewall entries and default action; evaluator supports simple allow/deny matching on zones, CIDRs, protocol/port.

## Pipeline (planned)
1) Interface capture (AF_PACKET/raw sockets initially) with per-interface goroutines and batching.
2) Parser → flow tracker (5-tuple + direction, timestamps, state).
3) Rule evaluation against immutable snapshot; actions: allow/drop (future: reset/mirror/tag/rate-limit).
4) DPI/ICS decoders:
   - TCP reassembly when needed.
   - Protocol-specific parsers emitting `dpi.Event`.
5) IDS/IPS engine consuming DPI events and flow context for signatures/behavioral rules.

## Rule model (initial)
- Source/dest zones, CIDRs, protocol+port. Default action fallback.
- Snapshot swapping is atomic (pointer swap in engine).
- Future extensions: ICS attributes (e.g., Modbus function code), identity, schedules.

## Next steps
- Implement capture workers and flow tracking structures.
- Extend evaluator for port ranges, ICMP, and ICS-aware predicates.
- Integrate DPI decoders into flow processing and rule context enrichment.
- Surface metrics/telemetry for throughput and drop counters.
