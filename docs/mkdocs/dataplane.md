# Data Plane Overview

## Components
- Capture manager (`pkg/dp/capture`): AF_PACKET capture worker (Linux) with interface validation.
- Engine harness (`pkg/dp/engine`): starts capture, hot-swaps immutable rule snapshots, runs native IDS over DPI events, and exposes `ShouldInspect` for selective DPI steering.
- Rule snapshots (`pkg/dp/rules`): immutable bundles with firewall entries, IDS rules, and default action; evaluator supports allow/deny matching on zones, CIDRs, protocol/port with ranges; ICS/identity predicates are matched when present.
- Flow tracking (`pkg/dp/flow`): flow key/state scaffolding with timeouts and hashing tests.
- Kernel programming (Linux):
  - Interface addressing + default routes applied via netlink (`pkg/dp/netcfg`).
  - Static routes + basic policy routing rules (PBR) applied via netlink (`routing` config).
  - nftables rules compiled/applied for zone firewall, NAT masquerade, and basic DNAT/port-forwards.
  - Ownership loop in `containd engine` re-applies interface + routing intent periodically and on netlink change events (non-destructive by default; replace semantics are admin-triggered only).

## Pipeline
1) Kernel enforcement via nftables/conntrack for fast path; userspace compiles/installs rules.
2) Selective capture (NFQUEUE/AF_PACKET) for DPI/IDS flows.
3) Flow tracker (5-tuple + direction, timestamps, state) for enrichment and IDS.
4) Rule evaluation against immutable snapshot; actions: allow/drop/reset, tag, rate-limit; IPS verdicts update nftables sets and conntrack.
5) DPI/ICS decoders:
   - TCP reassembly when needed.
   - Protocol-specific parsers emitting `dpi.Event`.
6) IDS/IPS engine consuming DPI events and flow context for signatures/behavioral rules.

## Rule model
- Source/dest zones, CIDRs, protocol+port (ranges). Default action fallback.
- Snapshot swapping is atomic (pointer swap in engine).

## Roadmap
- NFQUEUE-based selective DPI steering.
- Schedule and identity predicates in rule evaluation.
- Prometheus metrics for throughput and drop counters.
- Optional eBPF (XDP/TC) acceleration.
