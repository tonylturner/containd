# Data Plane Overview

## Components
- Capture manager (`pkg/dp/capture`): AF_PACKET capture worker (Linux) with interface validation.
- Engine harness (`pkg/dp/engine`): starts capture, hot-swaps immutable rule snapshots, runs native IDS over DPI events, manages NFQUEUE selective DPI steering, per-flow verdict caching, ICS asset auto-discovery, anomaly detection, signature matching, learn mode, and protocol statistics.
- Rule snapshots (`pkg/dp/rules`): immutable bundles with firewall entries, IDS rules, and default action; evaluator supports allow/deny matching on zones, CIDRs, protocol/port with ranges; ICS, identity, and schedule predicates are evaluated when present.
- Flow tracking (`pkg/dp/flow`): flow key/state scaffolding with timeouts, hashing (strings.Builder optimized), and sweep outside mutex.
- TCP reassembly (`pkg/dp/reassembly`): out-of-order segment handling with pre-allocated buffers.
- Verdict cache (`pkg/dp/engine`): per-flow DPI verdict cache (TOCTOU-safe) to avoid redundant inspection of already-classified flows.
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
5) DPI decoders (15 protocols via `DefaultDecoders()`, filtered by per-protocol enable/disable settings):
   - ICS: Modbus, DNP3, CIP/EtherNet/IP (with full EPATH and MSP sub-service parsing), S7comm, IEC 61850 MMS, BACnet, OPC UA.
   - IT: DNS (with compression pointer support), TLS (SNI/JA3), HTTP, SSH, SMB, NTP, SNMP, RDP.
   - TCP reassembly with out-of-order handling feeds protocol parsers.
   - Protocol-specific parsers emit `dpi.Event` structs.
   - Same decoder set is shared between live engine and offline PCAP analysis.
   - DPI operates in **learn** mode (passive observation) or **enforce** mode (active policy enforcement). See [ICS DPI](ics-dpi.md#dpi-modes).
6) IDS/IPS engine consuming DPI events and flow context for signatures/behavioral rules.
7) ICS asset auto-discovery builds inventory from observed traffic.
8) Anomaly detection identifies malformed frames, protocol violations, and rate anomalies.
9) Signature engine matches against 16 built-in ICS malware signatures.
10) Learn mode records traffic profiles and generates allowlist rules.
11) Protocol statistics and top talkers are tracked per flow.

## Rule model
- Source/dest zones, CIDRs, protocol+port (ranges). Default action fallback.
- Snapshot swapping is atomic (pointer swap in engine).

