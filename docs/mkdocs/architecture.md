# containd Architecture

High-level architecture overview.

## Planes
- **Data plane (`containd engine`)**: kernel-assisted enforcement (nftables/conntrack), NFQUEUE selective DPI steering, per-flow verdict caching, capture, flow tracking, TCP reassembly, rule evaluator, DPI (15 protocol decoders with per-protocol enable/disable), learn/enforce DPI modes, IDS, ICS asset auto-discovery, anomaly detection, signature matching, optional eBPF XDP/TC fast path.
- **Control plane (`pkg/cp`)**: config persistence (SQLite), services (syslog/DNS/NTP/DHCP/VPN/AV/proxies), policy compilation to rule snapshots/nftables sets, policy templates (Purdue baseline, maintenance windows), audit, identity predicates, embedded-daemon config generation.
- **Management plane (`containd mgmt` + UI + CLI)**: REST API (`api/http`), Prometheus /metrics endpoint, UI serving, CLI/SSH, config lifecycle (candidate/commit/commit-confirmed/rollback/export/import/backups), PCAP offline analysis, learn mode, event export (CEF/JSON/Syslog), audit, dashboards.

## Integrated daemons
The appliance optionally embeds Envoy (explicit forward proxy), Nginx (reverse proxy), Unbound (DNS), OpenNTPD (NTP), ClamAV (AV/Freshclam), WireGuard, and OpenVPN. containd owns lifecycle, config generation, and normalizes events into a unified schema for UI/CLI. All DPI is implemented natively in Go decoders -- 7 ICS protocols (Modbus, DNP3, CIP/EtherNet/IP, S7comm, IEC 61850 MMS, BACnet, OPC UA) and 8 IT protocols (DNS, TLS, HTTP, SSH, SMB, NTP, SNMP, RDP). ICS decoders can be individually enabled/disabled and operate in learn or enforce mode (see [ICS DPI](ics-dpi.md)).

## Packaging
- Containers: `build/Dockerfile.mgmt`, `deploy/docker-compose.yml`. Single-container appliance by default; `containd` binary has `all|mgmt|engine` subcommands for split deployments.
- Host deployment to run `containd all` (or split commands); config DB default `data/config.db` (env `CONTAIND_CONFIG_DB`).

## Module boundaries
- `api/http`: `/api/v1` health, config lifecycle (candidate/commit/commit-confirmed/rollback/export/import/backups), CRUD (zones/interfaces/rules/assets), services, audit, and telemetry endpoints.
- `pkg/cp/config`: config model + validation + SQLite store with candidate/running lifecycle and schema upgrades.
- `pkg/cp/services`: syslog/DNS/NTP/proxy/VPN/AV managers render configs; optional supervision of embedded daemons (Envoy/Nginx/Unbound/OpenNTPD/ClamAV) with validation + service events.
- `pkg/common/logging`: zap-based structured logger helper (stdout + optional rotation) plus legacy prefixed UTC helpers.
- `pkg/cli`: command registry with API-backed show/set/delete for config, commit/rollback, audit, services, and diagnostics.
- `pkg/dp/capture`: AF_PACKET capture worker (Linux) with interface validation.
- `pkg/dp/rules`: immutable rule snapshots and evaluator (zones/CIDRs/proto/port ranges; ICS/identity predicates matched when present).
- `pkg/dp/engine`: harness to start capture, swap/apply rule snapshots, evaluate contexts, and apply verdict-driven updates.
- `pkg/dp/enforce`: nftables compile/apply skeleton with dynamic block sets.
- `pkg/dp/dpi`: selective DPI framework and decoder manager with NFQUEUE steering and per-flow verdict cache; HTTP previews feed AV queue; ICS marker tags OT protocols for AV fail-open.
- `pkg/dp/ics`: ICS protocol decoders (Modbus, DNP3, CIP/EtherNet/IP, S7comm, IEC 61850 MMS, BACnet, OPC UA).
- `pkg/dp/dpi/it`: IT protocol decoders (DNS, TLS, HTTP, SSH, SMB, NTP, SNMP, RDP).
- `pkg/dp/inventory`: ICS asset auto-discovery from observed traffic.
- `pkg/dp/learn`: passive traffic learning and automatic rule generation.
- `pkg/dp/anomaly`: protocol anomaly detection (malformed frames, violations, rate anomalies).
- `pkg/dp/signatures`: signature-based IDS with 16 built-in ICS malware signatures.
- `pkg/dp/stats`: protocol statistics and top talkers.
- `pkg/dp/pcap`: PCAP offline analysis with DPI and policy generation.
- `pkg/dp/export`: event export in CEF, JSON, and Syslog formats.
- `pkg/dp/verdict`: verdict types/actions used by enforcement paths.
- `pkg/dp/reassembly`: TCP reassembly with out-of-order segment handling.
- `pkg/cp/templates`: policy templates (7 ICS protocol templates, Purdue baseline, maintenance windows).
- `pkg/common/metrics`: Prometheus /metrics endpoint.
- IDS evaluation lives in `pkg/dp/ids`; eBPF XDP/TC acceleration is optional (`pkg/dp/ebpf`).

## Flow of control
1) Management plane receives config via API; persisted in SQLite with candidate/commit/commit-confirmed/rollback; audit records for config changes.
2) Control plane compiles policies to nftables rulesets/sets and DP rule snapshots; engine hot-swaps snapshots.
3) Kernel enforces fast path via nftables (or optional eBPF XDP/TC for early drops); NFQUEUE steers selected flows to userspace for DPI/IDS; per-flow verdict cache avoids redundant inspection; IPS/AV verdicts update nftables sets/conntrack (AV blocks flows on malware; ICS can be fail-open).
4) DPI decoders (DefaultDecoders() shared between live engine and offline PCAP analysis) feed events to IDS, anomaly detection, signature matching, asset inventory, learn mode, and protocol statistics.
5) Services (syslog/NTP/DNS/proxy/VPN/AV) are rendered and supervised by control-plane service managers; service events flow into unified telemetry.

## Observability and logging
- Structured logging uses zap with per-service service/facility tags; stdout is the primary sink for container runs, with optional JSON + file rotation (lumberjack; default 20MB / 5 backups / 7 days) under `/data/logs/` for on-appliance retention. Log level can be overridden via `CONTAIND_LOG_LEVEL` or `CONTAIND_LOG_LEVEL_<SERVICE>`; file sinks can be disabled with `CONTAIND_LOG_FILE=0`; all service loggers can target a remote syslog collector via `CONTAIND_LOG_SYSLOG_ADDR` + `CONTAIND_LOG_SYSLOG_PROTO`.
- Syslog forwarding is configured via the syslog service config; pipeline forwards unified events over UDP/TCP with JSON or RFC5424 output, basic retry/backoff, counters, and error surfacing.
- Unified event stream carries firewall/DPI/proxy/service/audit events; service managers emit metrics/events that feed UI sparklines and dashboards.

