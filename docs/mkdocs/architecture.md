# containd Architecture

This document is rendered from `docs/mkdocs/`.

This document tracks the high-level architecture for containd as it evolves.

## Planes
- **Data plane (`containd engine`)**: kernel-assisted enforcement (nftables/conntrack), capture, flow tracking, rule evaluator, DPI/IDS (selective).
- **Control plane (`pkg/cp`)**: config persistence (SQLite), services (syslog/DNS/NTP/DHCP/VPN/AV/proxies), policy compilation → rule snapshots/nftables sets, audit, identity (phased), embedded-daemon config generation.
- **Management plane (`containd mgmt` + UI + CLI)**: REST API (`api/http`), UI serving, CLI/SSH, config lifecycle (candidate/commit/commit-confirmed/rollback/export/import/backups), audit, dashboards.

## Integrated daemons (per `agents.md`)
The appliance optionally embeds Envoy (explicit forward proxy), Nginx (reverse proxy), Unbound (DNS), OpenNTPD (NTP), and ClamAV (AV/Freshclam). containd owns lifecycle, config generation, and normalizes events into a unified schema for UI/CLI. IT DPI/telemetry is implemented natively in Go decoders for current scope.

## Packaging
- Containers at repo root (`Dockerfile.mgmt`, `docker-compose.yml`). Single-container appliance by default; `containd` binary has `all|mgmt|engine` subcommands for split deployments.
- Host deployment to run `containd all` (or split commands); config DB default `data/config.db` (env `NGFW_CONFIG_DB`).

## Module boundaries (current)
- `api/http`: `/api/v1` health, config lifecycle (candidate/commit/commit-confirmed/rollback/export/import/backups), CRUD (zones/interfaces/rules/assets), services, audit, and telemetry endpoints.
- `pkg/cp/config`: config model + validation + SQLite store with candidate/running lifecycle and schema upgrades.
- `pkg/cp/services`: syslog/DNS/NTP/proxy/VPN/AV managers render configs; optional supervision of embedded daemons (Envoy/Nginx/Unbound/OpenNTPD/ClamAV) with validation + service events.
- `pkg/common/logging`: zap-based structured logger helper (stdout + optional rotation) plus legacy prefixed UTC helpers.
- `pkg/cli`: command registry with API-backed show/set/delete for config, commit/rollback, audit, services, and diagnostics.
- `pkg/dp/capture`: AF_PACKET capture worker (Linux) with interface validation; NFQUEUE steering planned.
- `pkg/dp/rules`: immutable rule snapshots and evaluator (zones/CIDRs/proto/port ranges; ICS/identity predicates matched when present).
- `pkg/dp/engine`: harness to start capture, swap/apply rule snapshots, evaluate contexts, and apply verdict-driven updates.
- `pkg/dp/enforce`: nftables compile/apply skeleton with dynamic block sets.
- `pkg/dp/dpi`: selective DPI framework and decoder manager; HTTP previews feed AV queue; ICS marker tags OT protocols for AV fail-open.
- `pkg/dp/ics`: ICS protocol decoders (Modbus/TCP).
- `pkg/dp/verdict`: verdict types/actions used by enforcement paths.
- IDS evaluation lives in `pkg/dp/ids`; eBPF remains optional and unimplemented.

## Flow of control (current/target)
1) Management plane receives config via API; persisted in SQLite with candidate/commit/commit-confirmed/rollback; audit records for config changes.
2) Control plane compiles policies to nftables rulesets/sets and DP rule snapshots; engine hot-swaps snapshots.
3) Kernel enforces fast path; selective capture feeds userspace for DPI/IDS; IPS/AV verdicts update nftables sets/conntrack (AV blocks flows on malware; ICS can be fail-open).
4) Services (syslog/NTP/DNS/proxy/VPN/AV) are rendered and supervised by control-plane service managers; service events flow into unified telemetry.

## Observability and logging
- Structured logging uses zap with per-service service/facility tags; stdout is the primary sink for container runs, with optional JSON + file rotation (lumberjack; default 20MB / 5 backups / 7 days) under `/data/logs/` for on-appliance retention. Log level can be overridden via `CONTAIND_LOG_LEVEL` or `CONTAIND_LOG_LEVEL_<SERVICE>`; file sinks can be disabled with `CONTAIND_LOG_FILE=0`; all service loggers can target a remote syslog collector via `CONTAIND_LOG_SYSLOG_ADDR` + `CONTAIND_LOG_SYSLOG_PROTO`.
- Syslog forwarding is configured via the syslog service config; pipeline forwards unified events over UDP/TCP with JSON or RFC5424 output, basic retry/backoff, counters, and error surfacing.
- Unified event stream carries firewall/DPI/proxy/service/audit events; service managers emit metrics/events and will wire counters to UI sparklines and dashboards.
- Future: add Prometheus endpoint, configurable retention/rotation defaults, and RFC5424-compliant forwarding with retries/backpressure aligned to syslog manager settings.

## Upcoming work
- Selective DPI steering (NFQUEUE/AF_PACKET), decision caching, and enforcement acceleration.
- Expand unified event schema + retention and add Prometheus metrics.
- Harden routing reconcile and DNAT validation; add richer policy predicates (ICS/identity/schedules).

Further details will be refined as the roadmap advances.
