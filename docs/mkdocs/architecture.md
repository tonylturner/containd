# containd Architecture

This document is rendered from `docs/mkdocs/`.

This document tracks the high-level architecture for containd as it evolves.

## Planes
- **Data plane (`containd engine`)**: kernel-assisted enforcement (nftables/conntrack), capture, flow tracking, rule evaluator, DPI/IDS (selective).
- **Control plane (`pkg/cp`)**: config persistence (SQLite), services (syslog/NTP/DNS/proxies), policy compilation → rule snapshots/nftables sets, audit, identity (placeholder), embedded-daemon config generation.
- **Management plane (`containd mgmt` + UI + CLI`)**: REST API (`api/http`), UI serving, CLI/SSH (planned), config lifecycle (candidate/commit/rollback/export/import), audit, dashboards.

## Integrated daemons (per `AGENTS.md`)
The appliance optionally embeds Envoy (explicit forward proxy), Nginx (reverse proxy), Unbound (DNS), and OpenNTPD (NTP). containd owns lifecycle, config generation, and normalizes events into a unified schema for UI/CLI. IT DPI/telemetry is implemented natively in Go decoders for current scope.

## Packaging
- Containers at repo root (`Dockerfile.engine`, `Dockerfile.mgmt`, `docker-compose.yml`). Single-container appliance by default; goal is single `containd` binary with subcommands.
- Host deployment to run `containd all` (or split commands); config DB default `data/config.db` (env `NGFW_CONFIG_DB`).

## Module boundaries (current)
- `api/http`: `/api/v1` health, config load/save/validate/export/import, CRUD (zones/interfaces/rules), syslog settings (more to add: objects/assets, policies, identity, audit, services).
- `pkg/cp/config`: config model + validation + SQLite store (candidate/commit/rollback not yet implemented).
- `pkg/cp/services`: syslog manager stub; NTP/DNS pending; audit/identity placeholders.
- `pkg/common/logging`: prefixed UTC loggers.
- `pkg/cli`: command registry with API-backed show/set/delete for zones/interfaces/rules; more to add (commit/rollback/audit).
- `pkg/dp/capture`: capture manager placeholder (NFQUEUE/AF_PACKET planned).
- `pkg/dp/rules`: immutable rule snapshots and evaluator (zones/CIDRs/proto/port ranges; ICS/identity placeholders).
- `pkg/dp/engine`: harness to start capture, swap/apply rule snapshots, evaluate contexts, and apply verdict-driven updates.
- `pkg/dp/enforce`: nftables compile/apply skeleton with dynamic block sets.
- `pkg/dp/dpi`: selective DPI framework and decoder manager.
- `pkg/dp/ics`: ICS protocol decoders (Modbus/TCP skeleton added).
- `pkg/dp/verdict`: verdict types/actions used by enforcement paths.
- Placeholders remain for `pkg/dp/ids` and `ebpf/`.

## Flow of control (current/target)
1) Management plane receives config via API; persisted in SQLite; candidate/commit/rollback model to be added; audit every change.
2) Control plane compiles policies to nftables rulesets/sets and DP rule snapshots; engine hot-swaps snapshots.
3) Kernel enforces fast path; selective capture feeds userspace for DPI/IDS; IPS verdicts update nftables sets/conntrack.
4) Services (syslog/NTP/DNS) managed via control-plane services package (syslog stub now).

## Upcoming work
- Implement capture/flow tracking and DPI/IDS integration.
- Expose CLI via SSH and wire UI to APIs.
- Add syslog forwarding, NTP/DNS services, and richer rule predicates (ICS, identity, schedules).

Further details will be refined as we implement each phase.
