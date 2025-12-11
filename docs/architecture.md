# containd Architecture

This document tracks the high-level architecture for containd as it evolves.

## Planes
- **Data plane (`ngfw-engine`)**: capture, flow tracking, rule enforcement, DPI/IDS.
- **Control plane (`pkg/cp`)**: config persistence (SQLite), services (syslog, NTP/DNS later), policy compilation → rule snapshots.
- **Management plane (`ngfw-mgmt` + UI + CLI`)**: REST API (`api/http`), UI serving, CLI/SSH (planned), config import/export.

## Packaging
- Containers at repo root (`Dockerfile.engine`, `Dockerfile.mgmt`, `docker-compose.yml`). Single-container appliance by default.
- Host deployment to run `ngfw-mgmt`/`ngfw-engine` as services; config DB default `data/config.db` (env `NGFW_CONFIG_DB`).

## Module boundaries (current)
- `api/http`: `/api/v1` health, config load/save/validate/export/import, CRUD (zones/interfaces/rules), syslog settings.
- `pkg/cp/config`: config model + validation + SQLite store.
- `pkg/cp/services`: syslog manager stub (forwarding pending).
- `pkg/common/logging`: prefixed UTC loggers.
- `pkg/cli`: command registry with initial `show` commands (to be exposed via SSH/HTTP).
- `pkg/dp/capture`: capture manager placeholder.
- `pkg/dp/rules`: immutable rule snapshots and evaluator (zones/CIDRs/proto/port, ranges).
- `pkg/dp/engine`: harness to start capture, swap rule snapshots, evaluate contexts.

## Flow of control (current)
1) Management plane receives config via API; persisted in SQLite (`pkg/cp/config`).
2) Engine loads compiled rule snapshot (future: control-plane compiler) and hot-swaps pointer.
3) Capture workers (stub) feed flows → rule evaluator → actions (allow/deny; future: reset/mirror/tag/rate-limit).
4) Services (syslog/NTP/DNS) managed via control-plane services package (syslog stub now).

## Upcoming work
- Implement capture/flow tracking and DPI/IDS integration.
- Expose CLI via SSH and wire UI to APIs.
- Add syslog forwarding, NTP/DNS services, and richer rule predicates (ICS, identity, schedules).

Further details will be refined as we implement each phase.
