# System Services

Tracks syslog, NTP, and DNS service configuration and status handling managed by `ngfw-mgmt`.

## Syslog

- Config model: `services.syslog.forwarders[]` with `address`, `port`, `proto` (udp|tcp).
- API (initial):
  - `GET /api/v1/config` (includes services.syslog)
  - `POST /api/v1/config` to update full config
  - `/api/v1/services/syslog` get/set endpoints.
- Service manager stub in `pkg/cp/services/syslog` for applying syslog config; `Run` placeholder and UDP forwarder skeleton present (no real event piping yet).
- Forwarders are validated for port range and protocol.

## Auth/SSH (future)
- Identity placeholders live in `pkg/cp/identity` (users, devices, sessions).
- CLI API wrapper supports bearer tokens; full auth/RBAC to be implemented.
- SSH server integration planned for Phase 4 to expose the CLI.
