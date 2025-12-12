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

## Proxies

- Config model: `services.proxy.forward` (Envoy explicit forward proxy) and `services.proxy.reverse.sites[]` (Nginx published services).
- API:
  - `GET/POST /api/v1/services/proxy/forward`
  - `GET/POST /api/v1/services/proxy/reverse`
- CLI:
  - `show proxy forward|reverse`
  - `set proxy forward <on|off> [port] [zone...]`
  - `set proxy reverse <on|off>`
- On commit/rollback, `ngfw-mgmt` renders daemon configs to the services directory (`CONTAIND_SERVICES_DIR` or `/var/lib/containd/services`): `envoy-forward.yaml` and `nginx-reverse.conf`.
- `pkg/cp/services/proxy` includes an **optional supervision stub** that starts/stops Envoy/Nginx if binaries are present. It validates the generated Nginx config with `nginx -t` before restart, tracks last start/error timestamps, and exposes a richer `/api/v1/services/status` view consumed by `show services status`.

## Auth/SSH (future)
- Identity placeholders live in `pkg/cp/identity` (users, devices, sessions).
- CLI API wrapper supports bearer tokens; full auth/RBAC to be implemented.
- SSH server integration planned for Phase 4 to expose the CLI.
