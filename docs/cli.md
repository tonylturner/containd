# CLI Design

The CLI mirrors appliance-style workflows. Commands will call control-plane APIs/config store for configuration and show operations.

## Current skeleton

- Command registry in `pkg/cli` with stub commands:
  - `show version`
  - `help` / `show help` / `set help`
  - `show zones`
  - `show interfaces`
- API-backed commands:
  - `show health`
  - `show config`
  - `show running-config`
  - `show running-config redacted`
  - `show candidate-config`
  - `show diff`
  - `show system`
  - `show services status`
  - `show ids rules`
  - `show audit`
  - `show dataplane`
  - `show zones` / `show interfaces` (HTTP GET if API provided)
- Mutating commands (API):
  - `set zone <name> [description]`
  - `set interface <name> <zone> [cidr...]`
  - `set firewall rule <id> <action> [src_zone] [dst_zone]`
  - `delete firewall rule <id>`
  - `set dataplane enforcement <on|off> [table] [iface...]`
  - `set system hostname <name>` (candidate)
  - `set system mgmt listen <addr>` (candidate)
  - `commit`
  - `commit confirmed [ttl_seconds]`
  - `confirm`
  - `rollback`
  - `export config`
  - `export config redacted` / `export config --redacted`
  - `import config <path>`
- Backed by the config store (uses `pkg/cp/config`); ready to wire into SSH/HTTP transports later.

## Auth (current)

Management APIs and the in-app CLI require bearer-token auth by default.

Environment variables:
- `CONTAIND_LAB_MODE=1` disables auth checks (lab/dev only).
- `CONTAIND_ADMIN_TOKEN=<secret>` enables full access.
- `CONTAIND_AUDITOR_TOKEN=<secret>` enables read-only access.

When not in lab mode, at least one token must be set or the API will return `503` with an auth configuration error.

## Future

- Add `show running-config`, `set`/`delete` commands for interfaces/zones/rules.
- Integrate with embedded SSH server for appliance-style access.
- Hook command execution to HTTP client layer (or direct store) depending on deployment topology.
- Add service commands (syslog/NTP/DNS) as system services land.
