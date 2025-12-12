# CLI Design

The CLI mirrors appliance-style workflows. Commands will call control-plane APIs/config store for configuration and show operations.

## Current skeleton

- Command registry in `pkg/cli` with stub commands:
  - `show version`
  - `show zones`
  - `show interfaces`
- API-backed commands:
  - `show health`
  - `show config`
  - `show zones` / `show interfaces` (HTTP GET if API provided)
- Mutating commands (API):
  - `set zone <name> [description]`
  - `set interface <name> <zone> [cidr...]`
  - `set firewall rule <id> <action> [src_zone] [dst_zone]`
  - `delete firewall rule <id>`
- Backed by the config store (uses `pkg/cp/config`); ready to wire into SSH/HTTP transports later.

## Future

- Add `show running-config`, `set`/`delete` commands for interfaces/zones/rules.
- Integrate with embedded SSH server for appliance-style access.
- Hook command execution to HTTP client layer (or direct store) depending on deployment topology.
- Add service commands (syslog/NTP/DNS) as system services land.
