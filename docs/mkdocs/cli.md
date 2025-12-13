# CLI Design

This document is rendered from `docs/mkdocs/`.

The CLI mirrors appliance-style workflows. Commands will call control-plane APIs/config store for configuration and show operations.

## Current skeleton

- Command registry in `pkg/cli` with stub commands:
  - `show version`
  - `help` / `show help` / `set help`
  - `show zones`
  - `show interfaces`
- Local diagnostics:
  - `show ip route` (Linux only)
  - `diag ping <host> [count]`
  - `diag traceroute <host> [max_hops]`
  - `diag capture <iface> [seconds] [file]` (Linux only; writes `.pcap`)
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
  - `set system ssh listen <addr>` (candidate)
  - `set system ssh allow-password <true|false>` (candidate)
  - `set system ssh authorized-keys-dir <dir>` (candidate)
  - `commit`
  - `commit confirmed [ttl_seconds]`
  - `confirm`
  - `rollback`
  - `export config`
  - `export config redacted` / `export config --redacted`
  - `import config <path>`
- Backed by the config store (uses `pkg/cp/config`); ready to wire into SSH/HTTP transports later.

## Auth (current)

Management APIs and the in-app CLI use short-lived JWT sessions stored in a cookie by default.

Environment variables (common):
- `CONTAIND_LAB_MODE=1` disables auth checks (lab/dev only).
- `CONTAIND_JWT_SECRET=<secret>` enables JWT signing/verification (required when not in lab mode).
- `CONTAIND_COOKIE_SECURE=1` forces the `Secure` flag on the auth cookie (use when serving over HTTPS).

Roles (current):
- `admin` (full access)
- `view` (read-only)

## SSH console (appliance-style)

`ngfw-mgmt` exposes an SSH console that runs the same CLI registry (admin-only).

Interactive commands:
- `menu` - setup + diagnostics menu (OPNsense-style)
- `wizard` - guided setup that writes to candidate config and optionally commits
- `diagnostics` / `diag` - diagnostics submenu

Notes:
- The SSH console is implemented without allocating a PTY; basic line editing/echo is handled internally.
- `diag capture` and `show ip route` require Linux (inside the container) and typically `CAP_NET_RAW`.

## Future

- Add `show running-config`, `set`/`delete` commands for interfaces/zones/rules.
- Integrate with embedded SSH server for appliance-style access.
- Add an interactive `wizard` command over SSH for initial provisioning.
- Hook command execution to HTTP client layer (or direct store) depending on deployment topology.
- Add service commands (syslog/NTP/DNS) as system services land.
- Add `show ip rule`, `set route`, and `set pbr` commands as routing/PBR support is surfaced via UI/CLI/API.
