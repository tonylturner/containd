# CLI Design

The CLI mirrors appliance-style workflows. Commands will call control-plane APIs/config store for configuration and show operations.

## Current CLI

- Command registry in `pkg/cli` with appliance-style commands:
  - `show version`
  - `help` / `show help` / `set help`
  - `show zones`
  - `show interfaces`
- Local diagnostics:
  - `show ip route` (Linux only)
  - `show ip rule` (Linux only)
  - `show neighbors` (Linux only; IPv4 ARP for now)
  - `diag ping <host> [count]`
  - `diag traceroute <host> [max_hops]`
  - `diag reach <src_iface> <dst_host|dst_ip|dst_iface> [tcp_port]` (legacy; TCP)
  - `diag reach <src_iface> <dst> <tcp|udp|icmp> [port]` (when `dst` is an interface name and `port` is omitted, containd runs a safe self-test for TCP/UDP)
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
  - `show routing`
  - `show nat`
  - `show port-forwards` (DNAT config)
  - `show conntrack [limit]` (kernel conntrack via engine; may be unavailable depending on runtime)
  - `show sessions [limit]` (alias of `show conntrack`)
  - `diag routing reconcile REPLACE`
  - `show ids rules`
  - `show audit`
  - `show dataplane`
  - `show zones` / `show interfaces` (HTTP GET if API provided)
- Mutating commands (API):
  - `set zone <name> [description]`
  - `set interface <name> <zone> [cidr...]`
  - `set interface bridge <name> <zone> <members_csv> [cidr...]`
  - `set interface vlan <name> <zone> <parent> <vlan_id> [cidr...]`
  - `set interface ip <name> dhcp`
  - `set interface ip <name> static <cidr> [gateway]`
  - `set interface bind <name> <os_iface>`
  - `set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]` (gateway can be an IP or a gateway name)
  - `set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]`
  - `set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]`
  - `set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all`
  - `set firewall rule <id> <action> [src_zone] [dst_zone]`
  - `delete firewall rule <id>`
  - `set nat on|off [egress <zone|default>] [sources <z1,z2|default>]`
  - `set outbound quickstart` (enables default route + SNAT + allow rule for LAN/MGMT → WAN)
  - `set port-forward add <id> <ingress_zone> <tcp|udp> <listen_port> <dest_ip[:dest_port]> [sources <cidr1,cidr2>] [desc <text>] [off]`
  - `set port-forward del <id>`
  - `set port-forward enable <id>` / `set port-forward disable <id>`
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
- Backed by the management API and config store; exposed via SSH and the in-app console.

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

`containd mgmt` exposes an SSH console that runs the same CLI registry (admin-only).

Interactive commands:
- `menu` - setup + diagnostics menu (OPNsense-style)
- `wizard` - guided setup that writes to candidate config and optionally commits
- `diagnostics` / `diag` - diagnostics submenu

Notes:
- The SSH console is implemented without allocating a PTY; basic line editing/echo is handled internally.
- `diag capture` and `show ip route` require Linux (inside the container) and typically `CAP_NET_RAW`.
- The `wizard` includes an optional step to run `set outbound quickstart` (equivalent to the UI "Quick start (LAN→WAN)").

## Roadmap

- SSH banners and host key rotation tooling.
- Richer neighbor and routing views in operational commands.
