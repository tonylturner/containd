# CLI

Use `containd cli` or the `configure` symlink inside the appliance to open the
interactive CLI and log in to management. The authenticated web console and
admin SSH console expose the same commands. For the starter's default SSH port:

```sh
ssh -p 2222 containd@localhost
```

Use `help`, `show help`, or `set help` to discover commands. Configuration
commands stage candidate edits: review `show diff`, then `commit` or
`commit confirmed [ttl_seconds]`. Use `confirm` to retain a confirmed commit and
`rollback` to restore the previous running configuration. Listener changes can
require a restart; committing does not rebind management sockets.

## Command reference

- Inspection and help:
  - `show version`
  - `help` / `show help` / `set help`
  - `show zones`
  - `show interfaces`
- Local diagnostics:
  - `show ip route` (Linux only)
  - `show ip rule` (Linux only)
  - `show neighbors` (Linux only; IPv4 ARP)
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
  - `set firewall ics-rule <id> <action> <protocol> [options...]`
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

## Authentication

Management APIs and the in-app CLI use short-lived JWT sessions stored in a cookie by default.

Environment variables (common):
- `CONTAIND_LAB_MODE=1` pins the lab credential to `containd/containd` and refuses
  every password change, including the SSH menu reset and the wizard's password
  step. Protected API routes still require a bearer token or cookie.
  With a JWT secret, the token's signature and expiry are validated without a
  session lookup. Without a secret, **any nonempty token passes**. Factory reset
  does not revoke lab web/API tokens in either case. Lab requests receive admin
  access rather than ordinary role enforcement. Use only in isolated, disposable environments; see
  [default-password and lab-mode limits](secure-by-design.md#2-default-passwords).
- `CONTAIND_JWT_SECRET=<secret>` enables JWT signing/verification. Compose requires
  a non-empty value even for labs; follow [onboarding](docker-compose.md#quickstart).
- `CONTAIND_COOKIE_SECURE=1` forces the `Secure` flag on the auth cookie (use when serving over HTTPS).

Roles:
- `admin` (full access)
- `view` (read-only)

## SSH console (appliance-style)

`containd mgmt` exposes an SSH console that runs the same CLI registry (admin-only).

Interactive commands:
- `menu` - setup + diagnostics menu (OPNsense-style)
- `wizard` - guided setup that writes to candidate config and optionally commits
- `diagnostics` / `diag` - diagnostics submenu

The menu's factory reset requires `NUCLEAR`. If the management API rejects the
reset or cannot be reached, the console displays the error and keeps the menu
open; it does not report completion. See [factory reset](api-reference.md#factory-reset)
for configuration recovery and credential-reset behavior.
An applied reset with warnings shows incomplete convergence and the warnings,
not a completion claim. The initiating appliance console disconnects after
printing its result; other SSH connections, including Linux shells, are closed.

Notes:
- The SSH console is implemented without allocating a PTY; basic line editing/echo is handled internally.
- `diag capture` and `show ip route` require Linux (inside the container) and typically `CAP_NET_RAW`.
- The `wizard` includes an optional step to run `set outbound quickstart` (equivalent to the UI "Quick start (LAN→WAN)").

### SSH authentication and host keys

`set system ssh allow-password false` stages an authoritative password disable,
including in lab mode. Staging and commit both refuse this setting unless an
existing admin has a usable public key in the effective authorized-keys directory.
Enroll and test an admin key before disabling passwords. Keys for view-only or
unknown users, empty files and malformed keys do not satisfy this check.
HTTP management authentication is unchanged.

When `allowPassword` is omitted or null, passwords are allowed in lab mode or
when the authorized-keys directory is empty or cannot be read. `show system`
and `show mgmt listeners` display this saved policy as `auto (bootstrap/lab)`;
explicit values display `yes` or `no`. `show system ssh` reports the effective
password policy and its source from the appliance, including any
`CONTAIND_SSH_ALLOW_PASSWORD` override. An explicit saved `false` takes precedence
over that environment variable; otherwise the environment override still applies.
`CONTAIND_SSH_AUTH_KEYS_DIR` selects the
effective keys directory ahead of the saved `authorizedKeysDir` setting.

Committed password and authorized-keys-directory changes apply to new logins.
Existing sessions remain open. If keys later disappear, passwords stay disabled;
restore the keys or change the SSH policy through HTTP management. A wizard
password change writes the user store immediately, rather than waiting for a
config commit. A rejected password or store error stops the wizard and is not
reported or audited as a successful change. In lab mode the wizard prints why
password changes are refused, skips its password step and continues.

`set system ssh host-key-rotation <days>` accepts 0 (disabled) through 36500.
The server checks host-key age at startup and every minute while running.
Committed rotation-setting changes take effect at the next check, without a
restart. At the age boundary the server atomically publishes a new host key for
new connections; existing sessions are unaffected. Rotation errors retain the
active key and are logged. Clients with a pinned host key must verify the new
fingerprint through a trusted channel before updating their known-hosts entry.

### Account checks at SSH login

Outside lab mode, SSH applies the web login's account checks after the password
or key:

- An account marked for a password change, such as the bootstrap `containd`
  admin, must change it before the CLI, menu or shell opens. SSH asks for the new
  password twice without echo and applies the web password rules; the new
  password must differ from the current one. A key login also asks for the
  current password. The change is audited.
- A password login of an account with TOTP MFA asks for an authentication code.
  A wrong code counts against the login rate limit, which is per client address
  and account. A key login does not ask: the key is the possession factor.
- An account whose required MFA enrollment grace period has ended cannot log in
  over SSH. The server's banner says to enroll through the web UI.

These steps use keyboard-interactive authentication, which OpenSSH enables by
default. Clients limited to the `password` method, such as `sshpass`, cannot
complete them.

A password or MFA change from the web UI, the API or the SSH menu ends the
account's other sessions and closes their SSH connections, including Linux
shells. The session or SSH connection that made the change stays open. Deleting
an account also closes its SSH connections.

Lab mode (`CONTAIND_LAB_MODE=1`) skips these checks. Password login with
`containd` / `containd` opens the CLI directly, and an MFA change or account
deletion leaves SSH connections open.

## ICS firewall rules

`set firewall ics-rule <id> <action> <protocol> [options...]` accepts the
existing zone and Modbus/CIP-style flags (`--src-zone`, `--dst-zone`,
`--function-code`, `--unit-id`, `--addresses`, `--read-only`, `--write-only`,
and `--mode`). For IEC 104 (`protocol` is `iec104`), use:

- `--type-ids <ids>` — comma-separated decimal TypeIDs from 1 through 255.
- `--classes <classes>` — comma-separated `monitor`, `control`, `system`, or `unknown`.
- `--ca <addresses>` — comma-separated decimal common addresses from 0 through 65534; 65535 is broadcast and is not a rule address.
- `--ioa <ranges>` — comma-separated decimal addresses or inclusive ranges, for example `0,65536-65567,16777215` (the 24-bit address space).
- `--read-only` — restrict the rule to read-only IEC traffic.
- `--direction <request|response>` — select the session half.
- `--mode <learn|enforce>` — choose the rule's ICS mode.

Example: allow supported monitoring types 1 (single-point) and 30 (timestamped
single-point) in server responses for common address 1 and the selected IOAs:

```text
set firewall ics-rule allow-measurements ALLOW iec104 --type-ids 1,30 --classes monitor --ca 1 --ioa 65536-65567 --direction response --mode enforce
```

`show firewall ics-rules` displays these IEC fields alongside the existing
ICS predicate fields.
