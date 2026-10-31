# CLI

Use `containd cli` or the `configure` symlink inside the appliance to open the
interactive CLI and log in to management. The authenticated web console and
admin SSH console expose the same commands. For the starter's default SSH port:

```sh
ssh -p 2222 containd@localhost
```

When commands are piped to `containd cli`, it continues after command errors
and exits with status 1 if any command fails; interactive sessions retain
status 0 on exit.

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
  - `show syslog status` (event forwarding counters, then audit record forwarding: totals, backlog and, per forwarder, cursor, backlog, last send and last error)
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
  - `set system ssh shell-mode <appliance|linux>` (candidate; see [shell modes](#shell-modes))
  - `commit`
  - `commit confirmed [ttl_seconds]`
  - `confirm`
  - `rollback`
  - `export config`
  - `export config redacted` / `export config --redacted`
  - `import config <path>`
- Backed by the management API and config store; exposed via SSH and the in-app console.

Read-modify-write commands, such as NAT, proxy, interface and system edits,
require a successful read of the current candidate settings. If that read fails
or returns no data, the command reports an error and sends no write; it does not
substitute running settings or defaults. Unspecified fields are preserved.
Outbound quick start completes all configuration reads before staging its changes.

## Learner Evidence

PCAP analysis imports a dataset; it does not generate rules or change policy.
The same learner handles explicit live watches. Viewer commands only read data;
all collection, generation, review and staging commands require admin.

```text
analyze pcap <filename>
show learn datasets [--limit 200] [--cursor <cursor>]
show learn dataset <dataset-id>
show learn observations <dataset-id> [--limit 200] [--cursor <cursor>]
show learn watches
show learn watch <watch-id>
show learn counters
start learn watch [seconds]
stop learn watch <watch-id>
generate learn <sealed-dataset-id>
show learn suggestions --dataset <dataset-id>
show learn suggestion <suggestion-id>
review learn suggestion <id@revision> approve|reject [coordinates-approved]
apply learn suggestions <request-id> <id@revision> [more-selections...]
delete learn dataset <dataset-id>
```

Start defaults to one hour, with a maximum of 24 hours and only one active watch.
Stop seals the live dataset. Follow returned cursors for complete lists. Inspect
service authority, gaps, expiry, frozen proof, limitations and withheld counts
before reviewing. IEC 104 requires explicit admin review; wire-coordinate evidence
requires a deliberate `coordinates-approved` acknowledgement after NAT/scope review.
Use the revision returned by review when staging.

`apply learn suggestions` atomically stages only selected certified revisions as
monitor rules; it never commits. A conflict rejects the whole batch. Retry the
same request ID and ordered selections after uncertain completion, since the
candidate may already be staged. Review `show diff`, then `commit` or `commit
confirmed`. Monitor rules do not authorize traffic: enforcement requires a later
explicit candidate mode edit and commit. The old profile/bulk workflow is removed.
See [Learning](ics-dpi.md#learning) for protocol and evidence-retention limits.

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

## Web console connections

The in-app console first authenticates `POST /api/v1/cli/ws/ticket` with the
management cookie or a Bearer credential, then opens
`/api/v1/cli/ws?ticket=<ticket>`. The ticket POST enforces cookie-authenticated
origin restrictions. The upgrade uses only the ticket, without comparing
`Origin` and `Host`, so proxies can strip the published port from `Host`.
Session JWTs never belong in the WebSocket URL; `?token=` is not accepted.

Tickets expire after 30 seconds and are single-use, even if the connection
attempt fails. Each connection or reconnect needs a fresh ticket. Restarting
management discards outstanding tickets. Issuance has no global, identity or IP
count limit; users sharing a lab account are not rejected because of pending
ticket counts.
Expired entries are cleaned lazily on the next issuance or redemption.
For session-backed authentication, logout, session expiry or revocation before
upgrade invalidates the ticket. Lab-mode credentials remain session-less as
with other management requests. The issuer's identity and role must still
match. A cookie alone cannot open
the WebSocket. Management access logs redact ticket and token query values.
Reverse proxies should redact these values too, since a ticket is a temporary
credential until consumed.

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

### Shell modes

The SSH shell mode selects what an interactive SSH login opens:

- `appliance` (default): the containd CLI. Type `shell` or `bash` to open a
  Linux shell. Type `exit` in that shell to return to the CLI.
- `linux`: a Linux `bash` login shell with the image's tools, such as
  `tcpdump` and `nft`. Type `configure` or `containd cli` to open the containd
  CLI. Type `exit`, `shell` or `bash` in that CLI to return to the shell.

A command on the `ssh` command line, such as
`ssh -p 2222 containd@localhost show version`, runs as one CLI command in both
modes.

containd reads the mode once, when management starts. A non-empty
`CONTAIND_SSH_SHELL_MODE` takes precedence over the saved
`system.ssh.shellMode`: `linux` in any letter case selects the Linux shell,
and any other value the appliance CLI. The saved value accepts only
`appliance`, `linux` or empty, which means `appliance`.
`set system ssh shell-mode <appliance|linux>` stages it. Commit it, then
restart containd. The starter Compose file (`deploy/docker-compose.yml`)
always sets `CONTAIND_SSH_SHELL_MODE` (default `appliance`); to change the
mode there, set the variable in `.env` and run `docker compose up -d`.

`show system` shows the mode SSH runs as `ssh.shell_mode` and its source as
`ssh.shell_mode_source`: `environment (CONTAIND_SSH_SHELL_MODE)`, `config` or
`default`. When the saved value differs, `ssh.shell_mode_saved` shows it and
says whether the environment overrides it or it applies after a restart.
`show system ssh` also lists the mode and its source.

The Linux shell needs a PTY. Interactive `ssh` requests one by default;
`ssh -T` does not. Without a PTY, a `linux` mode login opens the appliance CLI
with a warning. There, `shell` and `bash` say that the Linux shell needs an
interactive session, and the CLI keeps running.

In a Linux shell opened over SSH, `configure` and `containd cli` act as the
SSH login: they ask for no password and have the login's role. The shell
holds no token or password. Its CLI reaches management through the SSH
server, over a socket that exists only while the shell runs
(`CONTAIND_SSH_API_SOCKET`). After the shell or the SSH connection ends, or
the login's session is revoked, `containd cli` stops with
`SSH login unavailable`.

Elsewhere, for example with `docker exec <container> containd cli`, the CLI
calls the listeners management bound, as the SSH console does. When it binds
them, management records them in `run/management.json` in the directory of
the configuration store (`CONTAIND_CONFIG_DB`, default `/data/config.db` in
the image), readable only by its own user. It removes the file when it stops.
The CLI calls the HTTP listener on `127.0.0.1` unless it redirects to HTTPS,
and otherwise the HTTPS listener, trusting only the certificate management
serves. It follows no redirect. It logs in as `CONTAIND_CLI_USER` with
`CONTAIND_CLI_PASSWORD`; both default to `containd`. Without the file, the
CLI stops with `management is not running`. The container health check
(`containd healthcheck`) uses the same file.

Direct CLI login does not prompt for MFA or a replacement password. It stops
with a specific message if the account needs MFA, a password change or MFA
enrollment. Use the web UI for enrollment, and the web console or SSH for an
MFA-enabled account. A required password change can be completed through the
web UI or SSH. Inside an authenticated SSH shell, `containd cli` continues to
use that SSH login rather than logging in again.

The SSH CLI, and `containd cli` in an SSH shell, stay authorized while the
connection is open. With a JWT secret, the login's session also ends after 4
hours; reconnect after that. Lab mode without a JWT secret has no session
and no such limit.
The `menu`, `wizard` and `diagnostics` commands exist only in the appliance
SSH CLI. There, `configure` opens the setup wizard, the same as `wizard`.

Access and lab caveats:

- Only admin accounts can log in over SSH. Every admin can open the Linux
  shell in both modes, in and outside lab mode.
- Outside lab mode, the [account checks](#account-checks-at-ssh-login) finish
  before the CLI or shell opens. Lab mode skips them.
- The shell runs as the containd process user. The starter Compose file runs
  containd as root with `NET_ADMIN` and `NET_RAW`. In the default `all` mode the
  engine runs in the same container. The shell can therefore change nftables,
  routes and files directly, without candidate validation or commit.
- containd audits SSH logins and appliance CLI commands. Management audits
  the changes `containd cli` makes from an SSH shell, as for any API client.
  Commands typed in the Linux shell itself are not audited.

Use `linux` mode only where every SSH admin can have root access to the
appliance container.

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
password changes are refused, skips its password step and continues. Outside
lab mode, the menu reset and the wizard's password step first ask for the
current password; a wrong one stops the step and is audited as denied.

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
`--function-code`, `--object-classes`, `--unit-id`, `--addresses`, `--read-only`,
`--write-only`, and `--mode`). The command creates a new rule; it does not update an existing ID.
For CIP, `--object-classes <classes>` accepts comma-separated class IDs from
0 through 65535 in decimal or `0x`-prefixed hex (for example `4,0x66`).
`show firewall ics-rules` includes these values in `OBJECT_CLASSES`.
For IEC 104 (`protocol` is `iec104`), use:

- `--type-ids <ids>` — comma-separated decimal TypeIDs from 1 through 255.
- `--classes <classes>` — comma-separated `monitor`, `control`, `system`, or `unknown`.
- `--ca <addresses>` — comma-separated decimal common addresses from 0 through 65534; 65535 is broadcast and is not a rule address.
- `--ioa <ranges>` — comma-separated decimal addresses or inclusive ranges, for example `0,65536-65567,16777215` (the 24-bit address space).
- `--read-only` — restrict the rule to read-only IEC traffic.
- `--direction <request|response>` — select the session half.
- `--mode <monitor|enforce>` — choose the rule's ICS mode.

Additional IEC 104 selectors:

- `--cot <values>` — causes 1–63; `--originators <values>` — addresses 0–255.
- `--negative <true|false>` and `--test <true|false>` — exact P/N and T flags, including explicit false.
- `--select-execute <select|execute>` — only omitted Type IDs or 45–50, 58–63.

DNP3 selectors are `--masters` and `--outstations` (0–65519), `--groups` and
`--variations` (0–255), and `--addresses` (closed point-index ranges,
0–4294967295; requires groups). Stations apply to application messages only.
CIP selectors are `--instances` and `--attributes` (0–65535), or `--tags`
(comma-separated symbolic paths, for example `Motor.Speed,Program:Main.Pump`).
Tags cannot combine with `--object-classes`, `--instances` or `--attributes`.
New numeric lists accept decimal or `0x` hex. Omit a flag for ANY; `0` remains
an explicit value. `--unit-id` is Modbus-only; CIP does not accept `--addresses`.
The show table includes every selector, distinguishing absent booleans from false.
See [predicate semantics](ics-dpi.md#object-station-and-target-matching) for
variation 0, unknown targets, tag limitations and whole-message matching.

Example: allow supported monitoring types 1 (single-point) and 30 (timestamped
single-point) in server responses for common address 1 and the selected IOAs:

```text
set firewall ics-rule allow-measurements ALLOW iec104 --type-ids 1,30 --classes monitor --ca 1 --ioa 65536-65567 --direction response --mode enforce
```

`show firewall ics-rules` displays these IEC fields alongside the existing
ICS predicate fields.
