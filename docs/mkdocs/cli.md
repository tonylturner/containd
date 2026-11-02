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

`commit`/`commit confirmed`/`rollback`/`confirm` without an argument first GET /config/candidate (not /diff) and send its revision: this guards only the gap inside the command and commits whatever candidate is current (Junos semantics). `show diff` prints the revision; `commit revision <token>` binds to a reviewed revision.

Every configuration edit sends the revision of the snapshot it modified.
Direct-intent commands (such as create and import) read the revision first in
the same command. A stale write (412) or missing precondition (428) reports an
error without retrying. Read the current configuration, review your intended
changes, then issue a new command. Outbound quick start composes from one
candidate snapshot and chains the revisions returned by its staged writes.

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
  - `show firewall rules` (configured order numbers and via-forward IDs)
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
  - `add firewall rule <id> <action> [src_zone] [dst_zone] [position]`
  - `move firewall rule <id> top|bottom|before <id>|after <id>`
  - `set firewall rule <id> --<field> <value> ...`
  - `set firewall ics-rule <id> --<field> <value> ...`
  - `add firewall ics-rule <id> <action> <protocol> [options...]`
  - `set firewall default <ALLOW|DENY>`
  - `delete firewall rule <id>`
  - `set nat on|off [egress <zone|default>] [sources <z1,z2|default>]`
  - `set outbound quickstart` (stages default route + SNAT + allow rule for LAN/MGMT → WAN)
  - `set port-forward add <id> <ingress_zone> <tcp|udp> <listen_port> <dest_ip[:dest_port]> [sources <cidr1,cidr2>] [desc <text>] [off] [no-allow]`
  - `set port-forward del <id>`
  - `set port-forward enable <id>` / `set port-forward disable <id>`
  - `set dataplane enforcement <on|off> [table] [iface...]`
  - `set system hostname <name>` (candidate)
  - `set system mgmt http listen <addr>` (candidate)
  - `set system mgmt listen <addr>` (alias for the HTTP listener command; both
    set `httpListenAddr` and clear the legacy `listenAddr` in the candidate)
  - `set system ssh listen <addr>` (candidate)
  - `set system ssh allow-password <true|false>` (candidate)
  - `set system ssh authorized-keys-dir <dir>` (candidate)
  - `set system ssh shell-mode <appliance|linux>` (candidate; see [shell modes](#shell-modes))
  - `commit` / `commit revision <token>`
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

### Focused service settings

Admin service setters read the candidate service, preserve unspecified fields,
and POST with that read's revision. They stage only: review `show diff`, then
commit separately. A failed read or stale revision stops the edit without retry.
API validation, including management-access protection, remains authoritative.

Scalar syntax is `set <prefix> <field> <value>`. Booleans accept `true|false`
or `on|off`; lists take one comma-separated argument, with `-` clearing the
list. Quote text containing spaces; use `''` for an empty text field. Numeric
zero selects the API's default where supported. All names below are CLI names,
not raw JSON keys.

| Prefix | Fields |
| --- | --- |
| `dns` | `enabled`, `listen-port`, `listen-zones`, `upstream-servers`, `cache-size-mb` |
| `ntp` | `enabled`, `servers`, `interval-seconds` |
| `dhcp` | `enabled`, `authoritative`, `listen-ifaces`, `lease-seconds`, `router`, `dns-servers`, `domain` |
| `syslog` | `batch-size` (records), `flush-every` (seconds) |
| `av` | `enabled`, `mode` (`clamav|icap`), `fail-policy` (`open|closed`), `max-size-bytes`, `timeout-sec`, `cache-ttl`, `http-download`, `http-upload` |
| `av clamav` | `socket-path`, `update-schedule` (positive duration, e.g. `4h`), `custom-defs-path`, `freshclam-enabled` |
| `av scan` | `download-mode` (`hold|stream_tail`), `ics-zones`, `ics-assets` |
| `vpn wireguard` | `enabled`, `interface`, `listen-port`, `listen-zone`, `listen-interfaces`, `address-cidr`, `private-key-file` |
| `vpn openvpn` | `enabled`, `mode` (`client|server`), `config-path`, `source` (`profile|client|server`; see below) |
| `vpn openvpn client` | `remote`, `port`, `proto` (`udp|tcp`), `username`, `password-file`, `ca-file`, `cert-file`, `key-file` |
| `vpn openvpn server` | `listen-port`, `proto` (`udp|tcp`), `listen-zone`, `listen-interfaces`, `tunnel-cidr`, `public-endpoint`, `push-dns`, `push-routes`, `client-to-client` |
| `proxy forward` | `allowed-clients`, `allowed-domains`, `upstream`, `log-requests` |
| `ids` | `enabled` |

`cache-ttl` accepts a non-negative duration such as `5m` and sends nanoseconds
without floating-point conversion. `0s` selects the native scanner's 10-minute
default; ICAP verdicts are never cached. Runtime quarantine (`backendDisabled`)
is not editable. Configure the single ICAP server with
`set av icap server <host:port> <true|false TLS> <service>`.

VPN `*-file` arguments read credential contents from the appliance process's
filesystem, not the browser's or SSH client's filesystem. Keep those files
private. File paths, not secret contents, enter command history and audit
records; save output does not print response bodies or saved secrets. Existing
redacted VPN secrets are retained by the API when other fields change.
For a new OpenVPN configuration, stage `enabled false`, choose `source`, fill
the settings and credentials, then stage `enabled true`. Changing `source`
explicitly removes the other sources: `profile` removes structured client and
server settings, `client` removes the server and profile path, and `server`
removes the managed client and profile path. The selected source's existing
settings are retained. A profile path must already exist on the appliance;
setting a path does not upload a file.

The forward proxy API currently rejects nonempty `allowedClients` and
`upstream`; these setters can clear them (`allowed-clients -`, `upstream ''`)
but do not add runtime support or bypass that refusal. Existing
`set proxy forward on|off [port] [zone...]` and `set proxy reverse on|off`
commands remain available.

Collections use separate `add`, `set` and `delete` commands. Add refuses an
existing key; set and delete refuse missing or ambiguous keys. Set requires at
least one `--field value` pair and changes only those fields. Delete stages
removal; it does not immediately change the running service.

| Collection | Key after command | Add requirements | Optional/set fields |
| --- | --- | --- | --- |
| `dhcp pool` | `<iface> <start-ip>` | `--end <ip>` | `--end` |
| `dhcp reservation` | `<iface> <mac>` | `--ip <ip>` | `--ip` |
| `vpn wireguard peer` | `<public-key>` | `--allowed-ips <cidrs>` | `--name`, `--allowed-ips`, `--endpoint`, `--persistent-keepalive` |
| `proxy reverse site` | `<name>` | `--listen-port <port> --backends <host:port,...>` | `--listen-port`, `--hostnames`, `--backends`, `--tls-enabled`, `--cert-ref`, `--description` |
| `ids group` | `<id>` | `--name <text>` | `--name`, `--description`, `--filter`, `--enabled` |
| `av scan include` | No key on add; `<index>` on set/delete | `--dest-ports <ports-or-ranges>` | `--source-zones`, `--dest-zones`, `--dest-ports` |
| `av scan exclude` | No key on add; `<index>` on set/delete | At least one nonempty selector (API-validated) | `--source-zones`, `--dest-zones`, `--sources`, `--destinations`, `--dest-ports` |

DHCP supports several pools per interface; changing a pool's start address or
another collection's key means deleting and adding it. MAC keys are normalized.
Scan indices are one-based positions in the current candidate selection; inspect
`show candidate-config` before using them. Include/exclude selectors accept the
same comma-separated lists and `-` clearing syntax as scalar list settings.
A reverse site's TLS `cert-ref` names an existing appliance proxy certificate
pair; it does not upload certificates. New IDS groups default to enabled;
`ruleCount` is computed, not an editable field. To toggle a single existing IDS
rule without altering its predicates, use
`set ids rule enabled <id> <true|false>`.

```text
set dns upstream-servers 1.1.1.1,9.9.9.9
add dhcp pool lan 10.0.0.20 --end 10.0.0.100
add dhcp reservation lan aa:bb:cc:dd:ee:ff --ip 10.0.0.25
set av cache-ttl 5m
add av scan include --source-zones lan --dest-zones wan --dest-ports 80,8080-8090
add vpn wireguard peer PUBLIC_KEY --allowed-ips 10.8.0.2/32 --persistent-keepalive 25
set proxy reverse site portal --tls-enabled true --cert-ref portal
set syslog batch-size 100
set ids rule enabled modbus-write-attempt false
add ids group plant --name 'Plant rules' --filter 'proto:modbus'
show diff
```

### Rule positions and port forwards

For `add firewall rule`, the optional position suffix is `top`, `bottom`,
`before <id>` or `after <id>`; omitted means `bottom`. `set firewall rule`
edits an existing ID with field flags; it never creates a rule. `move firewall rule`
repositions an existing rule without changing its predicates. Unknown anchors and moving a rule
relative to itself are rejected. Changes are staged until commit.

```text
add firewall rule maintenance ALLOW ops plant before deny-plant
move firewall rule deny-plant bottom
set port-forward add plc wan tcp 1502 10.30.30.10:502 no-allow
set port-forward del plc
```

Port-forward add atomically stages the forward and, by default, requests a
matching explicit allow rule. DNAT alone does not authorize traffic.
The output reports `Inserted rule <id> at position <n>.`
for `generated`, or `Placement: <reason>; governing rules: <ids>` for `inside`
or `partial`. Partial/unknown overlap prints a warning and generates no grant;
existing policy decides delivery. A trailing `no-allow` stages translation
only and prints `No allow rule requested.` See
[placement reasons](policy-model.md#port-forward-publication-and-deletion).

Port-forward del atomically removes the forward's references, deleting rules
whose `viaForwards` list becomes empty and editing those that retain other IDs.
It prints `Deleted rules: <ids>` and `Edited rules: <ids>` (an em dash for an
empty list). Add and del both print the staged-change reminder; commit to apply.

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

## Account, backup and runtime operations

These operations do **not** stage configuration or require `commit`. Every
mutation below requires the final, case-sensitive `CONFIRM` argument and prints
an immediate-operation notice. Inspect the response: a request being accepted
is not proof that runtime protection, capture or revocation has converged.
Errors retain the API's fault details, including durable OpenVPN revocation
whose runtime installation is not confirmed.

Account and credential commands (admin only):

- `show users`
- `delete user <id> CONFIRM` — subject to the API's last-admin protection.
- `require mfa user <id> CONFIRM` — applies the API's enrollment grace period.
- `show openvpn clients`
- `issue openvpn client <name> CONFIRM` — returns credential metadata, not a profile.
- `download openvpn client <id> <new-file>` — saves the private profile to a file.
- `revoke openvpn client <id> CONFIRM`

Passwords are not command arguments. Account creation and password reset remain
available through System → Users; the SSH menu can change the current account's
password. There is no account disable/enable API; MFA disable is not account disable.

Appliance configuration backups:

- `show backups`
- `create backup <name> <redacted|full> CONFIRM` (admin)
- `download backup <id> <new-file>`
- `delete backup <id> CONFIRM` (admin)

Downloads create a new file with mode `0600`, refuse to overwrite an existing
file, and never print its contents. Views can only list/download redacted
backups, as enforced by the API. Full backups and OpenVPN profiles contain
secrets: keep the files private. Configuration backups do not include the users,
audit or evidence databases.

Runtime inspection and actions:

- `show protection` — includes the current boot/apply IDs and fault causes.
- `retry protection <boot-id> <apply-id> CONFIRM` (admin) — use IDs from the
  inspected status; stale requests fail rather than silently retrying another apply.
- `update av definitions CONFIRM` (admin) — starts an immediate definition update.
- `show pcap status`
- `start pcap CONFIRM` / `stop pcap CONFIRM` (admin) — use the committed collector
  settings; these do not edit capture configuration.
- `revoke connection <connection|client-service> <duration-seconds> <tcp|udp> <src> <dst> <sport> <dport> CONFIRM` (admin)
- `revoke connection <connection|client-service> <duration-seconds> <icmp|icmpv6> <src> <dst> <id> <type> <code> CONFIRM` (admin)

Connection revocation uses the original tuple shown by `show conntrack`.
`client-service` covers the selected client/service rather than only that tuple.
The API validates durations, protocols and addresses and reports connection
removal separately from revocation installation.

`export config [redacted|--redacted]` retains the default redacted export.
`export config full` explicitly requests an **unredacted, admin-only** export.
Its output is JSON and can contain secrets; do not paste it into logs or public
support requests. `import config <path>` sends the file bytes unchanged to the
API's strict import decoder, with the current candidate revision. Unknown,
duplicate and incorrectly cased root keys are rejected without changing the
candidate. A successful import is staged only; review the diff before committing.

## Authentication

Management APIs and the in-app CLI use short-lived JWT sessions stored in a cookie by default.

Environment variables (common):
- `CONTAIND_LAB_MODE=1` refuses every password change, including the SSH menu
  reset and the wizard's password step. It keeps existing and custom-seeded
  credentials; a freshly seeded lab uses `containd/containd`. Protected API
  routes still require a bearer token or cookie.
  With a JWT secret, the token must be HS256-signed and carry `exp`; signature
  and expiry are validated with 30 seconds of leeway, without a session lookup. Without a secret, **any nonempty token passes**. Factory reset
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
- The appliance CLI handles basic line editing and echo internally and can run
  without a PTY. The Linux shell requires a PTY.
- `diag capture` requires Linux (inside the container) and typically
  `CAP_NET_RAW`. `show ip route` requires Linux but not raw-packet access.
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
serves, using the public-leaf snapshot in the runtime record; no private key is
recorded. The record follows valid [management TLS rotations](config-format.md#management-https-identity),
including retention of the last-good identity after an invalid external rotation.
It follows no redirect. It logs in as `CONTAIND_CLI_USER` with
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

`add firewall ics-rule <id> <action> <protocol> [options...]` accepts the
existing zone and Modbus/CIP-style flags (`--src-zone`, `--dst-zone`,
`--function-code`, `--object-classes`, `--unit-id`, `--addresses`, `--read-only`,
`--write-only`, and `--mode`). The command creates a new rule; use
`set firewall ics-rule <id> --<field> <value> ...` to edit an existing ID.
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
add firewall ics-rule allow-measurements ALLOW iec104 --type-ids 1,30 --classes monitor --ca 1 --ioa 65536-65567 --direction response --mode enforce
```

`show firewall ics-rules` displays these IEC fields alongside the existing
ICS predicate fields.

## Focused policy edits

`set firewall rule <id> --<field> <value> ...` updates only supplied fields;
omitted fields and rule order are preserved. A missing ID is an error, not a
request to create. `add firewall rule` and `add firewall ics-rule` create rules.
The old create-only `set` syntax is not accepted.

| Flag | Value |
| --- | --- |
| `--action` | `ALLOW`, `DENY`, `RESET`, `RATE_LIMIT`, or `TAG` |
| `--source-zones`, `--dest-zones` | Comma-separated zone names; `--src-zone` and `--dst-zone` also accept lists |
| `--sources`, `--destinations` | Comma-separated addresses/CIDRs or supported VPN selectors |
| `--protocols` | Comma-separated `name[:port-or-range]`, e.g. `tcp:502,udp:1000-2000,icmp` |
| `--identities`, `--via-forwards` | Comma-separated identity names or port-forward IDs |
| `--log` | `true` or `false` |
| `--rate-limit` | Packets per second, optionally `pps:burst`; `none` removes the limit |
| `--tag`, `--description` | Text; quote spaces |
| `--schedule-days` | Comma-separated weekdays |
| `--schedule-start`, `--schedule-end` | `HH:MM` |
| `--schedule-timezone` | IANA timezone |
| `--schedule` | `none` removes the schedule |

An empty quoted list (`''`) clears that list. A schedule flag changes only its
specified subfield. A rate-limit value replaces both rate and burst (omitted
burst is 0, meaning the packet rate). The API validates the complete resulting
policy, including action parameters and management reservation.

`set firewall ics-rule` accepts all these flags plus the ICS selectors in the
preceding section. Use `--ics-protocol <modbus|dnp3|cip|iec104>` to change protocol;
a protocol change replaces the old predicate, so supply its new selectors in
the same command. Each selector takes a value: for edits, use `--read-only
true|false` and `--write-only true|false`, not creation's bare switches.
An empty quoted selector value clears it; omission preserves it. Clearing
`--mode ''` restores inheritance from the global DPI mode.

```text
set firewall rule maintenance --source-zones ops,lan --protocols tcp:502,tcp:20000 --log true
set firewall ics-rule allow-measurements --type-ids 1,30 --read-only false --description 'Monitoring only'
set firewall default DENY
```

`set firewall default <ALLOW|DENY>` stages the unmatched-traffic action and warns
about its reachability impact. Review the diff and use commit-confirmed when
changing access policy. It does not turn enforcement on or report runtime
protection as active.

### DPI and capture groups

- `set dataplane dpi enabled <on|off>` changes the DPI master toggle, not enforcement.
- `set dataplane dpi mode <monitor|enforce>` changes the global ICS mode.
- `set dataplane dpi protocols <name=bool,...>` edits named IT protocol toggles.
- `set dataplane dpi ics-protocols <name=bool,...>` edits named ICS protocol toggles.
- `set dataplane dpi ics-parsing <name=strict|tolerant,...>` edits named ICS parsing modes.
- `set dataplane dpi exclusions <type:value,...> [reason]` replaces the exclusion
  list; types are `ip`, `cidr`, and `domain`. IPv6 colons are supported. The optional
  quoted reason applies to every supplied exclusion.
- `set dataplane nfqueue-group <0..65535>` and `set dataplane nflog-group <0..65535>`
  change the respective capture groups; 0 disables that consumer, subject to
  configuration safety validation.

For maps, unnamed entries stay unchanged; `''` clears the entire map, restoring
its defaults. For exclusions, `''` clears the list. Other dataplane settings are
preserved, including capture interfaces, enforcement and the table name.

### Policy metadata and ICS templates

- `set zone consequence <name> <text>` edits zone consequence; `''` clears it.
- `set asset hostnames <id> <hostname,...>` replaces hostnames on an existing
  asset; `''` clears them. Other asset fields are preserved.
- `show templates ics` lists the ICS catalog, descriptions and required parameters.
- `preview template ics <name> [--source-zones <csv>] [--dest-zones <csv>]
  [--ranges <csv>] [--mode <monitor|enforce>]` prints generated rules without
  staging anything. This API operation requires administrator access even for preview.
- `apply template ics <name>` accepts the same options and stages the generated
  rules. Templates can update matching rule IDs; preview first and inspect the diff.

These commands use `/templates/ics`, a different catalog from `show templates`
and `apply template`. Register-guard templates take `--ranges 0-99,400-499`.
Omitting `--mode` lets generated rules inherit the global ICS mode.

Every edit above stages candidate configuration with the revision read in the
same invocation. Nothing auto-commits or applies. A stale revision fails visibly
without retrying; reload and review before issuing the command again.
