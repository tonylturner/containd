# System Services

Configure services through the UI or management API. Saving stages candidate
configuration; review the diff and commit to apply it. Rollback reapplies the
previous running configuration. See [Config Format](config-format.md#configuration-lifecycle)
for the lifecycle and [API Reference](api-reference.md) for endpoint details.

`containd mgmt` configures services and supervises DNS, NTP, OpenVPN, proxies,
and optional AV daemons. The engine owns the DHCP server and kernel WireGuard
interfaces. In split deployments these run in the engine's network namespace;
management and engine need the intended network reachability and privileges.
Check runtime status after commit, not just whether saving succeeded.

## Syslog

- Config model: `services.syslog.forwarders[]` with `address`, `port`, `proto` (udp|tcp).
- API:
  - `GET /api/v1/config` (includes services.syslog)
  - `POST /api/v1/config` to update full config
  - `/api/v1/services/syslog` get/set endpoints.
- Forwards unified events over UDP/TCP with RFC5424 or JSON formatting, basic retry/backoff, and counters surfaced in `/api/v1/services/status`.
- Forwarders are validated for port range and protocol.

## DNS (Unbound)

- Config model: `services.dns` with `enabled`, `listenPort`, `cacheSizeMB`, `upstreamServers`.
- API:
  - `GET/POST /api/v1/services/dns`
- Status and runtime events surface in `/api/v1/services/status` and `/api/v1/events`.

## NTP (chrony)

- Config model: `services.ntp` with `enabled`, `servers`, `intervalSeconds`.
- Uses chrony (`chronyd`), the only supported NTP daemon. `CONTAIND_NTPD_PATH`, if set, must name a `chronyd` binary.
- Positive `intervalSeconds` pins minpoll/maxpoll to a power of two, rounded up and clamped to 16–131072 seconds. Zero or omitted uses chrony's adaptive 64–1024 second defaults; initial `iburst` requests can be faster.
- Status `interval_seconds` reports the rendered fixed interval, not the requested value; it is null for adaptive polling or when disabled. `min_poll_seconds` and `max_poll_seconds` describe the configured range (null when disabled). These are configuration values, not measured synchronization cadence.
- API:
  - `GET/POST /api/v1/services/ntp`
- Status and runtime events surface in `/api/v1/services/status` and `/api/v1/events`.

## DHCP

- Config model: `services.dhcp` with `enabled`, `authoritative`, `listenIfaces`, `pools`, `reservations`, and lease settings.
- API:
  - `GET/POST /api/v1/services/dhcp`
  - `GET /api/v1/dhcp/leases`
- `authoritative` defaults to false. INIT-REBOOT, RENEWING and REBINDING requests for eligible addresses receive DHCPACK and record a lease in either mode, even when no prior lease is stored. This adopts active clients after lease data is lost and keeps their addresses out of the free pool.
- Eligible addresses must be inside the served interface's pool, must not be the server, network or broadcast address, and must not be leased or reserved for another MAC. A client's own fixed reservation, when configured, remains binding.
- Requests for ineligible addresses receive DHCPNAK only in authoritative mode; otherwise the server stays silent. SELECTING requests naming this server use the same eligibility checks. DISCOVER never receives DHCPNAK, including when the pool is exhausted.
- Authority is limited to directly attached configured interfaces whose pool lies in the interface IPv4 subnet. Requests relayed from another subnet or selecting another server receive no reply. Do not enable authority on networks managed by another DHCP server.
- Reservations are enforced by MAC and emit `service.dhcp.reservation.*` events.

## VPN

- Config model: `services.vpn` with WireGuard and OpenVPN modes.
- API:
  - `GET/POST /api/v1/services/vpn`
  - OpenVPN profiles and clients: `/api/v1/services/vpn/openvpn/*`
- Status is exposed via `/api/v1/services/status`; WireGuard runtime status is available from `/api/v1/services/vpn/wireguard/status`.

### OpenVPN (managed client)

The preferred path is to configure OpenVPN as a **managed client** from the UI:

- Configure `services.vpn.openvpn.managed` (remote/port/proto + CA/cert/key PEM blocks).
- `containd mgmt` renders a safe foreground config under `/data/openvpn/managed/` and supervises `openvpn --config /data/openvpn/managed/openvpn.conf`.
- Config exports are redacted by default (cert/key/password removed). Admins can
  explicitly request an unredacted export; keep it private.

### OpenVPN profiles (advanced import)

You can also import a foreground `.ovpn` profile (advanced):

- Upload a `.ovpn` from the UI (VPN page) to store it under `/data/openvpn/profiles/` and automatically set `services.vpn.openvpn.configPath` (managed config is cleared).
- The OpenVPN supervisor requires a **foreground** config (do not include the `daemon` directive).

### Docker requirements

OpenVPN requires `/dev/net/tun` and network administration privileges. The
starter maps the device and grants the required capabilities; use
[Docker Compose onboarding](docker-compose.md) rather than an unprivileged
`docker run`. WireGuard also needs engine-side kernel/network support.
Uploaded OpenVPN profiles can contain script hooks that run as root; only import
profiles you trust.

### OpenVPN (managed server)

To configure managed server mode:

- Configure `services.vpn.openvpn.mode=server` and `services.vpn.openvpn.server` (listen port/proto + `tunnelCIDR`).
- `tunnelCIDR` is the client address pool assigned by the OpenVPN server. This differs from WireGuard, where client networks are expressed via peer `AllowedIPs`.
- mgmt renders a server config under `/data/openvpn/managed/server/` and generates a local PKI under `/data/openvpn/managed/server/pki/`.
- Client profiles can be generated and downloaded as inline `.ovpn` files (requires setting `openvpn.server.publicEndpoint`).
- Enabling the OpenVPN server automatically opens the listen port on the WAN zone (nftables input) so clients can connect.

## AV

- Config model: `services.av` (ICAP or an engine-supervised ClamAV daemon).
- API:
  - `GET/POST /api/v1/services/av` (stages the candidate; commit to apply)
  - `POST /api/v1/services/av/update`
  - `GET/POST/DELETE /api/v1/services/av/defs`
  - The `av` entry of `GET /api/v1/services/status`

The engine is the only antivirus owner, in split and combined (`all`)
deployments alike. It applies the committed AV settings, runs clamd and the
FreshClam schedule, stores custom definitions and scans the HTTP previews the
dataplane queues. Management delegates status, updates and definitions to the
engine over its internal API; when the engine is unreachable these routes
return `503` and the status `av` entry reports `"available": false`.

ClamAV mode:

- The engine renders `clamd.conf` from the settings: clamd listens only on
  `clamav.socketPath` (required in clamav mode; the images prepare
  `/run/clamav/clamd.sock`) and loads every database in `/var/lib/clamav`. clamd restarts only when that rendered
  configuration changes.
- clamd needs at least one signature database before it starts. With
  `freshclamEnabled`, FreshClam runs once when enabled and then every
  `updateSchedule` (a Go duration such as `4h`; default `6h`; cron syntax is
  rejected). A successful download reloads clamd, or starts it if it was
  waiting for a database. Exit status "already up to date" is not an error.
- `POST /services/av/update` queues an immediate run on the same schedule and
  returns `202`; the result appears as `freshclam_last`/`freshclam_error`.
- Custom definitions are ClamAV database files (`.ndb`, `.hdb`, `.ldb`,
  `.yar` and the other ClamAV database types), at most 64 MiB. The engine
  validates each upload with `clamscan`, stores it under
  `clamav.customDefsPath` (default `/data/clamav/custom`, engine-local),
  installs it in the database directory and reloads clamd. Deleting a
  definition removes it and reloads clamd.
- Official databases live in `/var/lib/clamav` inside the engine container.
  Mount a volume there to keep them across container replacement.

Applying AV fails, and the commit reports a `services:` warning, when the
backend is missing, clamd exits or does not answer `PING` within three
seconds, or the first ICAP server does not answer `OPTIONS`. A freshly started
clamd with the full official database can take longer to load; the status
`ready` field turns true once it answers.

Scanning:

- `timeoutSec` bounds every scan and probe (default 5 s); `maxSizeBytes`
  rejects larger payloads before they are sent (0 = no limit). Both apply to
  ClamAV and ICAP, and resetting either to 0 restores the default.
- Scan failures follow `failPolicy`: `closed` reports `error`, `open` reports
  `bypass`; `failOpenIcs` forces `bypass` for ICS tasks. Only a malware
  verdict triggers a temporary flow block.
- Cached verdicts are keyed by content hash, backend and definitions
  generation, so new definitions or another server never reuse old verdicts.
- ICAP uses RFC 3507 `RESPMOD` with the payload as a chunked response body.
  `204 No Content` is clean; an `X-ICAP-Status` header containing
  `VirusFound` is malware; any other reply, including `200` with adapted
  content, is a scan error. `useTls` connects with verified TLS 1.2 or
  newer, using the configured host as the server name and the system roots
  plus the [additional CA bundle](config-format.md#additional-ca-bundle);
  there is no plaintext fallback.

Status (`av` entry) reports the applied settings, `ready` and `db_version`
from a live clamd `PING`/`VERSION` (or ICAP `OPTIONS`), scan, error and
detection counters, the clamd process, the FreshClam schedule and the applied
additional CA bundle revision (`trust_revision`).

## Proxies

- Config model: `services.proxy.forward` (Envoy explicit forward proxy) and `services.proxy.reverse.sites[]` (Nginx published services).
- API:
  - `GET/POST /api/v1/services/proxy/forward`
  - `GET/POST /api/v1/services/proxy/reverse`
- CLI:
  - `show proxy forward|reverse`
  - `set proxy forward <on|off> [port] [zone...]`
  - `set proxy reverse <on|off>`
- On commit/rollback, `containd mgmt` renders daemon configs to the services directory (`CONTAIND_SERVICES_DIR` or `/data/services`): `envoy-forward.yaml` and `nginx-reverse.conf`.
- Management includes optional supervision that starts/stops Envoy/Nginx if binaries are present. It validates the generated Nginx config with `nginx -t` before restart, tracks last start/error timestamps, and exposes the `/api/v1/services/status` view consumed by `show services status`.

## Auth/SSH
- Auth uses JWT cookie sessions by default with admin/view roles.
- SSH server integration is active and runs the same CLI registry (admin-only).

## Reset and reload

Factory reset reapplies appliance defaults to services as well as dataplane
policy. Disabling AV stops the engine's clamd and FreshClam schedule. DNS and proxy shutdowns
wait for daemon exit, escalating to a kill after two seconds and reporting an
error if exit cannot be confirmed within another two seconds.

`SIGHUP` in management or combined mode reapplies the stored running service
configuration; it does not promote candidate edits or reload environment
variables. See [reload and reset outcomes](api-reference.md#factory-reset) for
warnings, session revocation and restart-only settings.
