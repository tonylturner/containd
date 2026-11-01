# System Services

Configure services through the UI or management API. Saving stages candidate
configuration; review the diff and commit to apply it. Rollback reapplies the
previous running configuration. See [Config Format](config-format.md#configuration-lifecycle)
for the lifecycle and [API Reference](api-reference.md) for endpoint details.

`containd mgmt` configures services and supervises DNS, NTP, OpenVPN and proxies.
The engine owns the DHCP server, kernel WireGuard interfaces and AV runtime.
In split deployments, management-supervised daemons run in management's network
namespace; engine-owned services run in the engine's namespace. Both processes
need the intended network reachability and privileges.
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
- Enabling the managed OpenVPN server automatically opens its listen port in
  nftables INPUT on `listenInterfaces`, or `listenZone` when no interfaces are
  specified. The default zone is `wan`.

## AV

- Config model: `services.av` (an engine-supervised ClamAV daemon by default,
  or one remote ICAP server) with the `scan` selection of the traffic the
  scanning gate intercepts.
- API:
  - `GET/POST /api/v1/services/av` (stages the candidate; commit to apply)
  - `POST /api/v1/services/av/update`
  - `GET/POST/DELETE /api/v1/services/av/defs`
  - The `av` entry of `GET /api/v1/services/status`, whose `gate` object
    reports the scanning gate

The engine is the only antivirus owner, in split and combined (`all`)
deployments alike. It applies the committed AV settings, runs clamd and the
FreshClam schedule, stores custom definitions and runs the scanning gate.
Antivirus backends scan complete HTTP objects; whether delivery is held or
streamed depends on the download mode below. Nothing is scanned from packet
previews. Management delegates status, updates and definitions to the engine
over its internal API. When the engine is unreachable, update and definition
operations return `503`, and the status `av` entry reports `"available": false`.
Reading or staging AV configuration does not require a reachable engine.

### Scanning gate

With `enabled`, at least one `scan.include` entry and `httpDownload` or
`httpUpload` set, the engine intercepts HTTP/1.x connections transparently:
nftables steers each selected connection to a loopback listener of the
engine. The gate scans complete selected message bodies; uploads are held
until the verdict in every mode, and downloads are held until the verdict in
`hold` mode. With `stream_tail`, a download is forwarded except for its final
64 KiB, which is held until the verdict. A detection refuses a held body or
resets both connections after a streamed prefix. Clients and servers are
configured for nothing; the server sees the client's own IP address on another
source port. Only the existing source NAT changes what the server sees: a
connection that `nat` would masquerade today, because its egress is the
masquerading zone or because it is an inbound port forward's return path,
is masqueraded with the gate as without it.

The gate intercepts new TCP connections that the firewall would route
between zones, IPv4 and IPv6, forwarded ones and inbound IPv4 port forwards
alike; the selection matches the effective destination, after DNAT. The
firewall policy still decides every gated connection in both directions as
if it were forwarded, revocations and temporary blocks reset the gated
connections they match, and management, the engine API and the other local
services are never intercepted. A connection that was open before the
selection covered it continues unscanned until it closes, and a gated
connection stays gated until it closes, whatever the selection becomes.

Selecting traffic requires `dataplane.enforcement`. The selection:

- `include[]` entries name `sourceZones`, `destZones` and at least one
  `destPorts` entry (a decimal port or an `N-M` range, from 1). Zone pairs
  are directional like firewall rules, an empty zone list means any zone,
  every populated field of an entry must match, and any entry selects.
- `exclude[]` entries set at least one of `sourceZones`, `destZones`,
  `sources` (CIDRs), `destinations` (CIDRs) and `destPorts`. An excluded
  connection never reaches the gate, whatever the include entries say.
- No include entry may cover an ICS decoder port: 502 (Modbus), 2222 and
  44818 (EtherNet/IP), 2404 (IEC 104) and 20000 (DNP3). Staging rejects
  such a selection, naming the protocol and port. Files carried inside ICS
  protocols are not scanned.
- A selection may reference at most 255 egress zones. IPv6 link-local
  endpoints are never selected.
- A zone with no interface bound to it, an ICS asset without an IP address,
  and a closed fail policy without `icsZones` or `icsAssets` commit with a
  `services:` warning.

What is scanned: request bodies of selected connections when `httpUpload`
is set and response bodies when `httpDownload` is set. The gate frames
HTTP/1.0 and HTTP/1.1 only. Anything else on a selected port is "not
scanned" and follows the fail policy: TLS (HTTPS), HTTP/2, `CONNECT`,
`Upgrade` requests, partial objects (`206` or any `Content-Range`), bodies
larger than `maxSizeBytes` (with `0`, larger than 1 GiB) and objects the
scanner cannot classify in time. Such an outcome is never reported as
clean. Under `failPolicy: open` the object passes and is recorded as
unscanned; under `closed` the client is refused (`400` for a request the
gate cannot frame, `502` for such a response, `403` for a body it may not
deliver). A confirmed detection is refused with `403` under either policy.

Download modes (`scan.downloadMode`):

- `hold` (default) delivers no byte of a selected body before the verdict.
- `stream_tail` forwards a download as it arrives except its last 64 KiB,
  which the gate holds until the verdict. A verdict that delivers releases
  the tail; one that blocks resets both connections, because the client
  already holds a prefix. Uploads are held in every mode.

In both modes the gate remembers each download it refused as infected
(client address, origin, host, path and query) for 10 minutes, at most 4096
entries, and refuses a later request for that URL with `403` before
contacting the origin, so a withheld `stream_tail` tail cannot be fetched
with a `Range` request. The memory is a detection: it refuses the URL under
either fail policy, with the scanner unavailable and for ICS endpoints.

Fail policy and ICS endpoints:

- `failPolicy` is `open` (default) or `closed` and decides unscanned
  outcomes: scanner not ready, timeout, scanner error, oversized, unsupported
  and held-object capacity reached. The connection limit is a hard cap:
  excess connections close immediately under either policy.
- `scan.icsZones` and `scan.icsAssets` mark ICS endpoints: the zones'
  interfaces and subnets, and the assets' IP addresses. A connection with
  an ICS endpoint on either side passes unscanned outcomes under `closed`
  too. A detection is always blocked.

Gate status, the `gate` object of the `av` status entry:

- `state` is `off` while the data plane does not enforce; `refuse` or
  `pass` (by fail policy) while a listener or the gate's policy routing is
  down; `pending` while the gate runs but the scanner is not ready, so each
  selected object is refused under `closed` and passed under `open`; `open`
  when everything is up.
- `enabled` (the selection intercepts something), `fail_policy`, `admit`
  (the admission installed in nftables: `open`, `refuse` or `pass`) with
  `admit_error`, `listeners[]` (`address`, `masquerade`, `up`, `error`,
  `unavailable` for a loopback family the host lacks), `scanner` (`ready`,
  `error`), `connections`, `routing_error` and `warning`.
- A commit whose scanner backend is still starting succeeds with the
  `services:` warning `AV backend is still starting … scanning is pending
  until it is ready`, records `service.av.pending`, and the gate shows
  `pending` until clamd is capable and its selected scan paths are proven. The AV page
  shows the same state.
- Scanner readiness keeps two independent facts for each selected direction:
  backend capability and scan-path health. clamd must answer `PING` and
  `VERSION`; ICAP `OPTIONS` must declare `REQMOD` for uploads and `RESPMOD`
  for downloads. A successful scan never overrides a missing capability.
  Initial scan-path proof and recovery after a scan failure require a bounded
  scan of the standard EICAR antivirus test string in each unhealthy direction.
  Only an infected verdict is accepted: a clean reply (including ICAP `204`)
  could mean antivirus was bypassed and cannot restore readiness. These
  synthetic scans do not enter object counters, detections or security events.
  Healthy directions are not continuously canary-scanned.
- Readiness follows observable backend loss and recovery without a commit or
  status request. clamd capability is probed once per second after completion.
  ICAP honours `Options-TTL`, bounded to one through 30 seconds; a missing or
  invalid TTL selects one second. No autonomous ICAP probes run without a
  selected scan direction. Unhealthy directions retry their canary once per
  second, reusing unexpired OPTIONS capability. Each complete observation
  (capability plus canaries) has a two-second budget, or `timeoutSec` if shorter.
  Capability loss is detected within at most 34 seconds (an in-flight
  observation, the capped TTL, then the next observation); with the default
  one-second cadence the bound is five seconds. The gate samples readiness
  every 200 ms. A scan failure invalidates its direction immediately;
  transport failures also invalidate backend capability. Object-level
  rejections, detections and cancelled diagnostic requests do not invalidate
  readiness. An unchanged backend reapply retains the existing proof and accepts
  failures from scans already in flight; readiness ignores scan results from a
  replaced backend.
- Readiness proves the latest capability and scan-path observations, not that
  every future object will scan successfully. In particular, if an ICAP
  frontend keeps answering OPTIONS after its antivirus dependency fails,
  that scan-path loss is discovered by the next scan, not by OPTIONS or a
  periodic healthy-path canary. After that failure, OPTIONS alone cannot
  restore protection; the unhealthy direction must detect EICAR again.
  An active scan selection is not reported as protecting while either
  required fact is unavailable.

Gate runtime: the listeners bind `127.0.0.1` and `::1` on ports 18100
(plain) and 18101 (masqueraded upstream); the gate's replies reach it over
a policy routing rule for mark `0x00400000` to table 104010, and
`net.ipv4.tcp_fwmark_accept` must stay `0` (the status `warning` says when
it is not). The gate serves at most 1024 connections and holds at most 64
bodies at once, keeps bodies up to 4 MiB in memory and spools longer ones
to the temporary directory, bounds each read or write to 90 s, each head or
body to 10 min and each upstream connection attempt to 10 s. A scan may
take ten times `timeoutSec`, at least one minute, so a large clean object is
not cut short.

Events (`GET /api/v1/events`, protocol `av`): `service.av.detected` for a
detection, `service.av.scanned` for every other scanned or unscanned
object, `service.av.gate_connection` for a connection the gate could not
complete, `service.av.gate_state` for every admission change and
`service.av.pending` for a commit with a starting backend. Object events
carry the client, the effective destination (`server`) and, for a port
forward, `original_destination`, plus direction, verdict, action, backend,
reason, size, duration and, when known, method, host, target and status.
Reason `aborted` marks an object the client abandoned before the verdict;
it was neither decided nor delivered.

ClamAV mode:

- The engine renders `clamd.conf` from the settings: clamd listens only on
  `clamav.socketPath` (default `/run/clamav/clamd.sock`, which the images
  prepare) and loads every database in `/var/lib/clamav`. clamd restarts only
  when that rendered configuration changes.
- clamd needs at least one signature database before it starts. With
  `freshclamEnabled`, FreshClam runs once when enabled and then every
  `updateSchedule` (a positive Go duration such as `4h`; default `6h`).
  While AV is enabled, staging rejects any other value, including cron syntax.
  A successful download reloads clamd, or starts it if it was
  waiting for a database. Exit status "already up to date" is not an error.
- `POST /api/v1/services/av/update` queues an immediate run on the same schedule and
  returns `202`; the result appears as `freshclam_last`/`freshclam_error`.
- Custom definitions are ClamAV database files (`.ndb`, `.hdb`, `.ldb`,
  `.yar` and the other ClamAV database types), at most 64 MiB. The engine
  validates each upload with `clamscan`, stores it under
  `clamav.customDefsPath` (default `/data/clamav/custom`, engine-local),
  installs it in the database directory and reloads clamd. Deleting a
  definition removes it and reloads clamd.
- Every reload is confirmed in the background: the engine installs a probe
  signature and scans for it until clamd detects it, within five minutes,
  retrying a failed activation with a backoff between 30 s and 10 min. The
  status reports `reload_pending` meanwhile, the backend is not ready while
  an activation has failed, and `service.av.clamav_reload_confirmed` records
  each confirmed activation.
- Official databases live in `/var/lib/clamav` inside the engine container.
  The Compose files mount the named volume `clamav-db` there, so replacing
  the container does not download them again. A split deployment mounts such
  a volume on the engine service; management never uses the databases.
  When the engine runs as root, each ClamAV apply gives the directory and
  everything in it to the image's `clamav` account, so a volume kept from
  an image whose account had another uid keeps working. Symbolic links are
  re-owned, never followed.

Applying AV fails, and the commit reports a `services:` warning, when the
backend is missing, clamd exits, the ICAP server does not answer
`OPTIONS` with a non-empty `Methods` header declaring the needed methods,
or an initial scan-path canary fails.
A missing, empty or incomplete declaration reports the scanner as not
ready, with the reason in AV and gate status. A clamd that is still starting
when the three-second apply budget ends is pending, not failed (see the gate
status above); a freshly started clamd with the full official database can take
longer to load. Readiness requires capability, confirmed database activation
and scan-path proof for the selected directions.

Scanning:

- `timeoutSec` bounds connecting to the backend and scan probes (default
  5 s, at most 300); live status probes use at most 2 s. The gate's own
  deadline bounds each scan.
  `maxSizeBytes` rejects larger payloads before they are sent (0 = no limit,
  at most 104857600, clamd's default stream limit of 100 MiB). Both apply to
  ClamAV and ICAP. Setting `timeoutSec` to 0 restores the default; setting
  `maxSizeBytes` to 0 removes the scanner-side size check, but the gate's
  1 GiB bound and backend limits still apply. While AV is enabled, staging
  rejects negative or larger values.
- Every result records the backend that produced it. Native ClamAV verdicts
  are cached by content hash, clamd socket, definitions generation and size
  limit, so new definitions or another socket never reuse old verdicts.
  ICAP verdicts are never cached because the server may decide by direction,
  HTTP headers and endpoints.
- ICAP is a generic RFC 3507 backend with exactly one server and no
  failover. Uploads go as `REQMOD` with the request head, downloads as
  `RESPMOD` with the request and response heads. The request head is sent
  as the client sent it, including `Cookie` and `Authorization`, as ICAP
  specifies; choose an ICAP server you trust with it. The body streams as
  transferred (chunked framing removed, content coding kept), with
  `X-Client-IP` and `X-Server-IP`. A reply is infected when it carries
  `X-Infection-Found`, `X-Violations-Found`, `X-Virus-ID` or an
  `X-ICAP-Status` containing `VirusFound`; `204 No Content` is clean;
  `413` rejects an oversized object. Any other reply, including `200`
  with adapted content, is a scan error.
  An `OPTIONS` response must include a non-empty `Methods` header, listing
  `REQMOD` when uploads are scanned and `RESPMOD` when downloads are.
  A `200` response without that declaration is not ready.
  `useTls` connects with verified TLS 1.2 or
  newer, using the configured host as the server name and the system roots
  plus the [additional CA bundle](config-format.md#additional-ca-bundle);
  there is no plaintext fallback.

Status (`av` entry) reports the applied settings, combined capability and
scan-path `ready`, and `db_version` from a live clamd `VERSION` (empty for
ICAP). Status also includes scan, error and
detection counters, the clamd process, the FreshClam schedule, the pending
reload, the applied additional CA bundle revision (`trust_revision`) and
the `gate` object above.

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
