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

The Services overview groups the existing routes by **Connectivity**, **Access**,
**Inspection** and **Logs**. DNS, NTP and proxy software identities are available
under **Troubleshooting** / **Service details**, not in their primary summaries.
Overview trend charts require at least two reported samples with some activity;
empty, single-sample and all-zero series keep the reported rate and error text
without an empty chart. Individual pages lead with a compact **Configured** /
**Running** / **Attention** / **Updated time** strip, then settings, then
**Activity**. Configured describes the candidate editor, not live protection;
Running uses a separate runtime observation. DHCP and Syslog do not report a
separate running flag, so their strip leaves Running **Unknown**. WireGuard
link state and remote ICAP readiness are shown separately in Activity, not
reinterpreted as a process-running flag. Updated time
is the service's reported render/check time, not a guarantee of freshness.

**Troubleshooting** contains the **Service details** button for process IDs,
paths and software metadata. The button works with Enter or Space and leaves
focus on the button when closed. Fault causes remain outside disclosures.
Inspection stays available when the configuration read fails: editing and
**Save** are disabled, not troubleshooting or live-status refresh.
Antivirus keeps **Scanned traffic** beside its enable and fail-policy settings;
definition updates and VPN credential revocations remain immediate operations,
separate from staging settings with **Save**.

Service panels show **Unknown** when live status is unavailable; missing readings
are not stopped services or zero activity. Use **Refresh** or the panel's **Retry**
to request a new observation. **Service details** keeps process IDs, generated
settings files and scanner metadata available without crowding the status summary.
Antivirus **Scan-path details** retains listener counts and admission metadata;
fault causes, the scanning outcome and fail policy remain visible. Syslog
**Delivery details** and per-stream **Technical details** expose batching and exact
stream positions.
DHCP reports configuration-render counts, notes and errors inline in **Activity**,
with issued addresses in **Active Leases**. Its status does not report process IDs,
configuration-file or lease-file paths, so it has no separate troubleshooting
expander.
The antivirus status strip also summarizes the scan-path state and its traffic
effect before settings. Syslog summarizes known telemetry loss, continuity gaps
and audit forwarding failures/backlog there; per-stream totals are summed across
destinations and sources, not unique lost records. Audit forwarding does not
report a loss count, and missing progress remains **Unknown**. The collector
acknowledgement caveat is a neutral note, not itself a delivery fault.
**Advanced local scanner settings** and **Advanced remote scanner settings**
retain scanner paths, update scheduling and ICAP protocol settings. VPN keeps
peer JSON and profile import under **Advanced peer settings** and
**Advanced profile import**; opening a disclosure does not change saved settings.
Saved peers and customized scanner settings open automatically. DNS and proxy
advanced options open for non-default values. DHCP keeps listen interfaces,
gateway and pools beside enablement; its advanced options open for saved
non-default lease, DNS, domain or reservation settings. Remote scanner
settings also open whenever ICAP mode requires them. **Advanced profile path**
opens for a saved OpenVPN path or when an enabled path-based client needs one.

Dashboard's **No recent IDS/AV alerts** describes only the reported alert counts,
not overall appliance health or protection. The dashboard does not observe live
IPS protection state, so its IPS card always shows **Unknown**. Unknown service
cards are visually distinct from disabled services. Rule counts are counts, not
measured utilization; container memory bars require a reported positive memory
limit and percentage. An unlimited container has no memory utilization gauge.
The **Bind interfaces** checklist item is ready only when at least one interface
is configured and every configured interface matches a reported network device,
using its Device field or matching interface name. Logical interface counts alone
do not establish readiness. Missing configuration or live device information
leaves binding readiness **Unknown**.

Syslog **Last check** records the latest forwarding check, including empty or
failed batches, not successful delivery. Per-forwarder **Last sent** advances
only when records are sent. NTP binary details distinguish **not found** (discovery
reported no binary) from **Unknown** (no discovery result was reported).

Deleting a reverse proxy site first changes local edits. **Save** stages the
removal; review and **Commit** apply it. Saving alone does not remove a live site.

In Diagnostics, temporary flow blocks match source IP, destination IP,
destination service port and protocol, with any source port: they can affect
multiple connections. When enforcement is off, open **Deployment details** for
configuration and startup guidance. There is no enforcement switch on PCAP.

## Service faults

An older stored service configuration that no longer passes validation is
quarantined independently. Management, firewall replay and other services keep
running. Missing or expired proxy TLS material is also checked at apply time:
there is no plaintext fallback. Management-run process or filesystem failures
and engine-side WireGuard, DHCP or AV apply failures are reported per service
as runtime faults; they do not prevent other services or firewall application.
An AV backend still starting is a warning, not a fault.

`GET /api/v1/services/status` includes a sorted `faults` array (empty when healthy).
Each entry has `service`, `kind` (`config` or `runtime`) and a sanitized `message`.
Service identities are `syslog`, `dns`, `ntp`, `av`, `proxy`, `dhcp`, `wireguard`
and `openvpn`. Faulted service entries also contain `state: "faulted"` and `fault`
with that same object. WireGuard and OpenVPN have independent entries; the legacy
`vpn` entry remains. AV retains engine availability and runtime details alongside
the management-known fault, even when the engine is unreachable.

The desired configuration remains available for inspection, export and repair;
quarantine is never saved over it. Unchanged faults can be carried through
unrelated configuration edits, but new faults and invalid edits to a faulting
service are rejected. Clear the service section or repair it before changing
that service. Commit checks this again against the current running document.
Ruleset and coverage previews use the effective configuration and disclose
`serviceFaults`.

A quarantined service gets no automatic firewall admission rule. VPN CIDR tokens
for a quarantined tunnel match nothing; OpenVPN is stopped, and a quarantined
DHCP server is stopped without its UDP/67 input rule. WireGuard quarantine or
explicit disable removes containd-created links regardless of their names;
changing the enabled interface name removes the previous owned link. Delete
failures are reported as WireGuard runtime faults and retried on the next apply.
WireGuard link ownership is persisted in `/data/wireguard-links.json` (override
with `CONTAIND_WIREGUARD_STATE_PATH`) and scoped to the kernel boot and network
namespace. A kernel identity recorded only after exclusive creation prevents
adoption of foreign links. Ownership survives engine process restarts, but
existing unmarked links from older versions remain unowned on upgrade and are
never deleted automatically.
AV is different: scanner quarantine retains scan selection, directions and fail
policy. A closed policy still blocks unscanned content except the configured ICS
bypass; an open policy permits it. Quarantine does not silently disable the gate.

Fault-set changes produce service events and best-effort durable audit records,
not duplicate faults on every engine reconnect. The most recent boot's faults
also appear as `bootServiceFaults` in `/api/v1/system/management-reservation`.
Audit-write failure is logged and does not stop enforcement. Metrics expose
`containd_services_faulted{service}` independently of runtime observations:
a fault is not proof that a process or kernel interface has stopped.
Successful later application clears the fault.

## Runtime metrics

`containd_services_running{service="..."}` reports observed running state
(`1`) or stopped state (`0`). An absent series means unknown, not stopped;
do not fill missing series with zero in alerts or dashboards.

- Management refreshes `dns`, `ntp`, `syslog`, `proxy` and `openvpn` from its
  service managers during service application and fault updates. An absent
  manager removes its series. OpenVPN measures the supervised process, not
  tunnel connectivity; a connecting client counts as running.
- Management omits `dhcp` and `wireguard`: it has no live runtime observation
  for these engine-owned services in this collector. Desired configuration,
  apply outcomes and stored DHCP leases do not establish runtime state.
  WireGuard's on-demand status API does not feed these gauges.
- The aggregate `vpn` is `1` when OpenVPN is observed running. Otherwise it is
  omitted: without a WireGuard observation, management cannot establish that
  every VPN is stopped. A WireGuard fault does not hide a running OpenVPN daemon.
- The engine's AV manager owns `av`; management fault reporting does not
  overwrite that runtime gauge.

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
- The DHCP page picks listen interfaces from configured interfaces and edits
  pools as interface/start/end rows. Reservations use interface/MAC/IP rows;
  hostnames are observed in leases, not configurable reservation fields.
  Saved interface names absent from the configured list remain selectable.
  **Save** validates rows and stages the same configuration arrays; review and
  commit to apply. Lease, DNS and domain options remain under **Advanced options**.

## VPN

- Config model: `services.vpn` with WireGuard and OpenVPN modes.
- API:
  - `GET/POST /api/v1/services/vpn`
  - OpenVPN profiles and clients: `/api/v1/services/vpn/openvpn/*`
- Status is exposed via `/api/v1/services/status`; WireGuard runtime status is available from `/api/v1/services/vpn/wireguard/status`.
- OpenVPN status distinguishes a supervised daemon (`openvpn_running`) from
  completed initialization (`openvpn_connected`). A running client without a
  completed tunnel is connecting, not faulted. Client startup checks for early
  process exit for 250 ms, then leaves DNS and connection retries supervised.
  Connection status clears on a soft restart or process exit. Server startup
  still requires the initialization marker within five seconds before
  acknowledging its loaded revocation list.

### WireGuard keys and peers

The VPN page edits peers as rows: name, public key, allowed IPs (CIDRs), optional
endpoint and keepalive seconds. **Peers (JSON)** remains under **Advanced peer
settings** and edits the same list. Add, remove and edit operations stage only
when you select **Save**; commit applies them.

A stored private key shows **Private key configured — Replace**, without
revealing it. **Generate key pair** uses WebCrypto X25519 in the browser; it is
hidden with an explanation when unsupported. Only the private key is submitted
in the staged write, not in a URL or browser storage. Replacing the server key
requires updating clients. A successful Save clears each submitted secret field
even if you edit peers while it is pending. A newer replacement entered during
that request remains an unsaved draft; failed saves retain the draft for review.
This applies to the WireGuard private key and managed OpenVPN CA, certificate,
private key and password.

Client downloads require a known server public key (generated in this editor or
from live tunnel status) and a server endpoint with port entered in the download
helper. The endpoint helper is not persisted. **Download client config** produces
a template, not an issued credential: enter the matching client's private key
locally, then review its address and routes before use. The peer's allowed IPs
supply its proposed client addresses, and the server tunnel CIDR supplies the
initial route; routed networks may need different addresses or additional routes.
The server peer endpoint is not the server's public endpoint. Downloads never
include the server private key. A live public key describes the applied server,
which may differ from staged settings; commit and verify it before connecting.

### VPN secret-presence metadata

`GET /api/v1/services/vpn`, successful VPN stage responses and the VPN object in
profile-upload responses omit stored secret values. `wireguard.privateKeyConfigured`
is always a boolean. When `openvpn.managed` exists it always includes boolean
`caConfigured`, `certConfigured`, `keyConfigured` and `passwordConfigured`.
These are read-only presence indicators, not proof that a tunnel is running.
Managed OpenVPN fields show configured material without requiring it again.

Writes retain existing WireGuard keys when `privateKey` is omitted or empty.
When both old and new managed OpenVPN objects exist, omitted or empty CA,
certificate, key and password fields retain their stored values. To replace a
secret, supply a nonempty replacement. Omitting `managed` removes the entire
managed client configuration; it does not retain that object. These VPN writes
stage the candidate with the revision precondition; they never auto-commit.

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
- Imports are limited to **1 MiB** and parsed with a bounded option/arity
  allowlist. Certificate, key and TLS material must be inline
  (`<ca>`, `<cert>`, `<key>`, `<tls-auth>` or `<tls-crypt>` blocks).
  External file references, scripts/hooks, plugins, includes, management
  directives and unknown options are rejected. Uploads and runtime reads of
  `configPath` use the same parser and are re-rendered into containd-owned files;
  an arbitrary profile path does not bypass these restrictions.

### Docker requirements

OpenVPN requires `/dev/net/tun` and network administration privileges. The
starter maps the device and grants the required capabilities; use
[Docker Compose onboarding](docker-compose.md) rather than an unprivileged
`docker run`. WireGuard also needs engine-side kernel/network support.

### OpenVPN (managed server)

To configure managed server mode:

- Configure `services.vpn.openvpn.mode=server` and `services.vpn.openvpn.server` (listen port/proto + `tunnelCIDR`).
- `tunnelCIDR` is the client address pool assigned by the OpenVPN server. This differs from WireGuard, where client networks are expressed via peer `AllowedIPs`.
- mgmt renders a server config under `/data/openvpn/managed/server/` and generates a local PKI under `/data/openvpn/managed/server/pki/`.
- Client credentials can be created and downloaded as inline `.ovpn` files (requires setting `openvpn.server.publicEndpoint`).
- Enabling the managed OpenVPN server automatically opens its listen port in
  nftables INPUT on `listenInterfaces`, or `listenZone` when no interfaces are
  specified. The default zone is `wan`.

#### Client credentials and revocation

The VPN page lists each credential's name, issuer/serial ID, issue and expiry
times, and revoked state. Creating a credential takes effect immediately on
the **active managed server**, not the staged candidate. Names must be lowercase,
filename-safe and 1–64 characters long. An active name cannot be issued again
until its credential is revoked; reusing a name creates a new ID.

Use `GET /api/v1/services/vpn/openvpn/clients` to list credentials and `POST`
to that path with `{"name":"operator"}` to create one. Download with
`GET /api/v1/services/vpn/openvpn/clients/{id}`. IDs are opaque issuer/serial
identifiers, not names. Downloads are read-only: they never issue, renew or
repair credentials. Unknown IDs return 404; duplicate names, revoked downloads
and operations requiring an inactive managed server return 409; invalid names
return 400.

Revoke with the VPN page's confirmation dialog or
`POST /api/v1/services/vpn/openvpn/clients/{id}/revoke`. Revocation is durable
and irreversible; revoked entries stay in the inventory and cannot be downloaded.
The server checks a signed certificate revocation list (CRL) and restarts after
revocation, so **all clients reconnect once**. A 503 response containing
`revoked:true, applied:false` means **revoked, not yet applied**, not an undone
revocation: it is saved, but enforcement by the running server is not confirmed.
The UI keeps that warning while the page is open and offers **Retry apply**.
The list response reports `revocationsApplied`: false only when revoked credentials
exist and a running managed server has not confirmed loading the current CRL;
otherwise true, including when no managed server is running, since its next start
loads the current CRL.
The VPN page offers **Apply revocation** only while unapplied.
The revoke operation is idempotent; retry it after resolving the runtime problem.
These operations do not require a configuration commit.

The CRL lasts **7 days**, renews within **24 hours of expiry**, and is checked
**hourly** while running. Renewal is also checked across server restarts.

**Back up the OpenVPN PKI volume**, including the CA keys, credential inventory,
and revocation material under `/data/openvpn/managed/server/pki/`. Protect that
backup as a secret. Configuration exports, even unredacted ones, exclude the PKI
authority and are not a substitute for a PKI backup.

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
- Losing transport or a direction's capability invalidates its previous
  scan-path proof. After reconnection, every affected direction must detect
  EICAR again before readiness and datapath protection can recover. Newer
  capability replies cannot suppress that invalidation. Only a canary started
  after the loss can restore its direction's proof; ordinary clean traffic
  neither preserves obsolete proof nor supersedes a recovery canary.
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
- clamd needs at least one signature database before it starts. Automatic
  updates are off unless `clamav.freshclamEnabled` is true. When enabled,
  FreshClam runs once and then every `updateSchedule` (a positive Go duration
  such as `4h`; default `6h`).
  While AV is enabled, staging rejects any other value, including cron syntax.
  A successful download reloads clamd, or starts it if it was
  waiting for a database. Exit status "already up to date" is not an error.
- An omitted scanner mode means **Local scanner (ClamAV)**, including its
  readiness and definition-update controls. A missing-database fault offers
  **Update definitions** beside the cause. Both this and **Run definition update**
  request confirmation and act immediately, independently of **Save**.
  Definition uploads and deletion also require confirmation.
- If staging scan selections reports `needs dataplane.enforcement`, follow
  the link to the Firewall enforcement control, stage enforcement, then retry
  the AV save. Review both changes and commit to apply; the link changes no settings.
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
  **Cache TTL (seconds)** edits the cache duration, including fractional seconds;
  the API stores `cacheTtl` in nanoseconds. Zero selects the default 10 minutes.
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
- Management includes optional supervision that starts/stops Envoy/Nginx if binaries are present. Before publishing, it validates the staged configs with `envoy --mode validate` and `nginx -t` when those binaries are installed. Staged filenames retain their `.yaml` or `.conf` extension so each daemon uses the correct parser. Management tracks last start/error timestamps and exposes the `/api/v1/services/status` view consumed by `show services status`.

### Reverse sites and TLS

On **Proxies**, **Add** puts a new site in the local list. **Edit** loads an
existing site's name, listen port, backends, hostnames, description and TLS
settings; **Update site** changes that local list and **Cancel edit** discards
the form edits. **Save** stages the list into the candidate with its loaded
revision. Review and commit to apply; none of these form actions uploads
certificates or starts a listener immediately.

**Site TLS** opens automatically for a site with TLS enabled or a saved
certificate reference. Enable TLS and enter `certRef` as a filename stem,
not a file path: 1–128 ASCII letters, digits, underscores or hyphens, beginning
with a letter or digit. For reference `plant-web`, externally provision
`plant-web.crt` and `plant-web.key` in `/data/certs` on the management service
host (or the directory set by `CONTAIND_CERTS_DIR`). The files must contain a
matching PEM certificate/private-key pair, and every certificate in the chain
must be currently valid. Files and resolved symlinks must stay inside that
directory and be readable by the service. A container deployment needs these
files in its mounted storage.

There is no proxy-certificate upload API or web form. **System Settings**
certificate upload replaces the management HTTPS identity, not a proxy site's
certificate. A reference alone cannot provision the files. Missing, expired,
not-yet-valid or mismatched material rejects application rather than falling
back to plaintext.

Proxy faults lead with a short cause summary. **Technical details** retains the
exact reported diagnostic output, including generated configuration when the
daemon includes it; it is not a separate generated-file or log download.

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
