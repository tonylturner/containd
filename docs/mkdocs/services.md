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
- Uses chrony as the NTP implementation on Wolfi-based images. Falls back to openntpd if chrony is not available.
- API:
  - `GET/POST /api/v1/services/ntp`
- Status and runtime events surface in `/api/v1/services/status` and `/api/v1/events`.

## DHCP

- Config model: `services.dhcp` with `enabled`, `listenIfaces`, `pools`, `reservations`, and lease settings.
- API:
  - `GET/POST /api/v1/services/dhcp`
  - `GET /api/v1/dhcp/leases`
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

- Config model: `services.av` (ICAP and optional ClamAV supervision).
- API:
  - `GET/POST /api/v1/services/av`
  - `POST /api/v1/services/av/update`
  - `GET/POST/DELETE /api/v1/services/av/defs`

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
