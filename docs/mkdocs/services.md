# System Services

Tracks syslog, DNS, NTP, DHCP, VPN, proxy, and AV service configuration plus runtime status managed by `containd mgmt`.

## Syslog

- Config model: `services.syslog.forwarders[]` with `address`, `port`, `proto` (udp|tcp).
- API:
  - `GET /api/v1/config` (includes services.syslog)
  - `POST /api/v1/config` to update full config
  - `/api/v1/services/syslog` get/set endpoints.
- `pkg/cp/services/syslog` applies config and forwards unified events over UDP/TCP with RFC5424 or JSON formatting, basic retry/backoff, and counters surfaced in `/api/v1/services/status`.
- Forwarders are validated for port range and protocol.

## DNS (Unbound)

- Config model: `services.dns` with `enabled`, `listenPort`, `cacheSizeMB`, `upstreamServers`.
- API:
  - `GET/POST /api/v1/services/dns`
- Status and runtime events surface in `/api/v1/services/status` and `/api/v1/events`.

## NTP (OpenNTPD)

- Config model: `services.ntp` with `enabled`, `servers`, `intervalSeconds`.
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
- On commit/rollback, `containd mgmt` renders daemon configs to the services directory (`CONTAIND_SERVICES_DIR` or `/var/lib/containd/services`): `envoy-forward.yaml` and `nginx-reverse.conf`.
- `pkg/cp/services/proxy` includes optional supervision that starts/stops Envoy/Nginx if binaries are present. It validates the generated Nginx config with `nginx -t` before restart, tracks last start/error timestamps, and exposes a richer `/api/v1/services/status` view consumed by `show services status`.

## Auth/SSH
- Auth uses JWT cookie sessions by default with admin/view roles.
- SSH server integration is active and runs the same CLI registry (admin-only).
