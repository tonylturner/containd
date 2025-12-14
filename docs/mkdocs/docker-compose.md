# Docker Compose

This document is rendered from `docs/mkdocs/`.

This repo ships a `docker-compose.yml` for running the management plane (`containd`) and engine (`engine`) together, with a `.env`-driven configuration.

## Quickstart

```bash
cp .env.example .env
# Edit .env and set a real CONTAIND_JWT_SECRET
docker compose up -d --build

# Print connection info (UI/HTTPS/SSH + container IPs)
bash scripts/containd-connect
```

Tip: `bash scripts/containd up` wraps `docker compose up -d --build` and prints connection info automatically.

## Configuration via `.env`

Docker Compose automatically loads `.env` from the same directory as `docker-compose.yml`.

- `.env` is ignored by git (do not commit secrets).
- `.env.example` is the committed template.

### Common variables

- `CONTAIND_JWT_SECRET`: JWT signing key for UI/API auth (change for real deployments).
- `CONTAIND_COOKIE_SECURE`: set to `1` when running behind HTTPS (or a TLS-terminating proxy) to force the `Secure` cookie flag.
- `CONTAIND_TRUSTED_PROXIES`: comma-separated list of proxy IPs/CIDRs you trust for client IP resolution (e.g. `127.0.0.1,::1,10.0.0.0/8`).

### Management ↔ Engine connectivity

The management plane (`containd`) talks to the dataplane engine over the engine’s internal HTTP API.

- `CONTAIND_ENGINE_URL`: base URL for the engine API (must include a scheme, e.g. `http://127.0.0.1:8081`).

In the default compose file, `containd` runs in the same network namespace as the `engine` container
(`network_mode: "service:engine"`). This makes “interface/IP reality” consistent for UI, CLI, and dataplane,
but it also means:

- Use `http://127.0.0.1:8081` for `CONTAIND_ENGINE_URL` (container-local loopback), not `http://engine:8081`.

### Low ports (DNS / DHCP)

Some appliance services traditionally bind to privileged ports (e.g. DNS on `53/udp,tcp`).

In Docker lab mode, `docker-compose.yml` grants `CAP_NET_BIND_SERVICE` so embedded services can bind to low ports
without running as root.

## Interface mapping (Docker lab mode)

When the `engine` service is attached to multiple Docker networks, Docker creates one kernel interface per network.
The kernel device names (`eth0`, `eth1`, …) are not guaranteed to correspond to `wan/dmz/lan1…` in a stable order,
because Docker network attach order can vary.

In this repo’s `docker-compose.yml`, we explicitly pin:
- `wan` as the default-gateway network (`gw_priority`) so the kernel default route is via WAN.
- interface names (`interface_name`) so `wan/dmz/lan1..lan6` reliably map to `eth0..eth7`.

To keep the appliance UI/CLI stable in Docker labs, `Interfaces → Auto-assign` prefers matching interface roles by
the IPv4 subnets present on each interface (defaults match this repo’s `docker-compose.yml`):

- `wan`: `192.168.240.0/24`
- `dmz`: `192.168.241.0/24`
- `lan1..lan6`: `192.168.242.0/24` … `192.168.247.0/24`

If those subnets aren’t present, auto-assign falls back to kernel index ordering.

To override subnet matching (for custom lab topologies), set:
`CONTAIND_AUTO_WAN_SUBNET`, `CONTAIND_AUTO_DMZ_SUBNET`, `CONTAIND_AUTO_LAN1_SUBNET` … `CONTAIND_AUTO_LAN6_SUBNET`.

### Ports

- `CONTAIND_PUBLISH_HTTP_PORT`: host port for HTTP UI/API → container `8080`.
- `CONTAIND_PUBLISH_HTTPS_PORT`: host port for HTTPS UI/API → container `8443`.
- `CONTAIND_PUBLISH_SSH_PORT`: host port for SSH → container `2222`.
- `CONTAIND_PUBLISH_ENGINE_PORT`: host port for engine API → container `8081`.

### Persistent data paths (inside container)

All default DB paths are under `/data` (mounted to `./data` by compose):

- `CONTAIND_CONFIG_DB` (default `/data/config.db`)
- `CONTAIND_AUDIT_DB` (default `/data/audit.db`)
- `CONTAIND_USERS_DB` (default `/data/users.db`)

### SSH bootstrap

To avoid “chicken/egg” provisioning, you can seed an admin SSH key (authorized_keys line):

- `CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY`
- `CONTAIND_SSH_BOOTSTRAP_ADMIN_USER` (default `containd`)

## Troubleshooting

- Validate compose: `docker compose config -q`
- Follow logs: `docker compose logs -f containd`
- If interface auto-assign/reconcile fails with `engine interfaces status 400`, check `docker compose logs -f engine` for `ip_forward`/sysctl errors; older builds treated that as fatal in some VM-backed Docker runtimes.
- Factory reset (CLI): `factory reset NUCLEAR` (admin only; wipes config/users/audit and re-seeds defaults)
