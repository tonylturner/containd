# Docker Compose

This repo ships `deploy/docker-compose.yml` as the supported starter topology for the combined appliance (`containd all`). It is `.env`-driven, image-based, and gives containd a stable eight-interface Docker lab layout (`wan`, `dmz`, `lan1` through `lan6` on `eth0` through `eth7`).

Docker Compose owns the available networks, interface attachments, and Docker-level IP addresses. containd owns the security policy inside that topology: zone binding, routing intent, firewalling, DPI, services, and monitoring.

containd is designed to segment container-to-container traffic inside Docker-based labs. Linux Docker hosts are supported, and Docker Desktop is also a valid lab target because the traffic being filtered lives inside Docker's Linux VM. On Windows, use Docker Desktop with the WSL2 backend. containd is not a native host firewall for macOS or Windows networking.

## Quickstart

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/quickstart.sh
sh quickstart.sh
```

`quickstart.sh` downloads the starter compose into the current directory, writes `.env` from `.env.example`, generates a real `CONTAIND_JWT_SECRET`, auto-adjusts the starter subnets if they would overlap with existing Docker networks, and starts the stack.

If you want a customized starter directory before first boot, use the advanced bootstrap script instead:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/bootstrap-starter.sh
sh bootstrap-starter.sh --dir containd-lab --no-start
cd containd-lab
# edit .env if needed
docker compose up -d
```

If you cloned the repo locally, you can still use the same starter compose directly:

```bash
cp .env.example .env
# Edit .env if you want custom ports or lab subnets.
docker compose --env-file .env -f deploy/docker-compose.yml up -d
bash scripts/containd-connect
```

Tip: `bash scripts/containd up` wraps `docker compose --env-file .env -f deploy/docker-compose.yml up -d` and prints connection info automatically when a repo-root `.env` exists.

The starter compose enables nftables enforcement by default so a fresh lab behaves like a firewall once you bind zones and commit policy. It also runs the appliance as `root` inside the container because nftables, routing, and TUN operations need that privilege across Linux, Docker Desktop, and WSL-backed lab environments. Set `CONTAIND_ENFORCE_ENABLED=0` only when you intentionally want an observe-only/demo mode.

## Configuration via `.env`

Docker Compose automatically loads `.env` from the same directory as the compose file.

- `.env` is ignored by git (do not commit secrets).
- `.env.example` is the committed template.
- `.env` values seed startup defaults for a fresh appliance. Once `./data` contains a persisted config DB, the saved config remains authoritative until you change it through the UI/API or wipe the data directory.
- If you run `deploy/docker-compose.yml` from the cloned repo root, pass `--env-file .env` so Compose uses the repo-root file instead of looking for `deploy/.env`.

### Common variables

- `CONTAIND_IMAGE`: image tag to run in the starter compose. Defaults to `ghcr.io/tonylturner/containd:latest`.
- `CONTAIND_JWT_SECRET`: JWT signing key for UI/API auth (change for real deployments).
- `CONTAIND_LAB_MODE`: leave at `0` for normal deployments. Set to `1` only for disposable lab/dev auth behavior.
- `CONTAIND_ENFORCE_ENABLED`: starter compose default is `1` so nftables enforcement is active once policy is committed. Set `0` only for observe-only runs.
- `CONTAIND_COOKIE_SECURE`: set to `1` when running behind HTTPS (or a TLS-terminating proxy) to force the `Secure` cookie flag.
- `CONTAIND_TRUSTED_PROXIES`: comma-separated list of proxy IPs/CIDRs you trust for client IP resolution (e.g. `127.0.0.1,::1,10.0.0.0/8`).

### Management ↔ Engine connectivity

The management plane talks to the dataplane engine over the engine’s HTTP API. In combined mode, both run in one container:

- `CONTAIND_MODE`: `all` (default), `mgmt`, or `engine`.
- `CONTAIND_ENGINE_URL`: base URL for the engine API (must include a scheme). In combined `all` mode, containd auto-wires this to `http://127.0.0.1:8081` when it is unset.

If you run split mgmt/engine containers, point `CONTAIND_ENGINE_URL` at the engine host and optionally publish the engine port on the engine container.

### Low ports (DNS / DHCP)

Some appliance services traditionally bind to privileged ports (e.g. DNS on `53/udp,tcp`).

In Docker lab mode, `deploy/docker-compose.yml` grants `CAP_NET_BIND_SERVICE` and runs the appliance as `root` so embedded services can bind low ports and the dataplane can manage nftables, routing, and TUN devices reliably across Docker runtimes.

## Starter topology and interface mapping

The starter compose creates these Docker networks by default:

- `wan`: `192.168.240.0/24` on `eth0` (`192.168.240.2`)
- `dmz`: `192.168.241.0/24` on `eth1` (`192.168.241.2`)
- `lan1`: `192.168.242.0/24` on `eth2` (`192.168.242.2`)
- `lan2`: `192.168.243.0/24` on `eth3` (`192.168.243.2`)
- `lan3`: `192.168.244.0/24` on `eth4` (`192.168.244.2`)
- `lan4`: `192.168.245.0/24` on `eth5` (`192.168.245.2`)
- `lan5`: `192.168.246.0/24` on `eth6` (`192.168.246.2`)
- `lan6`: `192.168.247.0/24` on `eth7` (`192.168.247.2`)

Change the `CONTAIND_*_SUBNET` and `CONTAIND_*_IP` values in `.env` if your lab needs different addressing. The starter compose also marks `dmz` and `lan*` networks as Docker `internal` networks so they do not get accidental host NAT/external reachability by default.

### What Docker owns vs what containd owns

- Docker/Compose owns: which networks exist, which containers attach to them, and the container-level IP layout on those networks.
- containd owns: zone assignment, firewall rules, NAT, services, DPI, routing intent, and segmentation for traffic that is actually routed through the appliance.

If you want a workload to be segmented by containd, attach it to a single zone network and route cross-zone traffic through containd. If you multi-home an application container directly onto multiple zone networks, Docker gives it its own bypass path.

For larger classroom or demo environments, see [Customizing Lab Compose](lab-compose.md).
For Docker Desktop on Windows specifically, see [Windows / WSL Notes](windows-wsl.md).

### Stable interface mapping

When the `engine` service is attached to multiple Docker networks, Docker creates one kernel interface per network.
The kernel device names (`eth0`, `eth1`, …) are not guaranteed to correspond to `wan/dmz/lan1…` in a stable order,
because Docker network attach order can vary.

In this repo’s `deploy/docker-compose.yml`, we explicitly pin:
- `wan` as the default-gateway network (`gw_priority`) so the kernel default route is via WAN.
- stable per-network subnets and IPs so `Interfaces -> Auto-assign` can map `wan/dmz/lan1..lan6` deterministically even on Docker engines that do not support network-level `interface_name`.

To keep the appliance UI/CLI stable in Docker labs, `Interfaces → Auto-assign` prefers matching interface roles by
the IPv4 subnets present on each interface (defaults match this repo’s `deploy/docker-compose.yml`):

- `wan`: `192.168.240.0/24`
- `dmz`: `192.168.241.0/24`
- `lan1..lan6`: `192.168.242.0/24` … `192.168.247.0/24`

If those subnets aren’t present, auto-assign falls back to kernel index ordering.

On newer Docker engines you can optionally use Compose `interface_name` in custom lab files, but the supported starter path avoids depending on it so it works across older GitHub runners and classroom Docker installs.

To override subnet matching (for custom lab topologies), set:
`CONTAIND_AUTO_WAN_SUBNET`, `CONTAIND_AUTO_DMZ_SUBNET`, `CONTAIND_AUTO_LAN1_SUBNET` … `CONTAIND_AUTO_LAN6_SUBNET`.
If you change the starter topology subnets in `.env`, keep these auto-assign hints aligned.

### Ports

- `CONTAIND_PUBLISH_HTTP_PORT`: host port for HTTP UI/API → container `8080`.
- `CONTAIND_PUBLISH_HTTPS_PORT`: host port for HTTPS UI/API → container `8443`.
- `CONTAIND_PUBLISH_SSH_PORT`: host port for SSH → container `2222`.
- `CONTAIND_PUBLISH_ENGINE_PORT`: optional host port for engine API → container `8081` (only if you need external access to engine).

Smoke harness: `deploy/docker-compose.smoke.yml` publishes the engine API on host `18081` to avoid collisions and drives the mgmt API on `18080`.

### Persistent data paths (inside container)

All default DB paths are under `/data` (mounted to `./data` by the starter compose):

- `CONTAIND_CONFIG_DB` (default `/data/config.db`)
- `CONTAIND_AUDIT_DB` (default `/data/audit.db`)
- `CONTAIND_USERS_DB` (default `/data/users.db`)

### SSH bootstrap

To avoid “chicken/egg” provisioning, you can seed an admin SSH key (authorized_keys line):

- `CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY`
- `CONTAIND_SSH_BOOTSTRAP_ADMIN_USER` (default `containd`)

## Troubleshooting

- Validate compose: `docker compose config -q`
- Validate the repo-local starter path: `docker compose --env-file .env -f deploy/docker-compose.yml config -q`
- Follow logs: `docker compose logs -f containd`
- If a save succeeds but the UI shows a warning banner, Docker likely owns the underlying interface or route state. Adjust the topology/IP layout in `.env` or `docker-compose.yml`, then use containd for zones and policy on top of it.
- If interface auto-assign/reconcile fails with `engine interfaces status 400`, check `docker compose logs -f containd` for the underlying runtime error.
- If temporary block actions are unavailable, verify dataplane enforcement is enabled in the config model and that your compose file is passing `CONTAIND_ENFORCE_ENABLED=1`.
- If you see `operation not permitted` for WireGuard, OpenVPN TUN setup, or routing changes, verify the Docker runtime still has the expected capabilities/devices (`NET_ADMIN`, `NET_RAW`, `/dev/net/tun`) and that Windows is using the WSL2-backed Docker Desktop path.
- Factory reset (CLI): `factory reset NUCLEAR` (admin only; wipes config/users/audit and re-seeds defaults)
