# containd

An open-source next-generation firewall purpose-built for ICS/OT environments.

containd is a single-image appliance that combines zone-based firewalling, ICS protocol inspection, embedded network services, and a full management UI into one deployable container. It is designed for industrial control system operators who need OT-aware security without cobbling together dozens of point tools.

## Key Features

- **Zone-based firewall** with nftables enforcement, NAT (SNAT + DNAT), and default-deny posture
- **ICS/OT protocol inspection** — Modbus/TCP deep packet inspection with function code and register-level visibility
- **IT protocol DPI** — DNS, TLS (SNI/JA3), HTTP/2, SSH, RDP, SMB, SNMP, NTP
- **Native IDS** with Sigma-compatible rule evaluation across DPI events
- **Embedded services** — DNS resolver (Unbound), NTP (OpenNTPD), DHCP server, forward proxy (Envoy), reverse proxy (Nginx)
- **VPN** — WireGuard and OpenVPN with managed config, PKI, and client profiles
- **Antivirus** — ICAP pipeline with optional embedded ClamAV
- **Config lifecycle** — candidate/running configs, diff, commit, commit-confirmed with auto-rollback, deterministic JSON export/import
- **Management UI** — dashboard, topology, firewall rules, routing, NAT, services, monitoring, diagnostics, audit log, and in-browser CLI console
- **SSH console** — full CLI shell with `show`, `set`, `diag` commands, setup wizard, and diagnostics
- **Syslog forwarding** — UDP/TCP, RFC 5424 or JSON, with retry and backoff

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/containd/containd.git
cd containd
cp .env.example .env
# Edit .env — at minimum, set CONTAIND_JWT_SECRET to a unique value
docker compose up -d --build
```

Once running:

| Service | URL |
|---------|-----|
| Web UI / API | `http://localhost:8080` |
| HTTPS | `https://localhost:8443` |
| SSH console | `ssh -p 2222 containd@localhost` |

Default admin credentials: `containd` / `containd` — change these on first login.

Print full connection details:

```bash
bash scripts/containd-connect
```

### Standalone Container

```bash
docker run -d \
  --name containd \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 8080:8080 -p 8443:8443 -p 2222:2222 \
  -v containd-data:/data \
  -e CONTAIND_JWT_SECRET=your-secret-here \
  containd/containd:latest
```

### From Source

```bash
# Build the Go binary
go build -o containd ./cmd/containd

# Build the UI (static export)
cd ui && npm ci && npm run build && cd ..

# Run the combined appliance
CONTAIND_UI_DIR=ui/out ./containd all
```

## Architecture

containd runs as a single Go binary with three logical planes:

- **Data plane** — nftables/conntrack enforcement, packet capture, flow tracking, DPI/IDS, verdict engine
- **Control plane** — SQLite persistence, config lifecycle, policy compilation, service management (DNS/NTP/DHCP/VPN/AV/proxies), audit
- **Management plane** — REST API, web UI, SSH console, authentication/RBAC

The binary supports three modes: `containd all` (default, combined appliance), `containd mgmt` (management only), and `containd engine` (data plane only).

## Docker Compose Lab Topology

The included `docker-compose.yml` creates a lab environment with 8 isolated networks representing firewall ports:

| Network | Subnet | Interface |
|---------|--------|-----------|
| WAN | 192.168.240.0/24 | eth0 |
| DMZ | 192.168.241.0/24 | eth1 |
| LAN1 | 192.168.242.0/24 | eth2 |
| LAN2–LAN6 | 192.168.243–247.0/24 | eth3–eth7 |

Default zones: `wan`, `dmz`, `mgmt` (lan1), `lan` (lan2–lan6).

## Configuration

All runtime configuration is managed through the UI, CLI, or REST API and persisted in SQLite. No direct file editing required.

```bash
# CLI examples (via SSH or in-app console)
show interfaces
show zones
show firewall rules
set zone lan interface lan2
set firewall rule allow --src-zone lan --dst-zone wan --action allow
commit
```

Config can be exported and imported as deterministic JSON:

```bash
export config > backup.json
import config < backup.json
```

## Documentation

Full product documentation is embedded in the appliance (accessible via the Help icon in the UI) and built from `docs/mkdocs/`:

- [Architecture](docs/mkdocs/architecture.md)
- [Docker Compose Deployment](docs/mkdocs/docker-compose.md)
- [CLI Reference](docs/mkdocs/cli.md)
- [Configuration Format](docs/mkdocs/config-format.md)
- [Services](docs/mkdocs/services.md)
- [Dataplane & Enforcement](docs/mkdocs/dataplane.md)
- [ICS/DPI](docs/mkdocs/ics-dpi.md)
- [IDS Rules](docs/mkdocs/ids-rules.md)
- [Third-Party Licenses](docs/mkdocs/SPDX.md)

## Security

- Default-deny firewall posture out of the box.
- Distroless container image running as nonroot.
- JWT-based auth with session invalidation; admin and view-only roles.
- HTTPS with auto-generated self-signed certificate; custom cert install supported.
- SSH key auth supported; password auth for lab use.

For production hardening guidance and vulnerability reporting, see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
