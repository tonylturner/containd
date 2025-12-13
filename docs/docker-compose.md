# Docker Compose

This repo ships a `docker-compose.yml` for running the management plane (`containd`) and engine (`engine`) together, with a `.env`-driven configuration.

## Quickstart

```bash
cp .env.example .env
# Edit .env and set a real CONTAIND_JWT_SECRET
docker compose up -d --build

# Print connection info (UI/HTTPS/SSH + container IPs)
bash scripts/containd-connect
```

## Configuration via `.env`

Docker Compose automatically loads `.env` from the same directory as `docker-compose.yml`.

- `.env` is ignored by git (do not commit secrets).
- `.env.example` is the committed template.

### Common variables

- `CONTAIND_JWT_SECRET`: JWT signing key for UI/API auth (change for real deployments).
- `CONTAIND_COOKIE_SECURE`: set to `1` when running behind HTTPS (or a TLS-terminating proxy) to force the `Secure` cookie flag.
- `CONTAIND_TRUSTED_PROXIES`: comma-separated list of proxy IPs/CIDRs you trust for client IP resolution (e.g. `127.0.0.1,::1,10.0.0.0/8`).

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
- Factory reset (CLI): `factory reset NUCLEAR` (admin only; wipes config/users/audit and re-seeds defaults)

