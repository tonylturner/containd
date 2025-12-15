# containd

`containd` is an open-source next-generation firewall purpose-built for ICS/OT environments. This repository follows the agent specification in `agents.md` and evolves through staged phases. Product/operator docs live under `docs/mkdocs/` and the roadmap is tracked in `docs/tasks.md`.

## Current status

- Phase 0 scaffolding with Go entrypoints for `ngfw-engine` and `ngfw-mgmt`.
- Next.js UI in `ui/` (static export embedded into the appliance image).
- Docker Compose workflow for local appliance bring-up (HTTP+HTTPS UI/API and SSH console).

## Running the skeleton

```bash
# Combined appliance (default)
go run ./cmd/containd all

# Management plane only
go run ./cmd/containd mgmt

# Data plane only
go run ./cmd/containd engine
```

Health endpoints:

- `http://localhost:8080/api/v1/health` (management)
- `http://localhost:8081/health` (engine)

UI serving:
- `ngfw-mgmt` serves a built UI from `NGFW_UI_DIR` if set, otherwise prefers `ui/out`, then `ui/public`, then `/var/lib/ngfw/ui`.
- During development, run `npm run dev` in `ui/` and access the Next.js dev server directly.

Containers:
- Build appliance image (single container, default): `docker build -f Dockerfile.mgmt -t containd/containd:dev .`
- Compose (combined containd) + prints connection info: `bash scripts/containd up --build`
- Publish (example): `docker tag containd/containd:dev ghcr.io/you/containd:dev && docker push ghcr.io/you/containd:dev`

Consume published image:
- `docker run --rm -p 8080:8080 ghcr.io/you/containd:dev`

## Docker Compose quickstart

```bash
cp .env.example .env
# Edit .env and set a real CONTAIND_JWT_SECRET
docker compose up -d --build

# Print connection info (UI/HTTPS/SSH + container IPs)
bash scripts/containd-connect
```

Defaults:
- UI/API: `http://localhost:${CONTAIND_PUBLISH_HTTP_PORT:-8080}` and `https://localhost:${CONTAIND_PUBLISH_HTTPS_PORT:-8443}`
- SSH: `ssh -p ${CONTAIND_PUBLISH_SSH_PORT:-2222} containd@localhost` (password `containd` until you enroll a key)

Next steps: flesh out control plane models, data plane capture/flow tracking, and the full UI/CLI experience per `agents.md`.

## Docs

- `docs/mkdocs/` – operator/product documentation
- `docs/tasks.md` – roadmap/task tracker
