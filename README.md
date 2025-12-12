# containd

`containd` is an open-source next-generation firewall purpose-built for ICS/OT environments. This repository follows the agent specification in `agents.md` and evolves through staged phases.

## Current status

- Phase 0 scaffolding with Go entrypoints for `ngfw-engine` and `ngfw-mgmt`.
- Placeholder Next.js app directory under `ui/` for the upcoming web UI.
- Deployment stubs for container builds and docs placeholders.

## Running the skeleton

```bash
# Management plane API (uses Gin)
go run ./cmd/ngfw-mgmt

# Data plane stub
go run ./cmd/ngfw-engine
```

Health endpoints:

- `http://localhost:8080/api/v1/health` (management)
- `http://localhost:8081/health` (engine)

UI serving:
- `ngfw-mgmt` serves a built UI from `NGFW_UI_DIR` if set, otherwise prefers `ui/out`, then `ui/public`, then `/var/lib/ngfw/ui`.
- During development, run `npm run dev` in `ui/` and access the Next.js dev server directly.

Containers:
- Build appliance image (single container, default): `docker build -f Dockerfile.mgmt -t containd/containd:dev .`
- Build engine-only image: `docker build -f Dockerfile.engine -t containd/containd-engine:dev .`
- Compose (mgmt + engine): `docker compose up --build`
- Publish (example): `docker tag containd/containd:dev ghcr.io/you/containd:dev && docker push ghcr.io/you/containd:dev`

Consume published image:
- `docker run --rm -p 8080:8080 ghcr.io/you/containd:dev`

Next steps: flesh out control plane models, data plane capture/flow tracking, and the full UI/CLI experience per `agents.md`.
