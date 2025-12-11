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

Next steps: flesh out control plane models, data plane capture/flow tracking, and the full UI/CLI experience per `agents.md`.
