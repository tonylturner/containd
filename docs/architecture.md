# containd Architecture

This document tracks the high-level architecture for containd as it evolves. It mirrors the agent spec and will be expanded as components land.

- Planes: data plane (`ngfw-engine`), control plane (`pkg/cp`), management plane (`ngfw-mgmt` + UI + CLI).
- Packaging targets: containers for lab, host systemd services, future Kubernetes workloads.
- Docker build assets live at repo root (`Dockerfile.engine`, `Dockerfile.mgmt`); compose file for single-container appliance lives at `docker-compose.yml`. The `deploy/` directory was removed in favor of root-level assets and a single-container workflow.
- Control-plane HTTP server lives under `api/http` and exposes `/api/v1` endpoints (health, config load/save/validate) backed by the SQLite config store in `pkg/cp/config`.

Further details will be refined as we implement each phase.
