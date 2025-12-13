# Host Deployment

This document is rendered from `docs/mkdocs/`.

Outlines installation and systemd service setup for running `ngfw-engine` and `ngfw-mgmt` on a host. To be completed in future phases.

Container builds:
- Appliance Dockerfile: `Dockerfile.mgmt` at repo root (builds single image).
- Optional engine-only Dockerfile: `Dockerfile.engine` at repo root.
- Compose: `docker-compose.yml` at repo root for single-container appliance.
- The previous `deploy/` directory was removed; all packaging assets live at repo root.

Registry publishing (recommended workflow):
- Tag the appliance image to your registry: `docker tag containd/containd:dev ghcr.io/you/containd:dev`
- Push: `docker push ghcr.io/you/containd:dev`
- Consume elsewhere with a single image reference: `docker run --rm -p 8080:8080 ghcr.io/you/containd:dev`

Runtime notes:
- Configuration DB path defaults to `data/config.db` (override `NGFW_CONFIG_DB`).
- HTTP API on `NGFW_MGMT_ADDR` (default `:8080`) exposes `/api/v1/*` for config/syslog/etc.
