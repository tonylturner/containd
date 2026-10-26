# Product Documentation

This folder contains user- and operator-facing documentation intended to be rendered by MkDocs (Material theme).

Source of truth: `docs/mkdocs/`

Local build (requires Python + MkDocs):
- `mkdocs build -f docs/mkdocs.yml` from the repository root
- or `mkdocs serve -f docs/mkdocs.yml` for live preview

Start here:
- `architecture.md` – overall planes/modules and how requests flow
- `docker-compose.md` – local appliance bring-up
- `deploy-host.md` – host deployment notes
- `config-format.md` – canonical persisted config schema (JSON)
- `cli.md` – CLI/SSH console conventions and commands
- `dataplane.md` / `dataplane-enforcement.md` – enforcement model and kernel integration
- `services.md` – embedded service configuration (DNS/NTP/DHCP/VPN/AV/proxies)
- `ids-rules.md` / `ics-dpi.md` – IDS + ICS DPI notes
