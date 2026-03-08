# containd documentation

Welcome. This documentation is meant to be rendered in-app (Help icon) and as a standalone static site.

## Quick links

- Deploy: `docker-compose up -d` (see **Deploy with Docker Compose**)
- Configure: **CLI** (SSH console + in-app console)
- Core concepts: **Architecture** and **Dataplane**

## Additional references

- **API**: An [OpenAPI 3.0 spec](https://github.com/tonylturner/containd/blob/main/docs/openapi.yaml) is available. See [API Reference](api-reference.md) for details and environment variable documentation.
- **Config reload**: The containd process supports `SIGHUP` for live configuration reload without downtime.

## Documentation notes

- Images and diagrams should go under `docs/mkdocs/assets/` and be referenced as `assets/<file>`.
- See [CHANGELOG.md](https://github.com/tonylturner/containd/blob/main/CHANGELOG.md) for release history.
