# containd documentation

Welcome to the containd documentation. This content is rendered in-app (Help icon in the UI) and as a standalone static site.

## Quick links

- **Deploy**: `sh quickstart.sh` -- see [Deploy with Docker Compose](docker-compose.md)
- **Configure**: [CLI Reference](cli.md) (SSH console + in-app console)
- **Core concepts**: [Architecture](architecture.md) and [Dataplane](dataplane.md)
- **ICS/OT**: [ICS DPI](ics-dpi.md) -- protocol decoders, learn/enforce modes, per-protocol configuration
- **Policy**: [Policy Model](policy-model.md) -- zones, predicates, templates

## Additional references

- **API**: An [OpenAPI 3.0 spec](https://github.com/tonylturner/containd/blob/main/docs/openapi.yaml) is available. See [API Reference](api-reference.md) for details and environment variable documentation.
- **Supply chain**: [SBOM](sbom.md) -- software bill of materials, image signing, vulnerability scanning.
- **Licensing**: [Third-Party Licenses](SPDX.md) -- component-level SPDX license tracking.
- **Config reload**: The containd process accepts `SIGHUP` for configuration reload (partial -- not all subsystems reload yet).

## Documentation notes

- Images and diagrams should go under `docs/mkdocs/assets/` and be referenced as `assets/<file>`.
- See [CHANGELOG.md](https://github.com/tonylturner/containd/blob/main/CHANGELOG.md) for release history.
