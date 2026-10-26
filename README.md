# containd

[![CI](https://github.com/tonylturner/containd/actions/workflows/ci.yml/badge.svg)](https://github.com/tonylturner/containd/actions/workflows/ci.yml)
[![Release](https://github.com/tonylturner/containd/actions/workflows/release.yml/badge.svg)](https://github.com/tonylturner/containd/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

containd is a single-container appliance for ICS/OT lab segmentation.
It combines zone-based firewalling, protocol inspection, network services,
and web, SSH and API management around one configuration model.

It serves lab operators, instructors and integrators routing traffic between
Docker networks. Docker Compose owns network attachment and IP layout;
containd applies policy to traffic routed through the appliance.
It is not a native macOS or Windows host firewall.

## Quickstart

Use Docker with modern Docker Compose on Linux or Docker Desktop.
On Windows, use Docker Desktop's WSL2 backend. Run in a dedicated lab directory:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/quickstart.sh
sh quickstart.sh
```

The script delegates to `scripts/bootstrap-starter.sh`: it downloads the starter
Compose file, writes `.env`, generates a non-empty `CONTAIND_JWT_SECRET`, adjusts
conflicting starter subnets and starts the combined appliance (`containd all`).
Secret generation requires OpenSSL or Python 3.

To edit ports or networks before starting, use the
[customize-before-start flow](docs/mkdocs/docker-compose.md#quickstart)
with `bootstrap-starter.sh --no-start`.

**Published management ports are not a private network boundary.** Restrict
host/network access before starting; do not expose bootstrap credentials to
untrusted networks. See [deployment guidance](docs/mkdocs/docker-compose.md).

## Connect and configure

| Service | Default endpoint |
| --- | --- |
| Web UI / API | `http://localhost:8080` |
| HTTPS | `https://localhost:8443` |
| SSH console | Port `2222`, user `containd` |

The bootstrap login is **`containd` / `containd`**. Change the password immediately
through the web UI or management API; leave lab mode disabled for normal use.
SSH does **not** enforce MFA or a forced password change, and its PTY can reach
the appliance's Linux shell. Read the [authentication limits](SECURITY.md#authentication-limits).

HTTPS uses a generated self-signed certificate unless you supply a replacement.
See [hardening guidance](docs/mkdocs/secure-by-design.md) before remote access.

After login, create zones, bind interfaces, and define firewall policy.
Review the candidate diff and commit it to apply runtime changes. The
[configuration lifecycle](docs/mkdocs/config-format.md) describes staging,
commit-confirmed and rollback.

## Capabilities

- Zone-based nftables firewalling and SNAT/DNAT: [policy model](docs/mkdocs/policy-model.md).
- ICS protocol inspection, including IEC 60870-5-104: [ICS DPI](docs/mkdocs/ics-dpi.md).
- Candidate/running configuration with commit-confirmed and rollback: [config format](docs/mkdocs/config-format.md).
- Web, SSH and REST management with embedded network services: [services](docs/mkdocs/services.md).

See [architecture](docs/mkdocs/architecture.md) for the management, control and data planes.

## Documentation

Documentation is available from the appliance's **Help** icon and in the
[documentation home](docs/mkdocs/index.md).

- Deploy: [Docker Compose](docs/mkdocs/docker-compose.md), [custom labs](docs/mkdocs/lab-compose.md), [Windows / WSL](docs/mkdocs/windows-wsl.md).
- Configure: [CLI](docs/mkdocs/cli.md), [configuration JSON](docs/mkdocs/config-format.md), [API reference](docs/mkdocs/api-reference.md), [OpenAPI contract](docs/openapi.yaml).
- Inspect and enforce: [ICS DPI](docs/mkdocs/ics-dpi.md), [IDS rules](docs/mkdocs/ids-rules.md), [dataplane enforcement](docs/mkdocs/dataplane-enforcement.md).
- Operate safely: [hardening](docs/mkdocs/secure-by-design.md), [threat model](docs/mkdocs/threat-model.md), [updates](docs/mkdocs/update-policy.md), [advisories](docs/mkdocs/advisories.md).
- Verify artifacts: [SBOM and image signatures](docs/mkdocs/sbom.md). CI includes vulnerability scanning; results depend on the image and scan date.

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) for source builds, tests and documentation
changes, and the [Code of Conduct](CODE_OF_CONDUCT.md) for community expectations.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in public issues.

Licensed under [Apache License 2.0](LICENSE).
