# containd

[![CI](https://github.com/tonylturner/containd/actions/workflows/ci.yml/badge.svg)](https://github.com/tonylturner/containd/actions/workflows/ci.yml)
[![Release](https://github.com/tonylturner/containd/actions/workflows/release.yml/badge.svg)](https://github.com/tonylturner/containd/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/tonylturner/containd?logo=github&label=release)](https://github.com/tonylturner/containd/releases)
[![GHCR](https://ghcr-badge.egpl.dev/tonylturner/containd/latest_tag?ignore=sha256*,latest&label=ghcr.io)](https://github.com/tonylturner/containd/pkgs/container/containd)
[![Trivy](https://img.shields.io/github/actions/workflow/status/tonylturner/containd/published-trivy.yml?branch=main&label=Trivy&logo=trivy)](https://github.com/tonylturner/containd/actions/workflows/published-trivy.yml)
[![Cosign](https://img.shields.io/github/actions/workflow/status/tonylturner/containd/published-cosign.yml?branch=main&label=signed%3A%20Cosign)](https://github.com/tonylturner/containd/actions/workflows/published-cosign.yml)
[![SBOM](https://img.shields.io/github/actions/workflow/status/tonylturner/containd/published-sbom.yml?branch=main&label=SBOM%3A%20CycloneDX&logo=owasp)](https://github.com/tonylturner/containd/actions/workflows/published-sbom.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/tonylturner/containd?logo=go)](https://go.dev/doc/devel/release)
[![License](https://img.shields.io/github/license/tonylturner/containd)](LICENSE)
[![OT Segmentation](https://img.shields.io/badge/topic-OT%20Segmentation-orange)](https://github.com/topics/ot-segmentation)
[![Secure by Design](https://img.shields.io/badge/Secure%20by%20Design-CISA-blue)](https://www.cisa.gov/securebydesign)

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

The bootstrap login is **`containd` / `containd`**. Outside lab mode, the first
web or SSH login must change it; leave lab mode disabled for normal use. SSH
password login asks for a TOTP code on MFA accounts, and its PTY can reach the
appliance's Linux shell. Read the [authentication limits](SECURITY.md#authentication-limits).

HTTPS uses a generated self-signed certificate unless you supply a replacement.
See [hardening guidance](docs/mkdocs/secure-by-design.md#deployment-hardening) before remote access.

After login, create zones, bind interfaces, and define firewall policy.
Review the candidate diff and commit it to apply runtime changes. The
[configuration lifecycle](docs/mkdocs/config-format.md) describes staging,
commit-confirmed and rollback.

## Capabilities

- Zone-based nftables firewalling and SNAT/DNAT: [policy model](docs/mkdocs/policy-model.md).
  containd changes only its own tables (`inet containd`, `inet containd_policy`,
  `inet containd_dhcp`) and leaves other rules, such as Docker's DNS, alone.
- ICS protocol inspection, including IEC 60870-5-104: [ICS DPI](docs/mkdocs/ics-dpi.md).
- DNS- and TLS SNI-based [DPI domain exclusions](docs/mkdocs/ics-dpi.md#dpi-exclusions).
- Candidate/running configuration with commit-confirmed and rollback: [config format](docs/mkdocs/config-format.md).
- Web, SSH and REST management with embedded network services: [services](docs/mkdocs/services.md).
- Live kernel connections with timed kill, and ClamAV or ICAP scanning of inspected HTTP content: [services](docs/mkdocs/services.md).

See [architecture](docs/mkdocs/architecture.md) for the management, control and data planes.

## Documentation

Documentation is available from the appliance's **Help** icon and in the
[documentation home](docs/mkdocs/index.md).

- Deploy: [Docker Compose](docs/mkdocs/docker-compose.md), [custom labs](docs/mkdocs/lab-compose.md), [Windows / WSL](docs/mkdocs/windows-wsl.md).
- Configure: [CLI](docs/mkdocs/cli.md), [configuration JSON](docs/mkdocs/config-format.md), [API reference](docs/mkdocs/api-reference.md), [OpenAPI contract](docs/openapi.yaml).
- Inspect and enforce: [ICS DPI](docs/mkdocs/ics-dpi.md), [IDS rules](docs/mkdocs/ids-rules.md), [dataplane enforcement](docs/mkdocs/dataplane-enforcement.md).
- Operate safely: [hardening](docs/mkdocs/secure-by-design.md#deployment-hardening), [threat model](docs/mkdocs/threat-model.md), [updates](docs/mkdocs/update-policy.md), [advisories](docs/mkdocs/advisories.md).
- Verify artifacts: [SBOM and image signatures](docs/mkdocs/sbom.md). CI includes vulnerability scanning; results depend on the image and scan date.

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) for source builds, tests and documentation
changes, and the [Code of Conduct](CODE_OF_CONDUCT.md) for community expectations.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in public issues.

Licensed under [Apache License 2.0](LICENSE).
