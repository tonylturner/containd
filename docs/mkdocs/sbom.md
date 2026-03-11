# Software Bill of Materials (SBOM)

containd generates and publishes a Software Bill of Materials for every release. SBOMs provide a machine-readable inventory of all components, libraries, and dependencies packaged in the container images.

## Format and Standard

- **Format**: SPDX JSON (`spdx-json`)
- **Generator**: [Anchore Syft](https://github.com/anchore/syft) via the `anchore/sbom-action` GitHub Action
- **Standard**: [SPDX 2.3](https://spdx.dev/specifications/v2.3/) -- an ISO/IEC 5962:2021 international standard

## What the SBOM Covers

Each release produces two SBOMs:

| Image | SBOM Artifact | Description |
|-------|---------------|-------------|
| `ghcr.io/tonylturner/containd` | `sbom-mgmt.spdx.json` | Management appliance (Go binary, UI, embedded services, base image) |
| `ghcr.io/tonylturner/containd-engine` | `sbom-engine.spdx.json` | Data plane engine (Go binary, nftables, base image) |

The SBOMs enumerate:

- Go modules compiled into the `containd` binary (from `go.mod`)
- npm packages included in the UI static export (from `package-lock.json`)
- OS packages from the base image (Distroless Debian 12)
- Embedded service binaries (Envoy, Nginx, Unbound, ClamAV, etc.)

## How SBOMs Are Published

SBOMs are generated and attached as part of the [release workflow](https://github.com/tonylturner/containd/actions/workflows/release.yml):

1. Container images are built and pushed to GHCR.
2. Images are signed with [Cosign](https://github.com/sigstore/cosign) (keyless, GitHub OIDC).
3. Syft generates SPDX JSON SBOMs for each image.
4. SBOMs are attached to the signed images via `cosign attach sbom`.
5. SBOMs are uploaded as GitHub Actions artifacts for each release.

## Retrieving an SBOM

### From the container image (via Cosign)

```bash
# Install cosign
brew install cosign  # or see https://github.com/sigstore/cosign#installation

# Download the attached SBOM
cosign download sbom ghcr.io/tonylturner/containd:latest > sbom-mgmt.spdx.json
cosign download sbom ghcr.io/tonylturner/containd-engine:latest > sbom-engine.spdx.json
```

### From GitHub Actions artifacts

Navigate to the [Releases](https://github.com/tonylturner/containd/actions/workflows/release.yml) workflow and download the `sboms` artifact from any release run.

### Generate locally with Syft

```bash
# Scan the local image
syft ghcr.io/tonylturner/containd:latest -o spdx-json > sbom-local.spdx.json
```

## Verifying Image Signatures

Released images are signed with Cosign keyless signing (GitHub OIDC). Verify with:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/tonylturner/containd" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/tonylturner/containd:latest
```

## Vulnerability Scanning

Every CI build runs [Trivy](https://github.com/aquasecurity/trivy) against the container image with `--severity HIGH,CRITICAL --exit-code 1`. The build fails if any HIGH or CRITICAL vulnerabilities are found.

You can scan locally:

```bash
trivy image ghcr.io/tonylturner/containd:latest
```

## Related

- [Third-Party Licenses (SPDX)](SPDX.md) -- manual component-level license tracking
- [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) -- vulnerability reporting
