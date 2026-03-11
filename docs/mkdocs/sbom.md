# Software Bill of Materials (SBOM)

containd generates and publishes a Software Bill of Materials for every release. SBOMs provide a machine-readable inventory of all components, libraries, and dependencies packaged in the container images.

## Format and Standard

- **Format**: CycloneDX JSON (`cyclonedx-json`)
- **Version**: CycloneDX 1.6 (latest stable, as produced by Syft)
- **Generator**: [Anchore Syft](https://github.com/anchore/syft) via the `anchore/sbom-action` GitHub Action
- **Standard**: [CycloneDX](https://cyclonedx.org/) -- an OWASP standard for software supply chain component analysis

CycloneDX was chosen over SPDX for its richer vulnerability correlation support (VEX), broader tooling ecosystem, and first-class support in dependency-track, Grype, and other supply chain security tools.

## What the SBOM Covers

Each release produces two SBOMs:

| Image | SBOM Artifact | Description |
|-------|---------------|-------------|
| `ghcr.io/tonylturner/containd` | `sbom-mgmt.cdx.json` | Management appliance (Go binary, UI, embedded services, base image) |
| `ghcr.io/tonylturner/containd-engine` | `sbom-engine.cdx.json` | Data plane engine (Go binary, nftables, base image) |

The SBOMs enumerate:

- Go modules compiled into the `containd` binary (from `go.mod`)
- npm packages included in the UI static export (from `package-lock.json`)
- OS packages from the base image (Distroless Debian 12)
- Embedded service binaries (Envoy, Nginx, Unbound, ClamAV, etc.)

## How SBOMs Are Published

SBOMs are generated and attached as part of the [release workflow](https://github.com/tonylturner/containd/actions/workflows/release.yml):

1. Container images are built and pushed to GHCR.
2. Images are signed with [Cosign](https://github.com/sigstore/cosign) (keyless, GitHub OIDC).
3. Syft generates CycloneDX JSON SBOMs for each image.
4. SBOMs are attached to the signed images via `cosign attach sbom`.
5. SBOMs are uploaded as GitHub Actions artifacts for each release.

## Retrieving an SBOM

### From the container image (via Cosign)

```bash
# Install cosign
brew install cosign  # or see https://github.com/sigstore/cosign#installation

# Download the attached SBOM
cosign download sbom ghcr.io/tonylturner/containd:latest > sbom-mgmt.cdx.json
cosign download sbom ghcr.io/tonylturner/containd-engine:latest > sbom-engine.cdx.json
```

### From GitHub Actions artifacts

Navigate to the [Releases](https://github.com/tonylturner/containd/actions/workflows/release.yml) workflow and download the `sboms` artifact from any release run.

### Generate locally with Syft

```bash
# Scan the local image
syft ghcr.io/tonylturner/containd:latest -o cyclonedx-json > sbom-local.cdx.json
```

### Analyze with OWASP Dependency-Track

CycloneDX SBOMs can be imported directly into [Dependency-Track](https://dependencytrack.org/) for continuous vulnerability monitoring:

```bash
# Upload to Dependency-Track API
curl -X POST https://dtrack.example.com/api/v1/bom \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "project=$PROJECT_UUID" \
  -F "bom=@sbom-mgmt.cdx.json"
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

You can also use [Grype](https://github.com/anchore/grype) directly against the CycloneDX SBOM:

```bash
grype sbom:sbom-mgmt.cdx.json
```

## Related

- [Third-Party Licenses (SPDX)](SPDX.md) -- manual component-level license tracking
- [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) -- vulnerability reporting
