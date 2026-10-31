# Software Bill of Materials (SBOM)

containd generates and publishes a Software Bill of Materials for every release. SBOMs inventory components detected by the scanner in the final container images; their presence does not prove every dependency was identified.

## Format and Standard

- **Format**: CycloneDX JSON (`cyclonedx-json`)
- **Schema version**: inspect the artifact's `specVersion`; the workflow requests CycloneDX JSON without pinning a schema version
- **Generator**: [Anchore Syft](https://github.com/anchore/syft) via the `anchore/sbom-action` GitHub Action, supplemented with the management UI's production npm lockfile inventory
- **Standard**: [CycloneDX](https://cyclonedx.org/) -- an OWASP standard for software supply chain component analysis

## What the SBOM Covers

Each release produces two SBOMs:

| Image | SBOM Artifact | Description |
|-------|---------------|-------------|
| `ghcr.io/tonylturner/containd` | `sbom-mgmt.cdx.json` | Management appliance (Go binary, UI, embedded services, base image) |
| `ghcr.io/tonylturner/containd-engine` | `sbom-engine.cdx.json` | Data plane engine (Go binary, nftables, base image) |

Syft scans the final images for Go modules, Wolfi OS packages, and embedded
service binaries. The management image contains the UI's static export, not the
build-stage npm dependency tree. Its SBOM also includes versioned production
packages from `ui/package-lock.json` (including transitive and optional packages,
excluding dev-only entries). These components carry a `containd:inventory-source`
property identifying their lockfile entry. This is a conservative inventory of
the UI's production dependencies, not proof that every package or file survives
bundling. The release checks that `next` and `react` are present before signing.

## How SBOMs Are Published

SBOMs are generated and signed as part of the [release workflow](https://github.com/tonylturner/containd/actions/workflows/release.yml):

1. The release version and matching `v`-prefixed tag are validated as `MAJOR.MINOR.PATCH[-prerelease]` before container images are built and pushed to GHCR. Reserved channels such as `latest` cannot be built as release versions.
2. Images are signed with [Cosign](https://github.com/sigstore/cosign) (keyless, GitHub OIDC).
3. Syft generates CycloneDX JSON SBOMs for each image; the management SBOM merges the production npm inventory.
4. Each SBOM is signed with `cosign attest --type cyclonedx`, bound to its immutable image digest using the release workflow's GitHub OIDC identity.
5. SBOMs are attached as GitHub Release assets and uploaded in the `sboms` GitHub Actions artifact.

Only then can a stable tag whose commit is an ancestor of `origin/main` promote both images' `:latest` tags to the signed digests. It must be at least the highest stable semantic-version tag reachable from `origin/main`; older tags and prereleases do not move `:latest`. Both tag pushes and manual promotion also require successful **CI** from a push to main for the exact peeled commit, using the newest matching run's latest attempt. A manual **Release** workflow run with its `tag` input verifies existing image signatures and signed SBOM attestations without rebuilding. Both push and dispatch promotion bind image and attestation verification to the exact peeled commit using Cosign's `--certificate-github-workflow-sha`, in addition to the tag-specific workflow identity and GitHub OIDC issuer. Missing or unverifiable attestations block promotion. See [Update Policy](update-policy.md#when-latest-moves) for the CI wait, refusal and retry behavior.

## Retrieving an SBOM

### From the container image (via Cosign)

```bash
# Install cosign
brew install cosign  # or see https://github.com/sigstore/cosign#installation

# Download signed envelopes for inspection, using an immutable release reference.
# Downloading alone does NOT verify their signatures.
cosign download attestation --predicate-type cyclonedx "$IMAGE_REF" > attestations.jsonl
```

Use the verification commands below before extracting a trusted SBOM.

### From GitHub Releases or Actions

Prefer the versioned [GitHub Release assets](https://github.com/tonylturner/containd/releases):
`sbom-mgmt.cdx.json` and `sbom-engine.cdx.json`. The matching `release-images.txt`
records version-tagged image names and their immutable digests. The [Release workflow](https://github.com/tonylturner/containd/actions/workflows/release.yml)
also uploads these in its `sboms` Actions artifact, subject to artifact retention.

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

## Verifying Image Signatures and SBOM Attestations

Released images use Cosign keyless signing. Match the release workflow's trust
policy: exact workflow identity **at the release tag**, GitHub OIDC issuer,
peeled tag commit, and an immutable image digest. Do not verify a mutable
`:latest` reference against a broad repository-prefix identity regex.

In a trusted source checkout with the intended release tag fetched, set
`RELEASE_TAG` to that tag (for example `v0.1.34`) and `IMAGE_REF` to the matching
`ghcr.io/tonylturner/containd@sha256:...` reference constructed with its
`mgmt_digest` from `release-images.txt`:

```bash
set -euo pipefail
: "${RELEASE_TAG:?set the intended release tag}"
: "${IMAGE_REF:?set the immutable image reference from release-images.txt}"
[[ "$IMAGE_REF" =~ ^ghcr.io/tonylturner/containd(-engine)?@sha256:[a-f0-9]{64}$ ]]
RELEASE_COMMIT="$(git rev-parse --verify "${RELEASE_TAG}^{commit}")"
cosign verify \
  --certificate-identity "https://github.com/tonylturner/containd/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-sha "$RELEASE_COMMIT" \
  "$IMAGE_REF"
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/tonylturner/containd/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-sha "$RELEASE_COMMIT" \
  "$IMAGE_REF" > verified-attestations.jsonl
# Decode only the verified envelope payload; the predicate is the CycloneDX SBOM.
jq -s 'map(.payload | @base64d | fromjson | .predicate)
  | if length == 1 then .[0] else error("expected one SBOM; inspect verified predicates") end' \
  verified-attestations.jsonl > sbom-verified.cdx.json
```

Repeat with the engine digest if deploying the split engine image. Obtain tags
and release metadata from a source you trust; a digest alone does not identify
the intended release. See [Update Policy](update-policy.md) for the surrounding
backup, deployment, and post-update checks.

## Vulnerability Scanning

The CI Trivy job scans the built management image (`containd/containd:ci`) with `--severity HIGH,CRITICAL --exit-code 1` and the repository `.trivyignore`. Unsuppressed findings fail that job. This does not assert that both images or every workflow run are scanned, nor that a passing scan proves an absence of vulnerabilities.

The [scheduled image scan](#scheduled-checks-of-published-images) covers both published images.

You can scan locally:

```bash
trivy image ghcr.io/tonylturner/containd:latest
```

You can also use [Grype](https://github.com/anchore/grype) directly against the CycloneDX SBOM:

```bash
grype sbom:sbom-mgmt.cdx.json
```

## Scheduled Checks of Published Images

Three workflows check the published `:latest` management and engine images
daily, after each successful Release run, and on demand. Each one backs a README
badge:

| Workflow | Check |
|----------|-------|
| [Published image signatures](https://github.com/tonylturner/containd/actions/workflows/published-cosign.yml) | Cosign keyless signature from the release workflow at the image's release tag and its commit |
| [Published image SBOMs](https://github.com/tonylturner/containd/actions/workflows/published-sbom.yml) | Signed CycloneDX SBOM attestation under the same identity |
| [Published image scan](https://github.com/tonylturner/containd/actions/workflows/published-trivy.yml) | Trivy scan of every platform image, with the CI severity policy and `.trivyignore` |

The signature and SBOM checks also require both images to come from the same
release, and that release's version tag to resolve to the `:latest` digest.
Run the same checks locally with Docker, git and jq:

```bash
bash scripts/verify-published-images.sh signature
bash scripts/verify-published-images.sh sbom
bash scripts/verify-published-images.sh vulnerabilities
```

## Related

- [Third-Party Licenses (SPDX)](SPDX.md) -- manual component-level license tracking
- [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) -- vulnerability reporting
