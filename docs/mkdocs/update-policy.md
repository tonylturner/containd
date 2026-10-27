# Update Policy

## Supported releases

- The **latest stable release** is the primary supported line.
- Prereleases such as `-beta` tags are for evaluation, not long-term support.
- Do not assume security backports for older releases unless release notes or
  an advisory explicitly state otherwise.

## Release artifacts and security information

Releases include signed images, SBOMs, image digests, and packaged CSAF provider
metadata and published advisory JSON. Read GitHub Releases and the
[Changelog](https://github.com/tonylturner/containd/blob/main/CHANGELOG.md) for
changes. See [Advisories](advisories.md) for machine-readable security information
and [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) for
disclosure and reporting.

## Operator update checklist

1. Read release notes and linked advisories; identify whether management, engine,
   or both images are affected.
2. Export config and securely preserve the persistent `/data` volume, including
   users, audit/event data, and service files needed for rollback. See
   [Compose data locations](docker-compose.md#persistent-data-paths-inside-container).
3. Choose a version tag or digest. Verify image signatures and signed
   [SBOM attestations](sbom.md#verifying-image-signatures-and-sbom-attestations)
   according to your deployment policy.
4. Update deployment image references, pull the images, and recreate the appliance.
   For split mode, update the affected processes together as required by release notes.
5. Verify `/api/v1/health`, `/metrics`, login, cross-zone enforcement, and key
   services. Keep the backup until the deployment is verified.

### When `:latest` moves

`:latest` points to signed, SBOM-attested **stable** images whose tagged commit
is in main's history. Version-tagged images can exist before they are eligible
for that channel. Prereleases and commits outside main's history do not move it.
The release tag must be at least the highest stable semantic-version `v*` tag
reachable from `origin/main`. Promotion refuses older tags, including manual
requests, and records the reason in the workflow summary.
Both management and engine tags are promoted to their signed digests only after
image signature and CycloneDX attestation verification succeed with the exact
release-tag workflow identity, GitHub OIDC issuer, and peeled release commit.
Missing or unsigned SBOM evidence cannot pass these checks.

Pin a version tag or digest for repeatable deployments rather than relying on the
moving `:latest` channel. Pin digests when you require an exact image identity.

## Classroom guidance

Keep a class on the same known image versions. Schedule upgrades deliberately
and verify the exercise's policy and workload paths before students use them.
