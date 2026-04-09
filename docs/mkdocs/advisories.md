# Advisories and CSAF

containd publishes security information in both human-readable and machine-readable forms.

## Public Security Process

The public entry points are:

- [`SECURITY.md`](https://github.com/tonylturner/containd/blob/main/SECURITY.md) for disclosure policy and coordinated reporting
- `/.well-known/security.txt` for machine-readable discovery
- `/.well-known/csaf/provider-metadata.json` for CSAF provider metadata
- GitHub Releases for shipped fixes and operator-facing release notes

## Advisory Channels

When containd publishes a security fix, the project aims to keep these channels aligned:

- GitHub release notes and `CHANGELOG.md`
- GitHub Security Advisories when the issue warrants a formal advisory record
- CVE records when appropriate and available
- CSAF JSON documents for machine-readable downstream consumption

The goal is not to create separate narratives. Operators, instructors, and scanners should be able to trace the same issue through the same identifiers and fixed-version guidance.

## CSAF Adoption

containd adopts **CSAF 2.0** for machine-readable vulnerability advisories.

Current project artifacts:

- provider metadata: [`ui/public/.well-known/csaf/provider-metadata.json`](https://github.com/tonylturner/containd/blob/main/ui/public/.well-known/csaf/provider-metadata.json)
- advisory source layout: [`security/csaf/`](https://github.com/tonylturner/containd/tree/main/security/csaf)
- authoring template: [`security/csaf/templates/csaf-v2.0-template.json`](https://github.com/tonylturner/containd/blob/main/security/csaf/templates/csaf-v2.0-template.json)

Current publication state:

- containd publishes CSAF provider metadata and advisory documents
- advisory source: [`security/csaf/advisories/`](https://github.com/tonylturner/containd/tree/main/security/csaf/advisories)
- the release workflow packages the current provider metadata and any published advisory documents from the same release run

### Published Advisories

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [containd-2026-001](https://github.com/tonylturner/containd/blob/main/security/csaf/advisories/containd-2026-001.json) | Inherited Debian 12 CVEs in v0.1.16 container image | HIGH | Resolved in v0.1.17 (Wolfi migration) |

## When containd Publishes a Security Advisory

containd should publish a formal advisory when an issue affects the security expectations of the product, especially for:

- authentication or authorization bypass
- secret disclosure
- remote code execution or arbitrary command execution
- firewall or segmentation bypass
- unsafe config export/import behavior
- TLS, certificate, or session handling weaknesses
- supply-chain vulnerabilities that materially affect shipped images or release artifacts

Not every bug needs a standalone advisory. The threshold is whether operators need explicit security-impact guidance rather than a normal bugfix note.

## Minimum Advisory Content

Each advisory should include:

- a stable advisory identifier such as `GHSA-*`, `CVE-*`, or a temporary project identifier
- affected products and affected versions
- fixed versions
- mitigation or workaround guidance when an immediate upgrade is not possible
- references to the fixing release, commits, and related public records
- CWE or equivalent root-cause classification when practical

## GitHub Security Advisory and CVE Policy

The project intends to use GitHub Security Advisories as the primary hosted advisory record when a vulnerability needs a public coordinated disclosure artifact.

Expected behavior:

- open a GitHub Security Advisory for qualifying issues
- request or link a CVE when the issue merits one
- mirror the same identifiers and fixed versions into the CSAF document
- keep release notes, changelog text, and advisory text consistent

If a CVE is not yet assigned, containd may publish the advisory first and update the advisory and CSAF document once the CVE exists.

## Repository Layout

The repository separates ongoing process from published artifacts:

- [`security/csaf/README.md`](https://github.com/tonylturner/containd/blob/main/security/csaf/README.md) explains the process
- [`security/csaf/advisories/`](https://github.com/tonylturner/containd/tree/main/security/csaf/advisories) is for published advisory JSON and is intentionally empty until the first real advisory exists
- [`security/csaf/templates/`](https://github.com/tonylturner/containd/tree/main/security/csaf/templates) contains authoring skeletons

This keeps the machine-readable advisory process versioned with the codebase instead of being an undocumented afterthought.
