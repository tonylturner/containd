# Advisories and CSAF

The [security policy](https://github.com/tonylturner/containd/blob/main/SECURITY.md)
is the canonical source for private vulnerability reporting and coordinated
disclosure. This page indexes published advisories and their machine-readable
artifacts.

## Published advisories

| ID | Issue | Severity | Fixed version |
| --- | --- | --- | --- |
| [containd-2026-001](https://github.com/tonylturner/containd/blob/main/security/csaf/advisories/containd-2026-001.json) | Inherited Debian 12 CVEs in the v0.1.16 management image | HIGH | v0.1.17 (Wolfi migration) or later |

Use the advisory JSON for affected products/versions, remediation, references,
and revision history. A project identifier can exist before a CVE/GHSA is
assigned; use the identifiers actually recorded in each document.

Revision 3 distinguishes management 0.1.16 (affected) from 0.1.17 (fixed).
The engine existed in those releases, but its exact affected package set is not
established by runtime-base provenance alone; the advisory makes no engine
affected/fixed assertion.

## Discovery and downloads

- The appliance serves `/.well-known/security.txt`. Its CSAF entry points to
  the [canonical external metadata URL](https://tonylturner.github.io/containd/.well-known/csaf/provider-metadata.json);
  CSAF metadata and documents are not embedded in the appliance.
- [Advisory sources](https://github.com/tonylturner/containd/tree/main/security/csaf/advisories)
  are versioned in the repository. A GitHub source directory is not an HTTP
  advisory distribution directory.
- [GitHub Releases](https://github.com/tonylturner/containd/releases) attach
  `csaf-documents.tgz`: generated provider metadata, published advisories and
  release VEX for the exact management/engine digests and supported platforms.
  If scans and vendor triage have no statements, no empty VEX is emitted.
  The same archive is included in the `sboms` Actions artifact.

Release VEX combines every scan finding with applicable vendor triage. Untriaged
findings remain `under_investigation`; this does not mean safe or suppressed.
`known_affected` entries include remediation guidance. Only justified
`known_not_affected` vendor statements suppress scanner findings, scoped to a
product and release range. CI requires an advisory marking the release fixed
when its versioned changelog section contains `### Security`.

After stable promotion, the release workflow builds, validates and deploys a directory
from current advisories and all published release VEX archives. It has year
folders, `index.txt`, newest-first `changes.csv`, hashes and browsable listings.
Current source advisory revisions supersede archived copies. The metadata role
is `csaf_publisher`, not a claim of domain-root provider discovery.

The Pages uploader explicitly includes hidden files to preserve `.well-known`.
The maintainer must enable repository Pages with build type **GitHub Actions**
before the canonical URL is served. Release archives remain available separately.

The source format is CSAF 2.0. CI and releases run strict schema and mandatory
CSAF tests using a pinned local validator service. For authoring, triage,
filenames and local validation commands, see the
[CSAF contributor guide](https://github.com/tonylturner/containd/blob/main/security/csaf/README.md).
For applying fixes, see [Update Policy](update-policy.md).
