# Advisories and CSAF

The [security policy](https://github.com/tonylturner/containd/blob/main/SECURITY.md)
is the canonical source for private vulnerability reporting and coordinated
disclosure. This page indexes published advisories and their machine-readable
artifacts.

## Published advisories

| ID | Issue | Severity | Fixed version |
| --- | --- | --- | --- |
| [containd-2026-001](https://github.com/tonylturner/containd/blob/main/security/csaf/advisories/containd-2026-001.json) | Inherited Debian 12 CVEs in the v0.1.16 container image | HIGH | v0.1.17 (Wolfi migration) or later |

Use the advisory JSON for affected products/versions, remediation, references,
and revision history. A project identifier can exist before a CVE/GHSA is
assigned; use the identifiers actually recorded in each document.

## Discovery and downloads

- The appliance serves `/.well-known/security.txt` and CSAF provider metadata at
  `/.well-known/csaf/provider-metadata.json`.
- [Advisory JSON source](https://github.com/tonylturner/containd/tree/main/security/csaf/advisories)
  is versioned in the repository. A GitHub source directory is not an appliance
  HTTP advisory directory.
- [GitHub Releases](https://github.com/tonylturner/containd/releases) attach
  `csaf-documents.tgz`, containing provider metadata and published advisory JSON
  from that release. The release workflow also includes it in the `sboms`
  Actions artifact.

The source format is CSAF 2.0. For authoring, naming, and validation expectations,
see the [CSAF contributor guide](https://github.com/tonylturner/containd/blob/main/security/csaf/README.md).
For applying fixes, see [Update Policy](update-policy.md).
