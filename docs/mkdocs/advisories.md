# Advisories and CSAF

The [security policy](https://github.com/tonylturner/containd/blob/main/SECURITY.md)
is the canonical source for private vulnerability reporting and coordinated
disclosure. This page indexes published advisories and their machine-readable
artifacts.

## Published advisories

| ID | Issue | Severity | Fixed version |
| --- | --- | --- | --- |
| [containd-2026-001](https://github.com/tonylturner/containd/blob/main/security/csaf/advisories/containd-2026-001.json) | Inherited Debian 12 CVEs in the v0.1.16 management image | HIGH | v0.1.17 (Wolfi migration) or later |
| [containd-2026-002](https://github.com/tonylturner/containd/blob/main/security/csaf/advisories/containd-2026-002.json) | Forged audit and lab review actors through X-User in management lab/static-token sessions | LOW (CVSS 3.1: 2.7) | v0.1.42 |

Use the advisory JSON for affected products/versions, remediation, references,
and revision history. A project identifier can exist before a CVE/GHSA is
assigned; use the identifiers actually recorded in each document.

Revision 3 distinguishes management 0.1.16 (affected) from 0.1.17 (fixed).
The engine existed in those releases, but its exact affected package set is not
established by runtime-base provenance alone; the advisory makes no engine
affected/fixed assertion.

Advisory 002 covers management releases from 0.1.2-beta through 0.1.41.
Authenticated user sessions were unaffected; lab mode and static API tokens did
not overwrite the header-supplied audit actor. The supported engine-only service
does not register the management API, although its executable also supports
management modes. Upgrade management to 0.1.42, use normal user sessions with lab
mode disabled, or strip incoming `X-User` at a trusted reverse proxy that clients
cannot bypass. This advisory covers actor attribution only, not other audit
metadata.

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
product and release range. CI and release warn when the versioned changelog has
`### Security` without an advisory marking that version fixed. This warning
appears in GitHub annotations and the step summary but does not block publication.
Malformed inputs still fail.

Package assessments are scan-conditional: they appear only for the image and
platform where the scanner reports that identifier. Unconditional vendor
statements can also cover a release range without a scanner hit.

### v0.1.42 package assessments

The vendor triage covers both images at 0.1.42, not future releases:

- Seven ClamAV parser CVEs (CVE-2026-20337, -20338, -20339, -20345, -20346,
  -20347 and -20348) are `known_affected` when ClamAV-mode HTTP upload/download
  scanning is enabled. Both images ship the package; the standalone engine owns
  clamd and the HTTP scanning gate, just as the engine in the combined appliance
  does. Disable ClamAV-mode HTTP scanning or use an independently maintained
  ICAP backend until a fixed image is available. Disabling scanning removes
  that inspection protection. On 2026-11-05 the Wolfi security database lists
  1.5.4-r2 as fixed, but neither architecture's package index publishes it.
- GHSA-w67g-5rqw-f597 is `known_not_affected`: the shared binary uses WebSockets
  only as a server, and v1.5.1 uses cryptographic randomness for client masks.
- CVE-2026-78661 and CVE-2026-97045 are `known_not_affected`: a transitive
  dependency uses the HTML tokenizer, but the affected tree parser/renderer
  symbols are absent from the binaries. This is not a claim that the entire
  `x/net/html` package is absent.
- GO-2026-5932 is `known_not_affected`: the OpenPGP packages are not imported
  or linked; `x/crypto` is used for SSH and bcrypt.

The Go assessments combine govulncheck v1.9.0 symbol-level analysis for Linux
amd64/arm64 with source inspection. The WebSocket database entry marks broad
server APIs reachable; reachability alone does not establish the mask-key flaw.
The exact rationale and remediation statements are in
[`triage.json`](https://github.com/tonylturner/containd/blob/main/security/csaf/triage.json).

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
