# CSAF sources and release tooling

For reporting and disclosure, use [SECURITY.md](../../SECURITY.md). For download
locations, see [Advisories and CSAF](../../docs/mkdocs/advisories.md).

## Sources

- `advisories/` contains published CSAF 2.0 security advisories.
- `triage.json` is the single vendor-statement source for release VEX and Trivy
  suppressions. An empty list means no vendor triage, not an absence of findings.
- `templates/provider-metadata.json` supplies publisher fields, canonical URLs
  and the role (`csaf_publisher`). Do not claim `csaf_provider` without meeting
  that role's distribution and domain-root discovery requirements.
- `templates/csaf-v2.0-template.json` is an authoring skeleton, not a valid
  published document.

## Vendor triage

The JSON object has `schema_version: 1` and a `statements` array. Each statement
requires:

| Field | Meaning |
| --- | --- |
| `cve` or `ids` | One exact scanner identifier: a CVE string, or a single-element CSAF `ids` array (`system_name`, `text`) for a non-CVE identifier such as GHSA or GO |
| `products` | Nonempty subset of `containd`, `containd-engine` |
| `when` | `scan`: only where that identifier appears in the product/platform scan; `always`: unconditional vendor statement, including with no scan hit |
| `version_range.introduced` | Inclusive SemVer lower bound |
| `version_range.before` | Optional exclusive SemVer upper bound |
| `status` | `known_not_affected`, `known_affected`, `fixed`, or `under_investigation` |
| `details` | Nonempty vendor rationale; also the scanner suppression statement |

`known_not_affected` additionally requires a valid CSAF `flag` or an impact
`threat` string. `known_affected` requires a nonempty `remediations` array of
objects with `category` and `details` (optional HTTPS `url`); `none_available` and
`no_fix_planned` are valid categories. Multiple entries can describe a workaround
and the absence of a vendor fix separately. Overlapping statements for the same
identifier and product are rejected, including scan/always overlaps and overlaps
that assign the same status.

Use `when: "scan"` for package findings: a package removed or fixed in an image
must not leave a stale VEX statement behind. Matching is by exact vulnerability
identifier, not an inferred alias. A conditional statement does not expand a
single-platform hit to other platforms or the image index. Use `when: "always"`
for vendor statements that apply even when a scanner does not report them.
Both modes still require a matching release range and product. Select bounds
supported by the assessment, not hypothetical future versions. The initial real
assessments cover only 0.1.42 (`introduced: "0.1.42"`, `before: "0.1.43-0"`).
The `-0` upper bound excludes all next-patch prereleases as well.

Only `known_not_affected` statements suppress scanner findings. A finding in a
purportedly `fixed` release is not silently ignored. `scripts/csaf/ignore.py`
renders Trivy's YAML ignorefile (JSON is valid YAML), selecting one product and
release version. Unresolved statements are never scanner suppressions.

## Advisory authoring and validation

Use one advisory per vulnerability or tightly related cluster. Include scope,
versioned product branches, distinct affected and fixed product IDs,
remediations, revision history and references. A release whose `VERSION`
changelog section contains `### Security` is checked for a source advisory marking
that exact `product_version` fixed. Missing coverage emits a GitHub `::warning::`
and step-summary notice and exits successfully; it does not block CI or release.
Malformed inputs still fail. For hardening rather than a vulnerability fix, use
Changed/Fixed. The check does not inspect `[Unreleased]`.

Filenames follow CSAF 2.0 section 5.1: normalize the lowercase tracking ID by
replacing runs outside `[+\-a-z0-9]` with `_`, then append `.json`. For example,
ID `containd-vex-0.1.42` has filename `containd-vex-0_1_42.json`. The tools reject
filename/ID mismatches and normalized-name collisions.

From the repository root, with Go and Docker installed:

```bash
for test in scripts/csaf/*.test.py; do python3 "$test" || exit; done
bash scripts/csaf/validate.sh security/csaf/advisories
python3 scripts/csaf/gate.py
```

The integration test and validator wrapper run the published Secvisogram
validator service v3.0.3 image pinned to index digest
`sha256:181af4187f8f68ea443821ea1a5a57ba87a89b772282642c0e63dc37579673b3`.
The image supports `linux/amd64`; Docker Desktop uses emulation on Apple Silicon.
Each invocation owns a short-lived local container on an ephemeral loopback port. gocsaf `csaf_validator` v3.7.1 uses the service's
`basic` preset: strict schema plus all mandatory tests. The client appends
`/api/v1/validate` to its base URL. Every nonzero validator status fails; there
is no offline exit-code exception or dependency on a public validator service.

## Release generation and directory

The release workflow scans both exact image index digests for `linux/amd64` and
`linux/arm64` with Trivy 0.62.1, without suppressions. `generate.py` verifies scan
identity/platform, emits every finding and every applicable unconditional vendor
statement, and leaves untriaged findings `under_investigation`. Non-CVE scanner identifiers
are preserved as CSAF `ids`. No findings and no statements means no VEX document.
Dates come from the release commit, not the current clock. Job summaries list
all unresolved and known-affected entries.

`csaf-documents.tgz` contains generated provider metadata, source advisories and
the release VEX, with a directory index and hashes. Archives on published
GitHub releases are the historical VEX store; CI never commits them to main.

When CSAF sources or tools merge to main, after each successful Release run and on
manual dispatch, `.github/workflows/csaf-pages.yml` builds, validates and deploys an
aggregate directory from every published release's VEX archive plus current source
advisories, so an advisory is published when it merges, not only at the next release.
Source advisory revisions win on ID clashes. `build_site.py` writes
`.well-known/csaf/` with initial-release-year folders, `index.txt`, headerless
newest-first `changes.csv`, SHA-256/SHA-512 files and HTML directory listings.
Metadata `last_updated` is the newest document date.

The canonical metadata URL is
<https://tonylturner.github.io/containd/.well-known/csaf/provider-metadata.json>.
The appliance serves only the security.txt discovery pointer, not CSAF files.
The Pages upload uses `actions/upload-pages-artifact` v5 with
`include-hidden-files: true` to preserve `.well-known`, followed by
`actions/deploy-pages`; both are pinned by commit SHA. The maintainer must enable
repository Pages with build type **GitHub Actions** before deployment succeeds.
Release archives remain the historical download source.
