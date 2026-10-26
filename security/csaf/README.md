# CSAF advisory sources

This directory contains containd's CSAF 2.0 advisory JSON and authoring helpers.
For reporting and disclosure, use [SECURITY.md](../../SECURITY.md). For the
published advisory index and download locations, see
[Advisories and CSAF](../../docs/mkdocs/advisories.md).

## Layout and publication

- `advisories/` contains published JSON, including
  [containd-2026-001](advisories/containd-2026-001.json).
- `templates/` contains authoring skeletons.
- Provider metadata source is
  [`ui/public/.well-known/csaf/provider-metadata.json`](../../ui/public/.well-known/csaf/provider-metadata.json).
  The appliance URL is `/.well-known/csaf/provider-metadata.json`, not the source
  path. The release workflow attaches metadata and published advisories in
  `csaf-documents.tgz`.

## Authoring

Use one document per vulnerability or tightly related cluster. Suggested names:

- `CVE-YYYY-NNNNN.json`
- `GHSA-xxxx-xxxx-xxxx.json`
- `containd-YYYY-001.json` when no CVE/GHSA is assigned

Include vulnerability scope, affected products/versions, fixed versions,
mitigations or workarounds, revision history, and references to releases,
commits, and CVE/GHSA/CWE identifiers where available. Keep identifiers and
fixed-version guidance consistent with the changelog, release notes, and hosted
advisory records.

Validate documents against the official CSAF 2.0 schema before publishing;
this guide does not claim an automated repository schema-validation gate.
