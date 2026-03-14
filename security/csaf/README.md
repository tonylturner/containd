# CSAF

This directory tracks containd's machine-readable advisory material.

## Layout

- `advisories/` — published CSAF JSON documents for real vulnerabilities
- `templates/` — authoring helpers and skeletons for new advisories

## Publication Model

- Public discovery starts with `SECURITY.md` and `/.well-known/security.txt`.
- CSAF provider metadata is published at `ui/public/.well-known/csaf/provider-metadata.json`.
- Published advisories live in `security/csaf/advisories/` and may be attached to GitHub releases as part of the release workflow.
- Until containd has a real vulnerability advisory to disclose, this repository publishes provider metadata only and keeps `advisories/` intentionally empty except for explanatory docs.

## Authoring Rules

- Use CSAF 2.0 JSON documents.
- Prefer one advisory per vulnerability or tightly related vulnerability cluster.
- Include affected versions, fixed versions, mitigation/workaround guidance, references, and CWE/CVE/GHSA identifiers when available.
- Validate advisory documents against the official CSAF schema before publishing.
- Keep `CHANGELOG.md`, GitHub release notes, GitHub Security Advisories, and CSAF documents aligned.
