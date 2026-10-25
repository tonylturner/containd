# Update Policy

containd ships frequently and treats security fixes as normal product work, not separate premium functionality.

## Supported Release Posture

At the current stage of the project, the practical support policy is:

- the **latest stable release** is the primary supported line
- prereleases such as `-beta` tags are for evaluation and validation, not long-term support
- older releases may remain usable, but operators should not assume ongoing security backports unless the project says so explicitly in release notes or an advisory

This policy is intentionally simple and transparent. containd is not yet claiming a large matrix of maintained branches.

## How Security Fixes Are Published

Security-relevant changes should be reflected in:

- GitHub Releases
- `CHANGELOG.md`
- `SECURITY.md` when the disclosure process matters
- GitHub Security Advisories and CSAF documents when the issue warrants a formal advisory

Release artifacts already include:

- signed images
- SBOMs
- release image digests

The release workflow now also packages CSAF provider metadata and any published advisory JSON documents so machine-readable advisory data can travel with the release process.

## Operator Update Expectations

When a security-relevant release is published, operators should:

1. Read the release notes and any linked advisory.
2. Identify whether the release affects the mgmt image, engine image, or both.
3. Back up config and preserve audit/event data before upgrading.
4. Pull the fixed image, update the running compose or deployment reference, and restart the appliance.
5. Verify health, login, enforcement, and key services after the upgrade.

For Docker-based labs, this usually means updating the image tag and redeploying the stack.

## Recommended Secure Update Workflow

For a careful update:

1. Create a config backup from the UI/API.
2. Preserve `/data` or snapshot the volume if you need rollback confidence.
3. Verify image signatures and inspect the attached SBOM if your environment requires it.
4. Deploy the new image.
5. Confirm `/api/v1/health`, `/metrics`, login, and your core policy path still work.

## Versioning and Security Notes

containd single-sources release version metadata from the repo `VERSION` file. The release workflow checks that the pushed tag matches `VERSION`, and release notes are extracted from the matching `CHANGELOG.md` section.

This helps keep:

- shipped image tags
- release notes
- changelog history
- security update communication

in sync.

### When `:latest` Moves

A `v*` tag publishes version-tagged mgmt and engine images, digest signatures, SBOMs, and a GitHub release. It does **not** immediately update `:latest`.

Only after signing and SBOM attachment succeed does a separate promotion job move both images' `:latest` tags to the exact signed digests. Promotion requires a stable tag (no `-`) whose tagged commit is an ancestor of `origin/main`, verified using full Git history. Prereleases and tags whose commits have not reached main never move `:latest`.

If a stable tag was published before its commit reached main (for example `v0.1.33` on `iec104`), merge it to main first, then run the **Release** workflow manually with the `tag` input set to that existing tag. The shared promotion job rechecks eligibility, resolves the existing version images, verifies their signatures against this repository's tag-triggered release workflow identity, and checks their attached SBOMs before moving either `:latest` tag. It does not rebuild images or create another GitHub release. Ineligible tags are skipped; missing images, invalid signatures, or missing SBOMs fail promotion.

The merge must preserve the tagged commit in main's history; squashing or rebasing it into a different commit does not satisfy the ancestry check.

Operators who need a fixed release should pin a version tag or digest rather than the moving `:latest` tag.

## Classroom Guidance

For teaching environments, the most important update habit is consistency:

- keep the class on one known release
- use the same image tags across lab instructions
- update deliberately, not ad hoc mid-exercise
- treat security releases as opportunities to teach how operators evaluate and apply fixes
