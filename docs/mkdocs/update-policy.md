# Update Policy

## Supported releases

- The **latest stable release** is the primary supported line.
- Prereleases such as `-beta` tags are for evaluation, not long-term support.
- Do not assume security backports for older releases unless release notes or
  an advisory explicitly state otherwise.

## Direct-upgrade validation

There is not yet a proven direct-upgrade support floor. Schema-reader acceptance
alone is not a supported from→to matrix. The published-image smoke declares
training 0.1.30–0.1.42 and strict→strict 0.1.39–0.1.42 as validation targets;
these targets must not be read as passing support claims.

For a release candidate, run the complete
[upgrade matrix smoke](testing.md#upgrade-matrix-smoke) before tagging:

1. Build the management/all-mode image from the exact release source with a
   unique local tag and record its image ID and source commit.
2. Run `scripts/smoke-upgrade.sh` with `UPGRADE_IMAGE` pointing to that image,
   a unique `COMPOSE_PROJECT_NAME=upgrade-<id>` and a new private
   `UPGRADE_RESULTS` directory. Do not filter rows for release validation.
3. Require every declared row to pass. Preserve `matrix.json`, source image
   digests, row wall times and the empty `remaining-resources.json` teardown
   evidence privately. A failed or unexecuted row is not a pass.
4. Publish only the demonstrated from→to rows and their profile/topology
   prerequisites. Recheck them against each new candidate; do not infer
   compatibility from matching schema versions or an image-only boot.

The smoke stops on its first failure without repairing stored data or relaxing
protection assertions. It covers combined mode and a representative routed
policy, not every service or split deployment. Full stopped-data rollback
backups and the interface-name changes below remain mandatory.

## Release artifacts and security information

Releases include signed images, SBOMs, image digests, and packaged CSAF provider
metadata, published advisory JSON, and digest-bound VEX when there are findings
or applicable vendor statements. VEX `under_investigation` is unresolved, not a
claim of safety. Read GitHub Releases and the
[Changelog](https://github.com/tonylturner/containd/blob/main/CHANGELOG.md) for
changes. See [Advisories](advisories.md) for machine-readable security information
and [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) for
disclosure and reporting.

CI and release report a warning when a versioned `Security` changelog section
lacks an advisory marking that version fixed. Missing coverage does not block
publication; malformed advisory-check inputs and document validation errors do.

## Operator update checklist

1. Read release notes and linked advisories; identify whether management, engine,
   or both images are affected.
2. Export config and securely preserve the persistent `/data` volume, including
   users, audit/event data, and service files needed for rollback. See
   [Compose data locations](docker-compose.md#persistent-data-paths-inside-container).
3. Choose a version tag or digest. Verify image signatures and signed
   [SBOM attestations](sbom.md#verifying-image-signatures-and-sbom-attestations)
   according to your deployment policy.
4. Complete any deployment changes first, including the
   [interface-name upgrade](#interface-name-upgrade). Update deployment image
   references, pull the images, and recreate the appliance.
   For split mode, update the affected processes together as required by release notes.
5. Verify `/api/v1/health`, `/metrics`, login, cross-zone enforcement, and key
   services. Keep the backup until the deployment is verified.

## Interface-name upgrade

Back up before upgrading: export the configuration and securely copy the full
persistent data directory while the appliance is stopped. Preserve the old image
reference and Compose file too. Schema **0.1.11** cannot be read by 0.1.40 or
earlier; downgrading requires restoring the pre-upgrade data backup.

1. Upgrade Docker Engine to **28.1+** and Compose to a version accepting
   `interface_name` (2.36.0+).
2. Before recreating the appliance, add `interface_name: <row name>` to **each**
   appliance network attachment. Match your saved rows, not necessarily Docker
   network keys. Review custom rows; their names must be valid Linux interface
   names (1–15 bytes). There is no automatic renaming.
3. Render the updated file with `docker compose -f <your-compose.yml> config -q`.
   Move existing strict data as described below, then update the image and
   recreate the appliance with `docker compose -f <your-compose.yml> up -d`.
4. Check attached rows, management access, protection status, cross-zone policy,
   capture selectors and service listeners before restoring normal traffic.

Rows now bind only by name. The schema upgrade drops saved `interfaces[].device`
bindings and rewrites saved references to legacy device names to row names. Each
reference keeps the meaning its consumer gave it before the upgrade, assuming every
bound device existed: VLAN parents, bridge members, DHCP and PCAP interfaces prefer
a row name; routes, gateways, capture interfaces and PCAP forward targets prefer a
bound device; VPN listeners resolve in saved row order. Migration evidence in
audit/events records dropped bindings, rewritten references, and references that
matched both a row and another row's device, with the row chosen. New exports omit
`device`; importing old exports uses the same upgrade. Auto-assignment and its API/CLI are removed. Subnet environment
hints no longer assign roles; keep subnet variables only for Compose IPAM.
`CONTAIND_CAPTURE_IFACES` remains a kernel-name list: update it to row names under
the named Compose topology (for example `wan,lan1`).

**Do not upgrade only the image.** Without matching Compose attachment names,
rows become unattached and zone rules stop matching. Traffic follows non-zone
rules and the default action, which can either deny intended traffic or allow
traffic that zone-specific denies previously blocked. Protection is **degraded**,
not ready, with a reason naming affected policy-referenced zones and their rows;
this does not roll back the installed policy.

**Management exposure:** when no granted row is live, unbound-appliance recovery
keeps management reachable on live NICs except explicitly denied live names.
A WAN denial saved on an absent row named `wan` no longer applies to a device
still named `ethN` until Compose is fixed. Restrict host port publication and
external/container network access during the upgrade; do not assume the old WAN
management denial protects this interval. An explicit management reservation
remains independent deployment authority. Recreate with the correct names and
verify management policy before reopening access.

### Existing data directories

The public starter keeps `./data`. Strict now defaults to
`${CONTAIND_DATA_DIR:-./data-strict}` beside its Compose file. Repository dev
keeps its separate repository-root `data` folder. These distinct locations avoid
sharing an appliance accidentally; **starting without moving existing data creates a fresh
appliance**, not an upgrade.

For an existing repository strict deployment, with `CONTAIND_DATA_DIR` unset in
both the shell and `.env`, run from the repository root after taking a backup,
adding `interface_name` and selecting the new image:

```sh
# Stop if the target already exists or the move fails; inspect before retrying.
docker compose --env-file .env -f deploy/docker-compose.strict.yml down &&
  test ! -e deploy/data-strict &&
  mv deploy/data deploy/data-strict &&
  docker compose --env-file .env -f deploy/docker-compose.strict.yml up -d
```

If your Compose file lives elsewhere, move its adjacent `data` to `data-strict`
instead, or set `CONTAIND_DATA_DIR` to the absolute path of your existing strict
folder. Never point strict at a training data folder; keep each
profile and lab isolated, including any custom overrides.

### When `:latest` moves

`:latest` points to signed, SBOM-attested **stable** images whose tagged commit
is in main's history. Version-tagged images can exist before they are eligible
for that channel. Prereleases and commits outside main's history do not move it.
The release tag must be at least the highest stable semantic-version `v*` tag
reachable from `origin/main`. Promotion refuses older tags, including manual
requests, and records the reason in the workflow summary.
Both tag pushes and manual **Release** workflow runs (with the existing `tag`
input) require a completed, successful **CI** workflow run from a **push to
main**, with `head_sha` equal to the peeled tag commit. PR runs, other branches,
other workflows and other commits cannot qualify. The newest matching run and
its latest attempt take precedence; an older successful attempt cannot override
a newer pending or failed attempt.

Pending CI is checked up to 21 times, with 30 seconds between checks (at most ten
minutes of sleeps). Each API invocation, including all its pages, is limited
to 30 seconds, bounding API time to another ten and a half minutes. A timeout fails promotion;
after CI succeeds, re-run the **Release** workflow manually with the same tag.
Missing, failed or cancelled CI, or an API error, fails promotion immediately.
The workflow summary records the run ID, link, attempt and conclusion when a
matching run exists. Prerelease, off-main and version-regression skips remain
unchanged and do not wait for CI.

Both management and engine tags are promoted to their signed digests only after
image signature and CycloneDX attestation verification succeed with the exact
release-tag workflow identity, GitHub OIDC issuer, and peeled release commit.
Missing or unsigned SBOM evidence cannot pass these checks.

Pin a version tag or digest for repeatable deployments rather than relying on the
moving `:latest` channel. Pin digests when you require an exact image identity.

## Classroom guidance

Keep a class on the same known image versions. Schedule upgrades deliberately
and verify the exercise's policy and workload paths before students use them.
