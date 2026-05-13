# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.28] - 2026-05-13

Second hardening follow-up after Codex review on
[PR #22](https://github.com/tonylturner/containd/pull/22) flagged
a sharp gap in v0.1.27's supervise loop.

### Fixed

- **NFQUEUE handle is unconditionally closed before retry.** v0.1.27
  added supervise+retry to the NFQUEUE consumer, but a panic inside
  `run()` skipped the `nf.Close()` call: the close paths were a
  separate ctx-watcher goroutine and the register-error early
  return, neither of which fire on a recovered panic. Result: the
  kernel kept the old binding while supervise immediately called
  `nfqueue.Open` again — every retry hit EBUSY, supervise burned
  through all 8 attempts, then gave up. The "restart after panic"
  path was actually "restart-and-loop-fail until giveup". Now
  `defer nf.Close()` runs immediately after `nfqueue.Open()` so
  every return path — normal, error, or panic-via-recover —
  releases the handle. The separate ctx-watcher goroutine is gone
  (redundant with the deferred close + the main `<-ctx.Done()`).
  Codex review on PR #22 caught this as P1.

### Tests

1 new test (`TestNFQueueSuperviseCleansUpBetweenRetries`) that
asserts the supervise loop cannot re-enter `runFn` while a previous
attempt's deferred cleanup is still in flight — a regression in the
defer-close path would surface as an overlap flag flip.

## [0.1.27] - 2026-05-13

Hardening follow-up to v0.1.26. No behavior changes on the happy path —
addresses a defensive-only code path that didn't actually recover the
way the comment claimed it did.

### Fixed

- **NFQUEUE consumer is supervised with bounded retries** instead of
  silently exiting on panic. v0.1.26 added a `defer recover()` around
  the consumer goroutine to keep a malformed-netlink panic from
  killing the engine, but the recovered path returned from the
  goroutine without restarting the consumer — leaving the kernel
  queue permanently undrained. In practice the panic is unreachable
  with the v0.1.26 `mdlayher/netlink` v1.11.1 bump, but as defense in
  depth the recover should restart. New `supervise()` loop with
  exponential backoff (250ms → 30s, capped) and a hard ceiling of 8
  retries; a permanently-failing kernel surface logs "giving up"
  via `OnError` rather than spinning forever. Context-cancel exits
  cleanly without consuming a retry. Codex review on
  [PR #21](https://github.com/tonylturner/containd/pull/21) caught
  the original silent-exit as P1.

### Tests

3 new tests covering panic-then-restart, give-up-after-max-retries,
and clean-cancel paths. Test-only `withFastBackoff` seam compresses
the production envelope to sub-millisecond so the giveup test runs
in ~10ms instead of ~62s.

## [0.1.26] - 2026-05-13

Cross-platform ICS DPI enforcement, boot-time interface autobind, and a
batch of fixes surfaced by an end-to-end lab integration shakedown on
macOS Docker Desktop. Builds on v0.1.25's L4 event pipeline.

### Added

- **NFQUEUE-based ICS DPI enforcement.** New `dataplane.nfqueueGroup`
  config field. When non-zero, the compiler emits `queue num <N>` as
  the verdict for dpiEligible rules (those with an ICS predicate)
  instead of plain accept/drop, and the engine starts an NFQUEUE
  capture consumer at that group. Packets flow `kernel → queue →
  handlePacket → DPI decoders → enforceDPIEvents`, which evaluates
  the rule's ICS predicate (function-code allowlist, register
  ranges, etc.) and applies `BlockFlowTemp` via the `block_flows`
  nft set when a violation is detected. Without this, ICS rules
  compiled to plain accept and the function-code allowlist was
  decorative. Verified end-to-end: RTAC Modbus FC3 (in allowlist
  `[1..6]`) passes; FC8 (not in allowlist) triggers a `block_flows`
  entry within seconds, blocking the flow.

- **Forward-chain rule ordering reworked to support DPI.** The
  compiler now emits dpiEligible queue rules BEFORE the
  `ct state established accept` fast-path; otherwise only the SYN
  of an inspected flow reaches the queue and the data-bearing
  packets (carrying the actual Modbus/DNP3/CIP PDUs we need to
  inspect) match ct established and skip DPI entirely. Also moved
  `block_hosts`/`block_flows` drop rules above `ct established` so
  retroactive DPI verdicts actually drop subsequent packets of an
  already-established flow. Non-DPI rules continue to benefit from
  the conntrack fast-path.

- **`AutoBindDefaultInterfaceDevices` runs at mgmt boot.** Before
  the HTTP server begins accepting traffic, mgmt blanks any stale
  `interfaces[].device` references in the stored config and re-runs
  the subnet-match autobind (the existing `CONTAIND_AUTO_*_SUBNET`
  -driven logic). Without this, Docker/LinuxKit ethN reshuffles
  across container restarts left the stored device fields pointing
  at the wrong kernel interface; mgmt-access checks then used the
  wrong iface and the first API request from the management plane
  could 403. The function is exported as
  `AutoBindDefaultInterfaceDevices` so other startup paths can
  trigger the same logic.

### Fixed

- **`mdlayher/netlink` bumped to v1.11.1** (was a pre-release
  pseudo-version that predated the upstream fix). The old version
  panicked with `slice bounds out of range [:140] capacity 138`
  when `getBuffer` allocated raw `n` bytes for the message and
  later sliced to `nlmsgAlign(n)` which rounds up. Upstream fixed
  this by allocating `nlmsgAlign(n)` directly — the comment in
  `getBuffer` now explicitly says "aligned to the next multiple of
  the alignment of a netlink message, to avoid panic when parsing
  messages from the buffer." Visible on the LinuxKit kernel
  underlying macOS Docker Desktop, where it killed the engine
  process the moment the NFQUEUE consumer received a non-aligned
  message. Also bumped `florianl/go-nfqueue/v2` to v2.0.3 for
  compat. No fork needed — upstream already had it.

- **`nflog` consumer is cancelled before Reconfigure swap.**
  Previously `Engine.Configure(dataPlane)` built a fresh engine and
  `Reconfigure` swapped state, but the old nflog consumer goroutine
  kept the netfilter group registration with a closure over the
  now-defunct event store. The new `Start` then hit EPERM trying to
  re-register the group → `service.nflog.unavailable` event with no
  firewall.rule.hit events flowing despite kernel drops queuing to
  nflog. Engine now tracks `nflogCancel context.CancelFunc`;
  `Reconfigure` cancels the previous consumer after swap, so the
  new `Start` finds the group free.

- **`capture.Manager` accepts `Mode: "nfqueue"` without
  `Interfaces`.** Previously short-circuited when `len(Interfaces)
  == 0`, which made NFQUEUE mode unreachable from any config that
  didn't also pin specific eth devices. NFQUEUE is interface-
  agnostic (packets arrive via the kernel queue), so the check now
  only applies to AFPACKET mode.

- **`X-Containd-Warnings` is now a multi-value header.**
  `setWarningHeader` was joining warnings with `\n` into a single
  `Header.Set` value. Go's `net/http` strips control characters
  from header values for security, which collapsed all warnings
  into one space-separated string on the receiver. Each warning
  now gets its own `Header.Add` call so clients can read them
  cleanly via `Header.Values("X-Containd-Warnings")`. Embedded
  newlines within a single warning are converted to spaces to keep
  the value RFC 7230 §3.2 compliant.

- **`POST /api/v1/templates/ics/apply` accepts both hyphenated and
  underscored template names.** `GET /api/v1/templates` returns the
  canonical hyphenated form (e.g. `modbus-read-only`) but the apply
  switch was written with underscores (`modbus_read_only`). Anyone
  copy-pasting from the list endpoint would get a 400 "unknown ICS
  template". `buildICSTemplateRules` now normalizes hyphens to
  underscores at the boundary.

### Tests

10 new test functions across affected packages: hyphenated template
acceptance, multi-value warning header propagation, NFQUEUE manager
with no interfaces, NFQUEUE + chain-reorder snapshot fixtures,
boot-time autobind no-op vs repair paths.

### Note for downstream consumers

The `Compiler.QueueID` field added in this release pairs with
`NFQueueGroup` in the runtime config. Set both or neither — a queue
verdict in the compiled ruleset without a userspace consumer attached
would freeze inspected traffic at the kernel hook.

## [0.1.25] - 2026-05-12

### Added — closes #19

- **L4 firewall rule events** now flow into `/api/v1/events` for rules
  with `log: true` that don't have an `ics:` block. `Compiler.NFLogGroup`
  emits an `nft log prefix "containd:<id>:<ACTION> " group <N>` clause
  before the verdict on non-DPI rules with `Log: true`. New userspace
  consumer at `pkg/dp/capture/nflog_linux.go` (using
  `github.com/florianl/go-nflog/v2`) subscribes to the configured
  group and appends `firewall.rule.hit` events to the event store.
  Rule IDs are sanitized to `[A-Za-z0-9_-]` in the prefix so quote/
  colon/shell-meta characters in IDs don't produce broken nft syntax
  or unparseable consumer events.

- **Per-rule `ICSPredicate.Mode` is honored.** New
  `(*Engine).effectiveMode(matched)` helper resolves with 3-tier
  precedence: per-rule `Mode` > global `DPIMode` > `"learn"` (safe
  default). `enforceDPIEvents` evaluates per-event and skips verdict
  application unless effective mode is `"enforce"`. The
  `firewall.rule.hit` log event fires regardless of mode so operators
  in monitor-mode still get visibility for the observation phase
  before promoting rules to enforce.

- **ICS templates ship with `Log: true`** (Mode left blank to inherit
  global). All 6 protocol templates + ModbusRegisterGuard. Purdue
  Model's 4 explicit deny rules also gain `Log: true`. Operators
  applying a template under monitor mode now see what would have
  been blocked.

- **Apply-time `mode` parameter** on both
  `POST /api/v1/templates/apply` and `POST /api/v1/templates/ics/apply`
  HTTP endpoints. When set (`"learn"` or `"enforce"`), overrides each
  generated rule's `ICSPredicate.Mode`. Invalid values return 400.

- **`containd templates apply <name> [--mode <learn|enforce>]`** CLI
  flag. Threads through to the HTTP endpoint with the existing
  `validateFirewallICSMode` validator.

- **UI embed-path autodetect** in `ui/lib/api-core.ts`. If the page
  is loaded from `/containd/*` (the convention for embedding the
  containd UI behind a path-prefixed reverse proxy), prefix all API
  calls with `/containd`. `NEXT_PUBLIC_API_BASE` env var still wins
  if set. Fixes the templates UI returning "Failed to preview" when
  accessed via an embedded `/containd/templates/` URL. Wizard's ICS
  Communication card now also sets `log: true` on its generated rule.

### Changed

- `templates.Apply(name, cfg)` retains its existing signature; a new
  sibling `templates.ApplyWithOpts(name, cfg, ApplyOpts{Mode: ...})`
  is the mode-aware path used by the new handler/CLI surfaces.

### Security / dependencies

- Bumped Go toolchain `1.25.8` → `1.25.10` (in go.mod and both
  build/Dockerfile.{mgmt,engine}) to clear 5 HIGH stdlib CVEs flagged
  by Trivy: CVE-2026-33811, CVE-2026-33814, CVE-2026-39820,
  CVE-2026-39836, CVE-2026-42499.

- Added `github.com/florianl/go-nflog/v2 v2.3.0`.

### Tests

23 new test functions across the changed packages, covering log
clause emission, DPI suppression, no-group disables logging, prefix
truncation, rule-ID sanitization for unsafe characters, nflog prefix
parse + foreign-prefix rejection + malformed-prefix rejection +
packet field decode, effectiveMode resolution (per-rule wins,
global fallback, learn default, case normalization), template
factories ship `Log: true`, `ApplyWithOpts` overrides, HTTP apply
with `mode=enforce`/blank/invalid.

### Note on v0.1.24

v0.1.24 was tagged briefly but the release workflow failed at its
VERSION-vs-tag guard (VERSION file lagged the tag). No image was
published for that tag. v0.1.25 is the first release containing
these changes.

## [0.1.23] - 2026-05-08

### Documentation
- Transparency note in `docs/mkdocs/secure-by-design.md` under **§ 2 Default Passwords** documenting the v0.1.22 lab-mode credential pinning openly. Calls it out as a deliberate weakening of the default-password posture, scoped to the lab boundary, with explicit "when lab mode is appropriate" and "when lab mode is NOT appropriate" lists, the trade-offs (no credential rotation, SSH-on-:2222 uses the same pinned cred), and roadmap for a future per-instance bootstrap that preserves classroom usability without a universal shared credential.
- `docs/mkdocs/threat-model.md` § Auth Bypass / Privilege Escalation residual-risk list now flags lab mode and links to the secure-by-design transparency note.
- `docs/mkdocs/lab-compose.md` `.env` reference documents `CONTAIND_LAB_MODE` and explicitly warns it should not be enabled on deployments reachable from hostile or shared networks.
- This is a docs-only release rolling the transparency content into the published image alongside the v0.1.22 code change. No new behavior beyond v0.1.22.

## [0.1.22] - 2026-05-08

### Fixed
- `CONTAIND_LAB_MODE=1` now pins the canonical credential. The HTTP password-change endpoints (`POST /api/v1/auth/me/password` and `POST /api/v1/users/:id/password`) return 403 with a clear lab-mode message instead of accepting the change. `GET /api/v1/auth/me` no longer advertises `mustChangePassword: true` in lab mode, so the UI doesn't trigger a force-change flow that would (a) drift the credential away from the documented `containd/containd` default that workshop docs and SSH-on-:2222 depend on, and (b) hit the now-locked endpoint with a confusing CSRF/Origin error when accessed via a reverse proxy. `seedDefaultAdmin` also clears `MustChangePassword` at seed time in lab mode so the flag is never persisted. Surfaced by the RangerDanger workshop integration where students were forced to change the password on first login, breaking subsequent SSH-terminal labs and triggering CORS/CSRF errors when the change was attempted through the proxy. New `TestLabModeLocksPasswordChange` pins the contract.

## [0.1.21] - 2026-05-07

### Fixed
- `compileEntry` now emits one nft rule per protocol on the entry instead of only the first. A rule declaring `[tcp/502, tcp/20000, tcp/8080]` was silently compiling to a single tcp/502 line — every other protocol black-holed. The skeleton "only first protocol supported" code path was finished.
- `writeForwardChain` now emits ALLOW rules before DENY rules. nftables is first-match, so a broad deny ("block lan1->lan2 for tcp/8080") emitted before a narrow allow exception ("rtac/10.30.30.20->lan2/8080") would silently shadow the allow. Within each action, sort by ID for determinism.
- `applyRunningConfig` now calls `autoBindDefaultInterfaceDevices` after loading the committed config. Imports that use logical names (`wan`/`dmz`/`lan1`/`lan2`) with empty or stale `device` fields would otherwise compile to nft rules referencing whatever eth name the JSON happened to specify — silently wrong if the kernel's actual device order differs (e.g. docker assigns ethN by alphabetical network name, not compose order). Now resolved against the running kernel state at commit time.

## [0.1.20] - 2026-05-07

### Security
- Bumped Go toolchain in `build/Dockerfile.mgmt` and `build/Dockerfile.engine` from `golang:1.25.8-alpine` to `golang:1.25.9-alpine`, clearing three Trivy HIGH findings against the published image: `CVE-2026-32280` and `CVE-2026-32281` (crypto/x509 chain-validation DoS) and `CVE-2026-32283` (crypto/tls KeyUpdate DoS). All fixed in Go 1.25.9.

## [0.1.19] - 2026-05-07

### Added
- Tab-completion in the containd CLI. The `containd cli` shell now uses `peterh/liner` for line editing, prefix-match tab-completion against the registered command set (`Registry.Commands()`), and persistent history (`~/.containd_history`, override with `CONTAIND_CLI_HISTORY`). Falls back to plain reading when stdin isn't a TTY so non-interactive scripts keep working.

### Changed
- `shell` / `bash` in the CLI loop now exit the loop alongside `exit` / `quit` / `logout`, instead of printing the misleading "Already in Linux shell. Type 'exit' to return." Wrappers that launch `containd cli` (the SSH appliance shell, RangerDanger's in-app firewall terminal) drop the operator back to bash on return — so `shell` and `bash` are equivalent to `exit` here, not a separate sub-shell.

## [0.1.18] - 2026-04-09

### Fixed
- Fixed daemon lifecycle bug where clamd, envoy, and nginx were started with the HTTP request context, causing them to be killed when the API request completed. All supervised daemons now use a background context.
- Added CAP_SYS_TIME pre-start check for chrony NTP. Without the capability, chronyd exits immediately; the status API now reports a clear actionable error instead of silent failure.
- Added post-start stability check for the NTP daemon: if it exits within 1 second, the error is captured and the status API correctly reports running=false.

### Added
- Added 10 NTP unit tests covering config rendering (chrony and openntpd formats), poll interval conversion, Apply file writes, disable cleanup, status reporting, env var detection, and config path selection.
- Added SYS_TIME capability and CONTAIND_SSH_SHELL_MODE to the starter docker-compose.yml.
- Migrated the standalone engine image (Dockerfile.engine) from distroless to Wolfi for consistency with the management image.

### Changed
- Updated documentation (SPDX.md, sbom.md, audit-baseline.md) to reference Wolfi instead of distroless.

## [0.1.17] - 2026-04-09

### Changed
- Migrated container base image from debian:bookworm-slim to Wolfi (cgr.dev/chainguard/wolfi-base). Wolfi is glibc-based and actively patched, reducing CVE surface significantly compared to Debian while retaining a real Linux shell, tcpdump, and standard troubleshooting tools. Removed 39 Debian-specific CVE suppressions from .trivyignore.
- Embedded services (nginx, unbound, nftables, openvpn, clamav) are now installed via Wolfi apk. Tini is now installed from the Wolfi package repository.
- Replaced OpenNTPD with chrony for NTP time synchronization. Chrony is available in Wolfi, actively maintained, and is the standard NTP implementation on modern Linux. The NTP manager auto-detects chrony or falls back to openntpd. Config generation, validation, and supervision adapted for chrony's format and CLI.
- Pinned Wolfi base image by digest for reproducible builds.
- Updated CSAF advisory containd-2026-001 status to resolved by v0.1.17 base image migration.

## [0.1.16] - 2026-04-09

### Added
- Added configurable Linux shell mode to the SSH server. Set `CONTAIND_SSH_SHELL_MODE=linux` or use `set system ssh shell-mode linux` to drop into a real bash shell on SSH login with access to tcpdump and standard Linux tools. Type `configure` to enter the appliance CLI, `exit` to return to bash. The default `appliance` mode preserves existing behavior with a new `shell` command to access Linux.
- Added `containd cli` subcommand and `/usr/local/bin/configure` symlink for entering the appliance CLI from the Linux shell.
- Added `set system ssh shell-mode` CLI command and `show system` display of the current shell mode.

### Changed
- Switched container base image from distroless to debian:bookworm-slim to support real Linux shell access and tcpdump. Service binaries (nginx, unbound, nftables, openvpn, openntpd, clamav) are now installed via apt instead of staged from intermediate build layers.
- Published CSAF advisory containd-2026-001 documenting inherited Debian 12 CVEs from the base image change. See [advisory](security/csaf/advisories/containd-2026-001.json) and tracking issue #16.

### Security
- The base image change introduces 39 known HIGH/CRITICAL CVEs from upstream Debian 12 packages with no fixes currently available. These are in OS-level dependencies, not containd code. Operators not needing the Linux shell feature should use v0.1.15. See `.trivyignore` for the full suppression list.

## [0.1.15] - 2026-03-14

### Added
- Added route-level sanity coverage for the management API and a browser-driven route smoke suite over the shipped UI pages so release validation catches broken views and endpoint drift before user testing.

### Fixed
- Fixed ICS and firewall rule views so ICS predicate fields such as Modbus function codes are serialized and normalized as real JSON arrays instead of crashing the UI after template-generated rule creation.
- Clarified `security.txt`, CSAF provider metadata, and release packaging so containd now explicitly documents that it currently publishes CSAF provider metadata and authoring scaffolding, while advisory JSON documents are only published when a real vulnerability disclosure exists.

## [0.1.14] - 2026-03-13

### Added
- Added a repeatable audit/verification toolchain with coverage, performance, complexity, Semgrep, race, and smoke workflows so release validation can exercise correctness, security, and runtime behavior from a single documented path.
- Added threat-model, testing, performance, audit-baseline, and code-boundary documentation plus broader regression coverage, fuzz targets, and benchmark baselines across the API, services, CLI, SSH, dataplane, and ICS/IT-DPI parser surfaces.

### Changed
- Refactored oversized runtime, HTTP, CLI, dataplane, and UI modules into bounded domain files, resolving the oversized-file and high-complexity audit findings without changing the supported user-facing workflows.
- Refreshed Secure by Design documentation to reflect completed pledge items and added a simpler adherence status table for operators and reviewers.

### Fixed
- Hardened browser cookie-auth writes so same-origin enforcement now runs before session-refresh/auth side effects and correctly treats default ports as equivalent during origin checks.
- Fixed config import and factory reset flows so IDS rules are fully cleared or replaced instead of silently retaining stale table contents from prior state.
- Enabled DPI by default in the bootstrap/runtime startup path and validated config tab query parameters so first-run behavior matches the expected appliance defaults more reliably.
- Fixed race-only service supervision regressions in the VPN and syslog test/runtime paths, stabilized ClamAV/socket test fixtures for `-race`, and removed committed secret-looking test credential literals that tripped PR scanners.

## [0.1.13] - 2026-03-12

### Added
- Added a dedicated DPI smoke phase with a lightweight Modbus/TCP client/server harness so the default smoke suite now validates live protocol visibility, write detection, inventory population, and DPI enforcement behavior in addition to forwarding/NAT.

### Changed
- Updated the local development compose topology to honor the same `.env`-driven subnet and interface IP variables as the starter compose, so customized lab ranges and interface auto-assign hints stay aligned across both paths.

### Fixed
- Fixed first-boot/default interface binding and `Auto-assign` so interface-to-device mapping now follows subnet-aware matching instead of kernel index order, and can repair the old legacy default binding pattern when recognized.
- Fixed ICS policy template apply so generated firewall rules are actually written into candidate config and appear in the firewall UI after apply/commit instead of remaining preview-only.
- Fixed DPI flow handling so inspectable TCP flows are not prematurely cached as allowed before protocol decoders can inspect later packets, restoring reliable live protocol stats, top-talkers, and inventory updates.
- Ignored Python cache artifacts produced by the new smoke fixture scripts so `__pycache__` and `*.pyc` files stop polluting the worktree during local test runs.

## [0.1.12] - 2026-03-12

### Added
- Added per-user MFA requirement controls with a 7-day enrollment grace period, admin-side grace extension/reset actions, and restricted post-grace access until MFA is enabled.

### Changed
- Reworked the user-management page into separate manage/create tabs so MFA policy controls and account actions remain usable on narrower screens.

### Fixed
- Fixed the quickstart CI workflow YAML so GitHub Actions can parse the generated-password step correctly and rerun CI after `v0.1.11`.

## [0.1.11] - 2026-03-12

### Added
- Added optional app-based TOTP MFA for local accounts, including login challenge/verification, self-service enrollment in the UI, and admin-side MFA reset support for local users.
- Added a documented public advisory process with CSAF provider metadata, advisory authoring templates, and release packaging for machine-readable security materials.
- Added dedicated documentation for logging/evidence surfaces and update policy so operators and instructors can explain what containd records, forwards, and expects during secure updates.

### Fixed
- Removed the hardcoded password value from the quickstart CI smoke by generating a fresh password at runtime instead of committing a scanner-visible credential string.
- Removed the secret-looking JWT placeholder from `.env.example` so starter guidance no longer ships a committed fake secret value that looks like a real disclosure.

### Changed
- Tightened `SECURITY.md`, `security.txt`, and the Secure by Design docs to reflect the actual vulnerability disclosure workflow, advisory/CVE expectations, machine-readable publication points, and the current bootstrap-password caveat.
- Updated the API schema and local user-management surfaces to expose MFA state and the new MFA flows cleanly.

## [0.1.10] - 2026-03-12

### Fixed
- Removed the starter/dev compose dependency on Compose `interface_name`, restoring compatibility with Docker Engine versions older than `28.1` and fixing the CI quickstart smoke failure on GitHub-hosted runners.

### Changed
- Clarified Docker lab documentation so subnet-based auto-assign is the supported stable interface-mapping mechanism, while `interface_name` is described as an optional newer-engine feature for custom lab files.

## [0.1.9] - 2026-03-12

### Added
- Added `scripts/quickstart.sh` for the recommended two-command starter path and `scripts/bootstrap-starter.sh` for customizable lab bootstrap with cross-platform Docker/WSL-friendly setup.
- Added Windows / WSL deployment guidance and a dedicated lab-compose customization guide in the embedded docs.
- Added fresh-config bootstrap defaults for capture interfaces and dataplane enforcement, plus tests for the new environment helpers and bootstrap logic.

### Fixed
- Fixed starter and dev Docker Compose runtime privileges so nftables, routing, TUN, interface auto-assign, and block actions work in the supported container-lab deployment model.
- Fixed engine apply error handling so runtime capability failures are surfaced with useful detail instead of collapsing into generic save errors.
- Fixed starter bootstrap collisions with existing Docker networks by automatically selecting a non-overlapping starter subnet block on first setup when the defaults are already in use.

### Changed
- Switched the documented starter deployment to enforcement-on lab mode by default and clarified the ownership boundary between Docker-defined topology and containd-defined segmentation.
- Updated README and MkDocs deployment docs to center the new quick-start flow, advanced bootstrap flow, and Docker Desktop / WSL classroom guidance.
- Tightened diagnostics UI behavior so temporary block actions reflect enforcement availability and backend runtime errors directly.

## [0.1.8] - 2026-03-12

### Fixed
- Repaired the public starter compose and service write paths so interface, routing, NAT, firewall, config lifecycle, and service saves no longer degrade into generic UI failures.
- Fixed partial firewall rule updates so editing one field no longer drops the rest of the rule payload on save.
- Made direct service saves persist even when runtime apply hits an engine or service warning, and surfaced those warnings back to the UI instead of failing the request outright.
- Fixed the embedded forward and reverse proxy runtime configuration so Envoy validates cleanly, Nginx uses writable temp paths, and repeated service applies stop colliding with already-running Nginx listeners.
- Kept AV runtime state in sync even when another service apply fails, so AV update/definitions actions continue to work after mixed service changes.

### Changed
- Upgraded the public starter compose from a thin single-network quickstart to the full multi-interface lab topology used in development, with `.env`-driven Docker-managed networks and stable interface mapping.
- Clarified README and Docker Compose docs around Docker-owned topology versus containd-owned segmentation, and documented that full enforcement/runtime networking requires a Linux Docker host rather than Docker Desktop.
- Expanded CI coverage for the documented starter compose path so it now exercises core write flows instead of only health/read-only checks.
- Improved UI/API result handling across extended feature pages so warnings and backend validation details are shown directly for services, dataplane actions, and config operations.

## [0.1.7] - 2026-03-11

### Changed
- Single-sourced release versioning via the repo `VERSION` file and separated it from `SchemaVersionCurrent`, so future releases no longer need manual version edits across unrelated files.
- Release workflow now publishes the matching `CHANGELOG.md` section as the GitHub release body and verifies that the pushed tag matches the repo `VERSION` file.


## [0.1.6] - 2026-03-11

### Fixed
- Auto-wired the management plane to the local engine in combined `all` mode so the public standalone appliance can commit config changes, drive simulation, and query runtime state without extra environment variables.
- Fixed the published Docker Compose healthcheck to use `/usr/bin/containd`, matching the runtime image layout.
- Made the engine HTTP client fail fast on missing base URLs and non-2xx simulation responses instead of silently pretending control succeeded.
- Treated a missing `/proc/net/nf_conntrack` table as an empty conntrack view instead of a public quickstart error.

### Changed
- Added CI coverage for the documented standalone/public compose path, including health, login, interface state, and simulation control checks.
- Updated README and MkDocs deployment docs to describe the real combined-mode defaults and the new standalone image override flow.
- Updated release metadata and build version to `v0.1.6`.

## [0.1.5-beta] - 2026-03-11

### Security
- Bumped the Go toolchain and embedded stdlib to `1.25.8` across local builds, CI, and Docker images to address `CVE-2026-25679` and `CVE-2026-27142`.

### Changed
- Clarified the split between Dashboard and live Monitoring with first-run guidance on the dashboard and a telemetry-focused monitoring landing page.
- Routed the in-app Help button to page-specific documentation instead of always opening the docs root.
- Updated local font packaging to self-hosted npm dependencies instead of fetching Google fonts during the build.
- Simplified monitoring language so Events and Flows read more like operator tools and less like internal telemetry surfaces.
- Made topology and config details more action-oriented without changing the existing visual system.

### Fixed
- Restored exact candidate-vs-running config dirty detection in the global status bar.
- Finished the Events page live/pause control and visibility-aware polling.
- Made the Policy Wizard success state explicit about candidate config and commit requirements.
- Updated release metadata and schema/build version to `v0.1.5-beta`.
- Added clearer next-step actions in topology detail panels and reframed config workflow copy around live, staged, and review/apply states.
- Fixed multi-arch release packaging so build-only Docker stages run on the native build platform instead of hanging in emulated arm64 `npm ci` and builder steps.

### Added
- Single-binary appliance (`containd all|mgmt|engine`) with combined management and data plane.
- Zone-based firewall with nftables enforcement, NAT (SNAT masquerade + DNAT port forwarding), and default-deny posture.
- Config lifecycle: candidate/running configs with diff, commit, commit-confirmed (auto-rollback), and rollback.
- Deterministic JSON config export/import with schema versioning.
- SQLite-backed persistence for config, audit, and user databases.
- JWT-based authentication with admin and view-only roles; session invalidation on logout.
- HTTPS with auto-generated self-signed certificate and custom cert install/rotate.
- SSH console with CLI shell (`show`, `set`, `diag` command families), menu, and setup wizard.
- Web-based CLI console (xterm.js) embedded in the management UI.
- Full management UI: dashboard, interfaces, zones, firewall rules, routing, NAT, topology view, monitoring, diagnostics, sessions/conntrack, audit log.
- Embedded DNS resolver (Unbound) with config-driven management.
- Embedded NTP client (OpenNTPD).
- Embedded forward proxy (Envoy explicit forward proxy) with domain ACLs.
- Embedded reverse proxy (Nginx) with upstream pools and TLS termination.
- WireGuard VPN with kernel interface management, peer config, and runtime status.
- OpenVPN client and server with managed config, profile upload, local PKI, and downloadable client profiles.
- DHCPv4 server with per-interface scopes, persistent leases, and MAC-based reservations.
- ICS/OT asset model with criticality, tags, and policy references.
- Full ICS protocol DPI: Modbus/TCP, DNP3, CIP/EtherNet/IP (with EPATH and MSP sub-service parsing), S7comm, IEC 61850 MMS, BACnet, OPC UA.
- IT protocol DPI: DNS (with compression pointer support), TLS (SNI/JA3/versions/ciphers), HTTP/HTTP2, SSH, RDP, SMB, SNMP, NTP.
- ICS asset auto-discovery from observed traffic (`pkg/dp/inventory`).
- Learn mode: passive traffic learning with automatic allowlist rule generation (`pkg/dp/learn`).
- Protocol anomaly detection: malformed frames, protocol violations, rate anomalies (`pkg/dp/anomaly`).
- Signature-based IDS with 16 built-in ICS malware signatures (`pkg/dp/signatures`).
- PCAP offline analysis: upload capture files for DPI processing and policy generation (`pkg/dp/pcap`).
- Event export in CEF, JSON, and Syslog formats to file/UDP/TCP destinations (`pkg/dp/export`).
- Protocol statistics and top talkers (`pkg/dp/stats`).
- 7 ICS policy templates (Purdue baseline, maintenance windows, per-protocol defaults) (`pkg/cp/templates`).
- Schedule predicates and identity predicates on firewall rules.
- Prometheus /metrics endpoint for monitoring integration (`pkg/common/metrics`).
- TCP reassembly with out-of-order segment handling and pre-allocated buffers.
- NFQUEUE selective DPI steering with per-flow verdict caching.
- Optional eBPF XDP/TC fast path for early drops and hardware counters.
- Event spill-to-disk for high-volume event handling.
- Native IDS with Sigma-compatible rule evaluation over DPI events.
- Antivirus pipeline: ICAP client, async scanning queue, optional embedded ClamAV with freshclam.
- Syslog forwarding (UDP/TCP, RFC 5424/JSON, retry/backoff).
- Structured logging (zap) with per-service log files, JSON/console toggle, and env-based overrides.
- Pcap capture forwarding to external sensors.
- Static routing, policy-based routing, and OS route detection/adoption.
- Interface discovery and auto-assignment (WAN to default-route device).
- Conntrack visibility and targeted session kill.
- Diagnostics: ping, traceroute, TCP traceroute, interface reachability probe.
- Docker Compose lab topology with 8 networks (WAN, DMZ, LAN1-6) and stable gateway IPs.
- MkDocs Material documentation site embedded in the appliance image.
- Smoke test suite for NAT/forwarding/DNAT rule-order validation.

### Security
- Default-deny firewall posture with built-in management access rule.
- Distroless container image (nonroot) for minimal attack surface.
- Auth required by default on all management endpoints.
- Session denylist for immediate logout invalidation.
- JWT validation with strong secret enforcement when lab mode is disabled.
- MustChangePassword enforcement on first login.
- nftables injection prevention on firewall rule inputs.
- TLS 1.2+ with hardened cipher suite list.
- HSTS enabled by default.
- CORS with wildcard origin rejection.
- SameSite=Strict session cookies.
- Path traversal protection on all file-serving endpoints.
- Rate limiting on authentication and sensitive API endpoints.

### Performance
- Flow hash uses strings.Builder for reduced allocations.
- Verdict cache with TOCTOU fix for concurrent access safety.
- Flow sweep runs outside mutex to reduce lock contention.
- Event store uses in-place shift to avoid allocations.
- Regex caching in IDS rule evaluation.
- Schedule predicate evaluation is allocation-free.
- TCP reassembler uses pre-allocated segment buffers.
