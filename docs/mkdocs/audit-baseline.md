# Audit Baseline

This page translates the project-specific audit work into a practical maturity snapshot for containd. It is intentionally evidence-based rather than checklist theater: scores reflect the current codebase, test harness, and release process as they exist today.

## Current Scorecard

| Category | Score | Why it landed here |
|----------|------:|--------------------|
| Architecture | 8/10 | Package boundaries are separated, route/client/config ownership is now documented, and the oversized-file structural finding is resolved. Remaining work is about keeping the new boundaries disciplined rather than breaking up emergency 3000-line files. |
| Code quality | 8/10 | CI and core tests are healthy, the biggest handler/config/UI files have been decomposed below the audit threshold, parser fuzz coverage now spans the current ICS and IT-DPI decoders plus TCP reassembly, the local verification flow now includes `staticcheck` and `ineffassign`, and the tracked complexity hotspot report is now clean at the current threshold. Remaining gaps are keeping that boundary enforced and continuing decoder-specific hardening as new protocol support lands. |
| Security | 8/10 | Strong baseline: session auth, MFA, rate limiting, signed releases, SBOMs, same-origin protection for cookie-authenticated writes, and request body limits. Main caveats are the bootstrap password model and limited RBAC depth. |
| Testing | 8/10 | Good smoke and API coverage, including forwarding/NAT and DPI smoke scenarios, parser fuzzing across the current ICS and IT-DPI decoders plus TCP reassembly, and a new repeatable package-coverage workflow. Explicit coverage thresholds and deeper multi-packet campaigns are still incomplete, and several runtime-heavy packages still have low direct statement coverage. |
| Performance | 7/10 | The repo now includes repeatable dataplane benchmark and profile workflows for the engine packet path, TCP reassembly, and representative decoder paths. Broader benchmark coverage and regression thresholds are still needed, but performance work is no longer ad hoc. |
| UX | 7/10 | Setup, commit flow, and several operator paths are much stronger than the initial public release, but some configuration pages and status cues still need refinement. |
| Documentation | 9/10 | Public docs are now strong on deployment, security, threat model, update policy, CSAF/advisories, and lab topology. Remaining work is mostly keeping the audit and hardening docs current as the code evolves. |

## What This Audit Batch Added

- Same-origin protection for cookie-authenticated browser API writes.
- API request body limits for JSON and multipart write paths.
- Updated security-related env/docs surface for allowed cross-origin integrations.
- Supply-chain refresh for selected Go and UI dependencies.
- A clearer, repo-specific audit baseline instead of a generic external checklist.
- Validation logic extracted from `pkg/cp/config/config.go` into package-local domain files, reducing that file below the 1200-line threshold.
- Backup/import/export, runtime, service, template, identity, firewall, and VPN handler groups extracted out of `api/http/server.go` / adjacent handler modules into focused package-local files.
- Netcfg routing, link, and address helpers split into package-local Linux files so interface orchestration, route management, and raw netlink operations are no longer mixed together.
- UI/API decomposition across `ui/lib/api.ts`, `ui/components/Shell.tsx`, `ui/app/firewall/page.tsx`, `ui/app/config/page.tsx`, `ui/app/vpn/page.tsx`, `ui/app/ics/page.tsx`, and `ui/app/system/users/page.tsx`.
- Focused fuzz targets for `bacnet`, `cip`, `dnp3`, `dns`, `http`, `modbus`, `ntp`, `opcua`, `rdp`, `s7comm`, `smb`, `snmp`, `ssh`, `tls`, and TCP `reassembly`.
- A concrete parser-hardening fix: S7comm `ParseTPKT` now rejects undersized declared lengths instead of slicing past bounds.
- Initial benchmark baselines for TCP reassembly and representative DNS/HTTP/TLS decoder paths.
- A dedicated threat model covering parser abuse, control-plane compromise, supply-chain risk, topology bypass, and configuration tampering.
- A repo-local verification workflow in `scripts/dev-verify.sh` for vet, lint, tests, UI lint/build, and docs build.
- A curated Semgrep baseline in `scripts/semgrep-verify.sh` and ShellCheck coverage folded into the local verification workflow.
- A repeatable complexity report in `scripts/complexity-report.sh`, plus a broad complexity burn-down across CLI, HTTP, netcfg, DHCP, management startup, compile, enforcement, learning, and routing hotspots.
- A repeatable benchmark/profile workflow in `scripts/perf-baseline.sh` for the current dataplane baseline, including engine packet handling, reassembly, and representative IT-DPI decoders.
- A repeatable coverage workflow in `scripts/coverage-report.sh`, with optional integration into `scripts/dev-verify.sh --with-coverage`.
- A clean stabilization pass on this branch:
  - `bash scripts/dev-verify.sh --with-semgrep`
  - `bash scripts/smoketest`
  - `bash scripts/perf-baseline.sh --bench-time 10x`
  - `mkdocs build -f docs/mkdocs.yml`
- A smoke-harness fix that moved the WAN DNAT forwarding test off the engine control port so repeatable smoke runs no longer self-interfere with `/internal/config`.

## Structural Finding Status

The structural “oversized source files” audit finding is resolved on this branch.

- Tracked `.go`, `.ts`, and `.tsx` source files over `1200` lines: `0`
- Largest remaining tracked source file: `ui/lib/api.ts` at `887` lines
- Current `scripts/complexity-report.sh --top 12` result: `No functions over complexity threshold 20.`

The current goal is now regression prevention, not emergency file breakup.

## Evidence Snapshot

### Strengths already present

- Candidate vs running config model with validation, commit, confirm, and rollback flows.
- Signed releases, SBOM generation, Trivy scanning, and documented advisory/CSAF process.
- Local-account auth with session invalidation, forced password change, optional TOTP MFA, and admin MFA requirements with grace periods.
- End-to-end smoke coverage for forwarding, NAT, and Modbus/TCP DPI visibility/enforcement.
- Strong deployment docs for starter compose, custom lab topology, and Windows/WSL2 lab use.

### Current coverage snapshot

The current stable branch checkpoint, validated with `bash scripts/dev-verify.sh --with-semgrep`, `bash scripts/smoketest`, and `bash scripts/perf-baseline.sh --bench-time 10x`, reports the following `bash scripts/coverage-report.sh --top 12` baseline:

- total statement coverage: `58.9%`
- category averages:
  - `API`: `58.0%`
  - `App`: `54.3%`
  - `CLI`: `49.4%`
  - `Common`: `74.1%`
  - `Control Plane`: `74.2%`
  - `Dataplane`: `75.9%`
  - `Management Plane`: `51.3%`

The low end is now concentrated in command-entry, runtime orchestration, and a few runtime-support packages such as:

- `api/http`
- `cmd/ngfw-mgmt`
- `pkg/app/engine`
- `pkg/cli`

This is materially better than the first branch snapshot: `api/http` is now `48.0%`, `pkg/app/mgmt` is `53.3%`, `pkg/app/engine` is `55.3%`, `pkg/cp/config` is `59.1%`, `pkg/cp/services` is `59.5%`, `pkg/cli` is `49.4%`, `pkg/dp/capture` is `85.7%`, `pkg/dp/enforce` is `73.9%`, `pkg/dp/netcfg` is `100.0%` on the non-Linux path, `pkg/dp/dhcpd` is `90.0%`, `pkg/dp/conntrack` is `100.0%`, `pkg/dp/pcap` is `80.8%`, `pkg/dp/ebpf` is `92.7%`, `pkg/dp/ics/modbus` is `76.7%`, `api/engine` is `67.9%`, `pkg/mp/sshserver` is `51.3%`, `pkg/common/logging` is `77.1%`, and `pkg/dp/synth` is `57.4%`.

### Current maturity gaps

- No tracked source files currently exceed the `1200`-line audit threshold.
- The largest remaining contributor-facing files are now in the `700-900` line range and are bounded by explicit ownership rules:
  - `ui/lib/api.ts`
  - `api/http/cli_handlers.go`
  - `ui/app/firewall/firewall-dpi-config.tsx`
  - `ui/app/topology/PhysicalView.tsx`
- Static-analysis tooling is stronger but still not complete. `scripts/dev-verify.sh` now covers `golangci-lint`, `staticcheck`, `ineffassign`, and `shellcheck`, while `scripts/semgrep-verify.sh` provides a curated Semgrep baseline with an explicit allowlist for the remaining appliance-specific findings. `scripts/complexity-report.sh` is now part of the normal audit flow and currently reports clean at the `>20` threshold, but `gocyclo` and `shfmt` are still not hard-gated in the default pass.
- Threat-model coverage and fuzzing depth are still incomplete for higher-risk multi-packet parser behavior and any future decoder additions beyond the current ICS/IT-DPI set and TCP reassembly.
- Performance work now has a repeatable benchmark and profiling workflow, including the engine packet path, but broader dataplane benchmarks and regression thresholds are still missing.
- The bootstrap password model remains a conscious lab-usability tradeoff and should eventually move toward a stronger per-instance bootstrap flow.
- Package-level coverage is now easy to measure, and the lowest-runtime packages are improving, but the baseline still shows weak spots in command-entry, API surface, and a few service/runtime-support paths that need targeted tests.

## Checklist Mapping

| Audit theme | Status | Notes |
|-------------|--------|-------|
| Repository structure | Partial | Package separation is good and the oversized-file threshold is now satisfied; remaining work is continued boundary discipline rather than urgent structure repair. |
| Static analysis | Partial | `go vet`, CI linting, and a repo-local `scripts/dev-verify.sh` flow now cover `golangci-lint`, `staticcheck`, `ineffassign`, and `shellcheck`, Semgrep has a curated local baseline in `scripts/semgrep-verify.sh`, and complexity tracking exists via `scripts/complexity-report.sh`, which is currently clean at the `>20` threshold. `gocyclo` and `shfmt` are still not hard-gated in the default pass. |
| Authentication / authorization | Partial | Strong session auth and MFA posture; RBAC remains intentionally simple. |
| Secrets management | Partial | Good env/template posture, but synthetic fixture keys still need ongoing scanner discipline. |
| API hardening | Partial | Auth, rate limiting, origin checks, and body limits are present; CSRF token scheme is still unnecessary because the API now enforces same-origin for cookie writes. |
| Network appliance security | Partial | Enforcement, NAT, and runtime controls are covered; malformed-packet and resource-exhaustion testing should deepen. |
| Protocol parser safety | Partial | Parser bounds checking exists in practice and fuzz targets now cover the current BACnet, CIP, DNP3, DNS, HTTP, Modbus, NTP, OPC UA, RDP, S7comm, SMB, SNMP, SSH, TLS, and TCP reassembly paths. Coverage is materially better, but deeper malformed-input campaigns and future parser additions still need the same discipline. |
| Testing coverage | Partial | Strong smoke/integration progress, parser fuzzing, and a repeatable package-coverage workflow now exist, but explicit coverage targets are not yet enforced and several lower-level runtime and command-entry packages still have light direct coverage. |
| Performance audit | Partial | Initial benchmark baselines and a repeatable profiling workflow now exist, but broader dataplane benchmark coverage and regression thresholds are still needed. |
| Observability | Done | Structured logging, audit/event surfaces, metrics endpoint, and logging guidance are already in place. |
| Config safety | Done | Candidate/running, validation, commit, rollback, and backup flows are implemented. |
| Release engineering | Done | Reproducible container builds, Wolfi runtime image (pinned by digest), cosign signing, and SBOM generation are already part of the release path. |
| Documentation | Done | Strong public docs now include deployment, security posture, code boundaries, audit status, and a dedicated threat model. |

## Recommended Next Steps

1. Enforce the new code-boundary rules so the resolved oversized-file finding does not regress.
2. Expand fuzzing and malformed-input regression coverage into higher-risk multi-packet handling paths, richer corpus seeds, and any future decoder additions beyond the current ICS/IT-DPI and TCP reassembly coverage.
3. Use `scripts/coverage-report.sh` to target the lowest-coverage orchestration and Linux-runtime packages before deciding whether any minimum package/category gates belong in CI.
4. Expand the new benchmark baseline to additional dataplane paths and the heaviest UI routes, then decide where lightweight regression tracking belongs in CI or release validation.
5. Keep running `scripts/complexity-report.sh` so the now-clean complexity report stays clean, then decide whether `gocyclo` should become a hard gate.
6. Keep the threat model current as auth, deployment modes, and protocol coverage evolve.
