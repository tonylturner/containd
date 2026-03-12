# Audit Baseline

This page translates the project-specific audit work into a practical maturity snapshot for containd. It is intentionally evidence-based rather than checklist theater: scores reflect the current codebase, test harness, and release process as they exist today.

## Current Scorecard

| Category | Score | Why it landed here |
|----------|------:|--------------------|
| Architecture | 6/10 | Package boundaries are already reasonably separated, but several core files are still very large and carry too many domains. |
| Code quality | 6/10 | CI and core tests are healthy, but local static-analysis coverage is still thinner than the target audit asks for and some oversized files need decomposition. |
| Security | 8/10 | Strong baseline: session auth, MFA, rate limiting, signed releases, SBOMs, same-origin protection for cookie-authenticated writes, and request body limits. Main caveats are the bootstrap password model and limited RBAC depth. |
| Testing | 7/10 | Good smoke and API coverage, including forwarding/NAT and DPI smoke scenarios, but protocol fuzzing and broader coverage targets are still incomplete. |
| Performance | 5/10 | The UI and dataplane have had targeted fixes, but there is still no formal benchmark or profiling baseline in the repo. |
| UX | 7/10 | Setup, commit flow, and several operator paths are much stronger than the initial public release, but some configuration pages and status cues still need refinement. |
| Documentation | 8/10 | Public docs are now strong on deployment, security, update policy, CSAF/advisories, and lab topology, but the project still lacks a dedicated threat model document and deeper parser-hardening guidance. |

## What This Audit Batch Added

- Same-origin protection for cookie-authenticated browser API writes.
- API request body limits for JSON and multipart write paths.
- Updated security-related env/docs surface for allowed cross-origin integrations.
- Supply-chain refresh for selected Go and UI dependencies.
- A clearer, repo-specific audit baseline instead of a generic external checklist.

## Evidence Snapshot

### Strengths already present

- Candidate vs running config model with validation, commit, confirm, and rollback flows.
- Signed releases, SBOM generation, Trivy scanning, and documented advisory/CSAF process.
- Local-account auth with session invalidation, forced password change, optional TOTP MFA, and admin MFA requirements with grace periods.
- End-to-end smoke coverage for forwarding, NAT, and Modbus/TCP DPI visibility/enforcement.
- Strong deployment docs for starter compose, custom lab topology, and Windows/WSL2 lab use.

### Current maturity gaps

- Oversized core files still need decomposition:
  - `api/http/server.go`
  - `pkg/cp/config/config.go`
  - `ui/lib/api.ts`
  - `ui/components/Shell.tsx`
  - selected large UI pages such as `ui/app/firewall/page.tsx`
- Static-analysis tooling is not yet fully standardized locally (`staticcheck`, `ineffassign`, `gocyclo`, `semgrep`, `shellcheck`, and `shfmt` are not consistently available in this environment).
- Threat-model and fuzzing coverage are still incomplete for higher-risk parser paths.
- Performance work is still opportunistic rather than benchmark-driven.
- The bootstrap password model remains a conscious lab-usability tradeoff and should eventually move toward a stronger per-instance bootstrap flow.

## Checklist Mapping

| Audit theme | Status | Notes |
|-------------|--------|-------|
| Repository structure | Partial | Good package separation; file-level decomposition still needed. |
| Static analysis | Partial | `go vet` and CI linting are in place; broader local lint suite still needs standardization. |
| Authentication / authorization | Partial | Strong session auth and MFA posture; RBAC remains intentionally simple. |
| Secrets management | Partial | Good env/template posture, but synthetic fixture keys still need ongoing scanner discipline. |
| API hardening | Partial | Auth, rate limiting, origin checks, and body limits are present; CSRF token scheme is still unnecessary because the API now enforces same-origin for cookie writes. |
| Network appliance security | Partial | Enforcement, NAT, and runtime controls are covered; malformed-packet and resource-exhaustion testing should deepen. |
| Protocol parser safety | Partial | Parser bounds checking exists in practice, but fuzzing is not yet broad enough to claim high maturity. |
| Testing coverage | Partial | Strong smoke/integration progress, but explicit coverage targets are not yet enforced. |
| Performance audit | Planned | Profiling and benchmark baselines are the next maturity step. |
| Observability | Done | Structured logging, audit/event surfaces, metrics endpoint, and logging guidance are already in place. |
| Config safety | Done | Candidate/running, validation, commit, rollback, and backup flows are implemented. |
| Release engineering | Done | Reproducible container builds, distroless runtime image, cosign signing, and SBOM generation are already part of the release path. |
| Documentation | Partial | Strong public docs exist; threat model and deeper parser-hardening docs remain to be added. |

## Recommended Next Steps

1. Split the largest Go and UI files by domain without changing behavior.
2. Add parser fuzz targets and malformed-input regression cases for the riskiest DPI paths.
3. Add benchmark and profiling baselines for the dataplane and the heaviest UI routes.
4. Publish a dedicated threat-model document covering parser abuse, control-plane compromise, supply-chain risk, and configuration tampering.
