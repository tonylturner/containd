# Quality, security and operations maturity audit

Target: `iec104` at `40ec7f81cbf3b9629d3d71233741e6d4d0afda17`, audited 2026-10-25. VERSION is 0.1.32; next containd release is 0.1.33, not RangerDanger's 0.2.0. Product frame: mature training/testing and container-workload protection, not a physical-interface production appliance. Secure remote access (SRA) assurance is prioritized. IEC104 B–E work remains **in progress**, not re-audited here.

Method: read-only static audit; **Verified** means source/docs/test declarations were read, not that a vulnerability was exploited or a test passed. **Inferred** marks security consequences requiring runtime confirmation. No suites, Docker, scanners, browsers or live services were run. Historical coverage is not a measurement of this revision. The prior lane's report was read first and its claims are being independently checked and carried forward. This artifact is written incrementally outside the checkout. Repository status was clean at entry; no root/nested AGENTS.md or CLAUDE.md appeared in repository file discovery; CONTRIBUTING.md supplies the conventions.

## 1. Inventory

### Delivery and deployment surfaces (Verified)

- `.github/workflows/ci.yml:11-219`: curated Semgrep; Linux Go tidy/vet/race; golangci-lint v2; MkDocs; npm install/audit/lint/build; combined-image build, real quickstart HTTP smoke, and blocking HIGH/CRITICAL Trivy image scan. Actions use full commit pins. CI triggers main pushes and PRs (:6-9), not ordinary iec104 branch pushes.
- `.github/workflows/release.yml:9-173`: v-tag release, VERSION check, combined-management and engine image builds for linux/amd64 and linux/arm64, GHCR push, keyless Cosign signing, CycloneDX SBOM attachment, image digest manifest, changelog extraction, CSAF archive and GitHub release. No CI dependency is declared.
- `build/Dockerfile.mgmt:3-35`: docs, static Next UI and CGO-free combined Go binary built separately. `deploy/docker-compose.yml:104-126` supplies public starter JWT requirement, HTTP/HTTPS/SSH publications, persistent data and combined mode. Hardening is commented guidance (:128-143), not enabled policy.
- `deploy/docker-compose.dev.yml:14-97`: source-built combined root appliance, NET_ADMIN/NET_RAW/NET_BIND_SERVICE, Docker socket bind, TUN and mutable dev tag. `deploy/docker-compose.smoke.yml:1-37`: root appliance, lab mode, empty JWT secret, fixed token, publicly published management/engine/SSH ports and shared fixture data. Smoke helper services and two networks occupy :39-113.
- `.env.example:43-46,88-109`: combined/split engine URL/address controls, blank JWT template, documented universal bootstrap credentials, Secure-cookie override, trusted proxies and allowed origins.
- `CONTRIBUTING.md`: build/test/release-version conventions, subsystem ownership, dev verification, coverage/performance tools; missing AGENTS.md is onboarding/discoverability debt, not a vulnerability.

Additional lab deployment inventory (deployment only; IEC104 B–E behavior remains in progress, not reassessed): `test/iec104/compose.yml:17-57` requires branch-local image refs/pull_policy never, root network capabilities, forwarding sysctl, ephemeral **loopback host** engine/mgmt publications and tmpfs data; endpoints have dedicated per-zone networks and health dependencies (:59-105). Unlike smoke compose, it avoids fixed/global host ports, but :30-38 still explicitly binds internal APIs on container interfaces and uses empty-secret lab auth: host loopback publication is not zone-to-engine isolation (Q1/Q7). `test/iec104/preflight/compose.yml:1-100` runs a separate disposable preflight tool (not product management), no host port publications, fixed two subnets, NET_ADMIN/NET_RAW and results bind. Endpoint/capture Dockerfiles pin Alpine digests; endpoint verifies lib60870 archive SHA256 and includes corresponding source/license (`test/iec104/endpoint/Dockerfile:15-43`), explicitly harness-only GPL image, not linked into containd. Preflight uses mutable golang:1.25/alpine:3.22 (`preflight/Dockerfile:1,7`) versus repo Go 1.26.9, requiring a toolchain-resolution/reproducibility check by the harness owner, not an assumed build failure. Capture helper is expressly host-network tcpdump for the throwaway bridge (`capture/capture.Dockerfile:1-7`); do not confuse its privileges with shipped product behavior.

### Package test inventory and coverage limits (Verified static inventory)

Tracked Go inventory: **322 non-test Go files, 227 test files, 1,154 Test-prefixed declarations (includes TestMain), 23 Fuzz-prefixed declarations**. Counts include build-tagged tests and fixture tools; they are neither executed-test counts nor coverage. Complete package inventory below is `source / test files / Test* / Fuzz*`:

| Package | Counts | Package | Counts |
|---|---:|---|---:|
| api/engine | 4/2/8/0 | api/http | 34/22/126/0 |
| cmd/containd | 2/1/1/0 | cmd/ngfw-engine | 1/0/0/0 |
| cmd/ngfw-mgmt | 2/1/3/0 | pkg/app/engine | 10/10/23/0 |
| pkg/app/mgmt | 9/8/34/0 | pkg/cli | 38/9/44/0 |
| pkg/common | 2/1/2/0 | pkg/common/logging | 3/1/5/0 |
| pkg/common/metrics | 1/0/0/0 | pkg/common/ratelimit | 1/1/8/0 |
| pkg/cp/audit | 2/1/1/0 | pkg/cp/compile | 2/3/9/0 |
| pkg/cp/config | 15/12/56/0 | pkg/cp/identity | 1/1/4/0 |
| pkg/cp/ids | 13/7/76/0 | pkg/cp/services | 15/15/40/0 |
| pkg/cp/templates | 4/1/15/0 | pkg/cp/users | 2/2/25/0 |
| pkg/dp/anomaly | 2/3/15/0 | pkg/dp/capture | 11/11/67/0 |
| pkg/dp/conntrack | 5/2/2/0 | pkg/dp/dhcpd | 3/1/1/0 |
| pkg/dp/dpi | 4/7/64/1 | pkg/dp/ebpf | 9/2/14/0 |
| pkg/dp/enforce | 2/3/30/0 | pkg/dp/engine | 21/23/88/0 |
| pkg/dp/events | 4/4/15/0 | pkg/dp/export | 3/1/9/0 |
| pkg/dp/flow | 2/2/6/0 | pkg/dp/ics/bacnet | 2/2/11/2 |
| pkg/dp/ics/cip | 2/2/24/2 | pkg/dp/ics/dnp3 | 4/5/36/3 |
| pkg/dp/ics/eventfields | 3/1/4/0 | pkg/dp/ics/eventfields/decodertest | 2/0/0/0 |
| pkg/dp/ics/iec104 | 4/8/26/3 | pkg/dp/ics/iec61850 | 1/1/12/0 |
| pkg/dp/ics/modbus | 2/5/24/2 | pkg/dp/ics/opcua | 2/2/13/1 |
| pkg/dp/ics/s7comm | 2/2/32/1 | pkg/dp/ids | 1/1/2/0 |
| pkg/dp/inventory | 1/1/9/0 | pkg/dp/itdpi | 10/10/56/8 |
| pkg/dp/learn | 1/2/9/0 | pkg/dp/netcfg | 16/2/4/0 |
| pkg/dp/pcap | 12/7/20/0 | pkg/dp/rules | 5/4/25/0 |
| pkg/dp/session | 4/3/7/0 | pkg/dp/signatures | 5/6/23/0 |
| pkg/dp/stats | 1/1/5/0 | pkg/dp/synth | 1/1/4/0 |
| pkg/dp/verdict | 1/1/1/0 | pkg/mp/sshserver | 5/2/8/0 |
| test/iec104/malformer | 3/1/8/0 | test/iec104/preflight | 4/0/0/0 |
| test/iec104/queueholder | 1/0/0/0 | | |

IEC104 counts are inventory only; its current contract/feature work is not reassessed. decodertest is a test helper, not an untested product capability.

- Real SQLite lifecycle tests exist (`pkg/cp/users/store_test.go:29-402`, `mfa_test.go:58-121`); auth tests cover oversized bodies, origin/forwarded-origin checks, login throttling, logout/revocation, forced-change and viewer denial (`api/http/handlers_auth_test.go:92-291,315-341,529-683`). MFA challenge/enroll/requirement/grace cases exist (`handlers_auth_mfa_test.go:19-302`). These are strengths, not proof of SSH parity.
- `pkg/dp/dhcpd/manager_other_test.go:4,16` is the sole DHCP direct test and is **!linux**. `pkg/dp/netcfg/forwarding_test.go:14-79` tests sysctl-file parsing and forwarding necessity; `netcfg_other_test.go:4,17-70` tests unsupported-platform behavior, not Linux address/route/WireGuard mutations. `conntrack_linux_test.go` exists but test presence alone does not establish useful live-kernel coverage.
- Linux kernel tests have explicit privilege/opt-in gates (`pkg/dp/enforce/iec104_kernel_linux_test.go:24-29`, `pkg/dp/capture/nfqueue_kernel_linux_test.go:29-43`). No explicit privileged-kernel CI job enables them. Their implementation belongs to the in-progress IEC104 work; this is a CI activation observation only.
- `scripts/coverage-report.sh:78,99-131` runs host-platform tests, computes total statement coverage and **unweighted package averages** per category. It clears GOFLAGS and does not label output by GOOS/commit or enforce thresholds. `docs/mkdocs/audit-baseline.md:68-85` records historical 58.9% total; its netcfg 100% explicitly covers non-Linux, and DHCP 90% cannot establish Linux runtime coverage. Do not use that snapshot as current Linux acceptance evidence.
- `ui/playwright.config.ts:6-21`, `ui/tests/route-smoke.spec.ts:5-40` provide a headless dev-server route harness with mocked APIs; `docs/mkdocs/testing.md:54-73` correctly calls it shallow but incorrectly says these regressions fail in CI. CI never runs `test:routes`; no real browser/backend auth/TLS/deployment integration job exists.
- Parser fuzz targets and performance/smoke scripts exist; ordinary `go test -race ./...` runs fuzz seeds, not sustained mutation campaigns. CI has no fuzz-duration/corpus artifacts, benchmark regression gate, forwarding/NAT/DPI smoke-script execution, or commit-specific published coverage artifact.

### Security/operator API, UI and CLI inventory (Verified)

- HTTP: `api/http/server.go:196-242,350-384` registers login/MFA/logout/self-account/session; admin user/MFA lifecycle; TLS/trusted-CA; config backup/import/export/commit; audit; CLI/WS. Session auth uses HS256 allowlisting, persistent revocation/expiry and current DB role (`auth.go:184-212,237-290`), 30-minute idle / four-hour maximum TTL (:29-32), Strict/HttpOnly cookie (:333-340), same-origin middleware before session refresh (`server.go:209-211`), body limits (:197) and explicit trusted proxies (:174-191). Health and metrics intentionally remain unauthenticated (:198-201).
- UI: `ui/app/login/page.tsx:77-116` implements password plus MFA challenge; `ui/components/Shell.tsx:152-218,525-618` orchestrates forced-password/MFA enrollment. `ui/app/system/users/page.tsx:69-271` and `users-sections.tsx:148-356` provide create/edit/delete/password reset and MFA require/grace/reset controls; `ui/app/system/settings/page.tsx:51-83,107-175` provides TLS status and cert/CA upload; `ui/app/audit/page.tsx:11-79` provides audit search/table. `/sessions` is **network conntrack**, not identity/session administration (`ui/app/sessions/page.tsx:64-87`); there is no identity-session inventory/revoke-all surface in the users Store interface (`pkg/cp/users/store.go:49-65`).
- CLI: `pkg/cli/registry.go:28-145` explicitly labels view/admin commands: show auth/system/mgmt listeners/audit, HTTPS enable/listen/redirect/HSTS, SSH password/key-dir/rotation/shell-mode, export/import/factory-reset/commit. `rbac.go:25-49` defaults unknown roles to view. HTTP CLI fixes the loopback destination rather than trusting Host (`api/http/cli_handlers.go:159-230`); SSH is admin-only and can enter a Linux shell (`server.go:251-259,329-332`). Direct `containd cli` logs in against management using env/default credentials (`cmd/containd/main.go:127-134,231-252`).
- TLS: P-256 self-signed bootstrap, one-year certificate, 0600 key (`pkg/app/mgmt/tls_support.go:224-274`), TLS >=1.2 hardened suites (`mgmt.go:294-307`), hot-reload via mtimes (:178-195), admin cert/key pair validation and /data path restrictions (`api/http/system_handlers.go:106-145`). HTTP/HTTPS and SSH destination-interface access toggles exist; these do not wrap engine API (`http_support.go:155-228`).
- Disclosure/evidence: public VDP, safe harbor, response expectations (`SECURITY.md:18-64`), security.txt/CSAF discovery (:118-128), signed-image/digest/update guidance, audit/event/syslog/metrics surfaces. Threat model correctly scopes Docker routing/bypass and excludes host kernel compromise (`docs/mkdocs/threat-model.md:18-22,164-172`), but misses important actual trust boundaries detailed below.

## 2. Maturity ratings

These are implementation/assurance ratings, not certifications or measured exploit resistance.

| Capability | Rating | Evidence / qualification |
|---|---|---|
| CI baseline/static checks | solid | Linux race, tidy/vet/lint, curated Semgrep, docs/UI builds, quickstart, blocking combined-image Trivy (`ci.yml:11-219`) |
| Coverage evidence by package/platform | partial | Local host-sensitive tool; no CI coverage artifacts/thresholds; DHCP/netcfg Linux gaps above |
| Kernel/container policy integration | partial | Smoke scripts and opt-in kernel tests exist; explicit CI privileged networking matrix absent |
| Parser fuzz target breadth | solid | 23 declarations across ICS/IT-DPI/reassembly; not a campaign-success claim |
| Sustained fuzz/corpus/regression service | absent | No duration-based fuzz workflow or corpus archival in `.github/workflows/ci.yml` |
| Browser/backend security integration | absent | Existing route harness mocks API; not invoked by CI |
| Performance assurance | partial | `scripts/perf-baseline.sh` and benchmarks exist; no regression acceptance gate |
| Multi-arch delivery | partial | Both images built for amd64/arm64; only runner-arch combined image smoke/scan in CI |
| Image signing | solid | Release signs both digest references via keyless Cosign (`release.yml:93-100`); remote results unverified |
| Release acceptance/promotion | partial | Push precedes signing/SBOM/changelog; no CI dependency; prereleases move latest |
| SBOM integrity/completeness | partial | CycloneDX attachments exist; no explicit signed SBOM attestation/per-platform inventory/static-UI dependency proof |
| Continuous dependency health | partial | Locked modules/npm, pinned actions/runtime digest, Trivy; npm audit nonblocking; scheduled refresh/govulncheck/secret gate absent |
| Local web auth/MFA/RBAC | partial | Substantial real handlers/tests; simple two-role model; sessions survive password/MFA change |
| Cross-interface account assurance | partial | SSH admin auth exists but bypasses MFA/forced-change and allows root shell |
| Engine management boundary | partial, unsafe default | Unauthenticated all-interface control API plus global input accept; highest-priority defect |
| Bootstrap / deployed transport defaults | partial | Secret startup guard, but universal bootstrap, global publications, cleartext HTTP, Secure-cookie override |
| Secret handling | partial | bcrypt, read/export redaction and restrictive backup/key writes; plaintext TOTP/VPN state and env signing secret |
| TLS lifecycle | partial | TLS1.2+/cert validation/hot reload; fail-open HTTPS bootstrap, non-atomic replacement, no expiry handling |
| Additional outbound CA support | stub | Upload/display exists; no trust-store consumer found |
| Audit/evidence | partial | Good surfaces, incomplete identity/TLS writes, ignored persistence errors, no raw-shell recording |
| Container hardening profiles | absent as tested profile | Root combined appliance with broad default caps; hardening comments, not enabled/tested profile |
| Deployment-mode clarity | partial | Combined/dev/smoke usable scaffolds; secure split trust boundary not implemented |
| Threat-model accuracy | partial | Topology risks correct; engine/SSH/socket/lab token/session/release gaps omitted |
| Documentation / onboarding | partial | Broad embedded docs; concrete drift; missing root guide; no dedicated product-roadmap nav |
| Source size discipline | solid | No tracked authored Go/TS/JS/Python/shell/C/CSS file >1000 lines; largest Go 957; OpenAPI schema 1432 is exempt generated/spec material |
| eBPF advertised acceleration | stub | Pass-only programs, no TTL reap, no app integration; see Q16 |

## 3. Bugs and debt found (ranked)

### Q1 — Critical: engine control API is exposed across the lab trust boundary
**Verified:** `pkg/app/engine/engine.go:70-74` defaults to `:8081`; :139-187 registers raw HTTP handlers and serves them with no authentication/TLS middleware. Mutators include apply_rules, config, routing, interfaces, services, packet capture/replay and blocks (:149-181). `pkg/dp/enforce/enforce.go:124-132` explicitly accepts TCP/8081 regardless of incoming interface before local access rules. All compose modes retain this listener. **Inferred consequence:** an untrusted attached lab workload can replace policy or runtime state without a management account; absence of a published host port is not isolation on Docker bridge networks. Validate reachability from each zone before claiming exploit reproduction. This invalidates threat-model objective “Only authorized users can change policy” (`threat-model.md:28,50-52`). Reserved management-path B–E work is in progress and not assessed; isolating the engine is a separate boundary requirement.

### Q2 — High: SSH bypasses forced-change/MFA and grants the appliance OS identity
**Verified:** password callback checks role and bcrypt only; public-key callback checks role and key only (`pkg/mp/sshserver/server_auth.go:58-112`); neither checks MFA enabled/required/grace or MustChangePassword. Fresh SSH defaults enable password bootstrap when key dir is empty (`pkg/app/mgmt/ssh_support.go:124-144`). Existing test explicitly authenticates freshly seeded `containd/containd` (`server_auth_test.go:223-247`). Both Linux shell mode and appliance `shell`/`bash` reach an OS shell (`server.go:251-259,326-332`; `server_pty.go:136-147`) with no credential drop. Shipped compose runs UID 0. **Inferred consequence:** the web's MFA/forced-change controls do not protect administrative shell/secret/config access. `secure-by-design.md:47,91-99` marks MFA Done without this caveat. Decide whether raw root shell belongs in a hardened/SRA profile; it is intentional for training, not a policy-compliant alternative to MFA.

### Q3 — High: credential/MFA changes leave existing sessions valid
**Verified:** `pkg/cp/users/store.go:420-467` updates password/TOTP fields without revoking sessions. Password handlers call only SetPassword (`api/http/auth_handlers.go:284-297`, `users_handlers.go:114-128`); MFA handlers call only SetTOTP/DisableTOTP plus requirement updates (`auth_mfa.go:245-321`). Session schema has no assurance/authentication epoch (`store.go:142-149`); middleware checks persisted expiry/revocation/user, not password-change time or MFA satisfaction (`auth.go:193-255`). **Inferred consequence:** a stolen pre-change session remains authorized until expiry/revocation; enabling MFA does not step it up. Deleting a user does remove sessions (:396-415), logout revokes the presented session, and current DB roles are re-read—do not confuse this gap with no session invalidation whatsoever.

### Q4 — High: network-facing insecure onboarding/transport defaults
**Verified:** `deploy/docker-compose.yml:104-112` requires a JWT secret but publishes HTTP/HTTPS/SSH on all host interfaces and defaults COOKIE_SECURE=0; `.env.example:93-99` documents universal bootstrap and disables Secure. `mgmt.go:204-210` enables HTTP with no default redirect. `api/http/auth.go:351-356` honors explicit false even on TLS. Universal credentials are actually seeded (`users/store.go:163-171`). **Inferred consequence:** network-observable onboarding/login tokens and a race to claim the first admin, especially shared classrooms. Improve defaults for container labs, not a physical firewall appliance. Redirect alone is insufficient: `tls_support.go:139-142` deliberately passes POST/non-GET through cleartext; disable external HTTP writes or bind HTTP loopback. Standard web forced-change is real but does not close the SSH gap.

### Q5 — High: development profile provides host Docker API authority
**Verified:** root dev appliance mounts `/var/run/docker.sock:ro` (`deploy/docker-compose.dev.yml:21-26,84-88`). Read-only bind mounting a Unix socket does **not** authorize Docker API calls read-only. **Inferred consequence:** root shell or process compromise can escalate to Docker host/other containers, including unrelated lab projects. Public starter has no socket. Threat model excludes host-kernel compromise, but should include this project-created host-control interface rather than treating it as an external compromise prerequisite.

### Q6 — Medium: remote resource bounds / throttling incomplete
**Verified:** SSH limiter key uses `RemoteAddr().String()` including reconnect-varying source port (`server_auth.go:63`); listener creates an unbounded goroutine per accepted connection and no handshake deadline (`server.go:114-127,154`). HTTP servers have no ReadHeaderTimeout/IdleTimeout (`pkg/app/mgmt/http_support.go:61,80`; engine.go:184-187). CLI WS calls ReadMessage without SetReadLimit (`api/http/cli_handlers.go:125-155`). **Inferred:** slow connections and large authenticated WS frames can consume resources; reconnects defeat the intended SSH brute-force bucket. Default HTTP header byte limits still exist in Go; do not describe this as unbounded header size.

### Q7 — Medium (high in exposed smoke mode): lab auth is broader than fixed workshop credentials
**Verified:** lab middleware promotes every accepted token to admin and does not consult DB sessions; empty-secret validation accepts any nonempty token (`api/http/auth.go:73-90,140-146`). Smoke enables precisely empty-secret lab mode and publishes HTTP, HTTPS, engine, SSH globally (`deploy/docker-compose.smoke.yml:18-20,33-37`). A nonempty-secret lab token need only be validly signed; its view role is ignored. This is more than “pinned containd password”; document the real boundary. Password pinning is also inconsistent: HTTP blocks changes but SSH menu/wizard directly SetPassword (`server_menu.go:154-173,440-453`), contradicting `secure-by-design.md:120-139` and `threat-model.md:102`. Wizard also ignores SetPassword failure and prints success (:451-453).

### Q8 — Medium: weak nonempty JWT secrets accepted; secrets-at-rest incomplete
**Verified:** startup rejects only empty and one exact example secret outside lab mode (`pkg/app/mgmt/mgmt.go:125-140`), not minimum strength. Bootstrap scripts do generate 32 random bytes (`scripts/bootstrap-starter.sh:51-68,294-296`) and rewrite via mktemp/mv (:78-97), a positive default path. TOTP seed is plaintext SQLite text (`users/store.go:135,446`); WireGuard/OpenVPN private key/password fields explicitly defer encryption (`config/config.go:285,321-326`) and config store marshals JSON into SQLite (`store.go:159-175,201-212`). HTTP config reads redact, unredacted export is admin-only (`server.go:397-400`; `config_backup_handlers.go:38-58`), backup writes use 0600 (:274,284), TLS/SSH keys use 0600. **Inferred:** backups/data access or UID0 shell exposes credential material; env-secret rotation invalidates JWTs globally but offers no scoped rotation/key lifecycle. Document a deliberate at-rest trust model before adding encryption whose key is stored beside the ciphertext.

### Q9 — Medium: trusted-CA upload is disconnected and validation is too weak
**Verified:** `api/http/system_handlers.go:156-195` writes PEM to the configured/default file, while `readAnyPEM:199-213` accepts any PEM block (not X.509 CA validation). Whole-repo Go reference search found TrustedCAFile only in config field/validation, upload, and CLI display—no RootCAs consumer. UI explicitly promises additional outbound TLS trust (`ui/app/system/settings/page.tsx:157-175`); config comment makes same promise (`config.go:94-96`). **Inferred:** operators can get a successful upload without the advertised TLS trust change. Implement actual consumers and reload contract, or remove the stub UI/API promise; a saved file is not working outbound trust.

### Q10 — Medium: TLS fail-open bootstrap, expiry omission, non-atomic replacement
**Verified:** certificate-generation failure warns and disables HTTPS while startup continues (`mgmt.go:220-224`). Existing files return immediately without parse/expiry checks (`tls_support.go:208-215`). Upload writes key then cert in separate filesystem operations (`system_handlers.go:138-145`), hot reload attempts either mtime change and returns error rather than last-good cert on mismatch (`tls_support.go:178-195`). **Inferred:** replacement can transiently break handshakes, or remain broken after second write failure; an expired cert can survive restart. TLS-info API reads saved config/default paths, ignoring startup env overrides (`system_handlers.go:49-54` versus `tls_support.go:28-43`, mgmt.go:231-249), so Settings can misreport effective listener/certificate state. Require valid cert before external HTTPS startup, atomic pair publication and last-good reload, and runtime-derived status. No live handshake reproduction performed.

### Q11 — Medium: security audit trail is incomplete and failure is silent
**Verified:** user CRUD/reset (`api/http/users_handlers.go:39-150`), self-password (`auth_handlers.go:254-298`), TLS/CA writes (`system_handlers.go:88-195`) have no auditLog call. MFA/login/config do log. `api/http/server.go:765` ignores audit Store.Add errors; SSH execution similarly ignores Add (`server.go:272-285`). Raw Linux shell bypasses per-command audit (`server.go:329-332`). SQLite audit supports append/list/wipe but no retention/integrity chain or durable external ack (`pkg/cp/audit/store.go:26-34,69-128`). **Inferred:** password/cert changes or full disk can leave no usable security evidence; arbitrary root shell can tamper with local evidence. Docs overstate completeness (`logging-evidence.md:19,79`; secure-by-design.md:53). Trace identity, assurance level, success/failure, session, target and secret-free change metadata consistently; surface degraded audit persistence rather than silently calling it done.

### Q12 — Medium: publication precedes acceptance, and prereleases replace stable latest
**Verified:** release triggers every `v*` tag, checks VERSION, then pushes mgmt/engine version and `latest` tags (`release.yml:9-11,47-86`). Signing/SBOM follow (:93-119), changelog validation follows even later (:130-142). GitHub prerelease classification occurs only at :168; `latest` publication is unconditional. No `needs`/workflow_run/reusable CI dependency, release scan or test step exists. CI only triggers main push/PR (`ci.yml:6-9`); tag-only and iec104 changes are not inherently checked. **Inferred:** a failed release can already have changed consumable tags, an unsigned/unvalidated image can briefly be live, and evaluation releases can become classroom latest. Repository branch/tag rules and actual remote checks are unknown; do not assume absence of organizational controls, but do not rely on them without evidence.

### Q13 — Medium: incomplete multi-arch/image SBOM and vulnerability acceptance
**Verified:** release builds two image manifests for amd64+arm64 (`release.yml:59-91`); CI only builds/loads/scans combined `Dockerfile.mgmt` for runner default architecture (`ci.yml:105-115,212-219`). No engine-image/arm64 runtime test or explicit per-platform scan/SBOM matrix exists. Release Cosign signs image digests; `cosign attach sbom` is an attachment, not explicit signed SBOM attestation (`release.yml:115-119`), unlike README.md:152's “SBOM attestation.” Final image copies only UI export, not npm lockfile (`Dockerfile.mgmt:86`); SBOM docs claim npm enumeration from package-lock (`sbom.md:26`). **Inferred/open:** actual SBOM npm completeness and which platform Syft selects from the manifest require inspecting released artifacts; the workflow alone cannot establish them. Signature verification example trusts a broad repository regexp rather than exact release workflow/ref (`sbom.md:81-84`). Lock signer identity and digest, verify signed provenance/SBOMs, and retain source/build dependencies as separate evidence where not shipped.

### Q14 — Medium: continuous dependency/secret assurance incomplete
**Verified:** npm audit deliberately succeeds on findings (`ci.yml:77`). No Dependabot/Renovate config, scheduled vulnerability workflow, govulncheck or dedicated secret-scanning gate appears in tracked automation. `.trivyignore` contains only policy comments, no current suppressions. Trivy CI is blocking for combined runtime image; local `--with-trivy` fs scan lacks `--exit-code 1` (`scripts/dev-verify.sh:150-178`) and scans only vulnerabilities, not secrets. Builder/Envoy tags are mutable, OS apk packages are unversioned (`Dockerfile.mgmt:3,12,21,37,49,55-69`; engine:6,25); Wolfi final base **is digest pinned** (:46,51). Local ineffassign uses @latest and ShellCheck uses stable; Semgrep uses remotely changing `--config auto` and rule/path-wide allowlists (`semgrep-verify.sh:31-39,53-61,78-105`). Thus “reproducible” (`audit-baseline.md:116`) is stronger than the workflow guarantees. Old/pseudo-version dependencies in `go.mod` (Gin 1.9.1, SQLite 1.27.0, 2018 shellquote/syslog, etc.) warrant maintenance review, not an unsupported assertion of current CVEs. **No current vulnerability count, dependency EOL determination or clean bill of health was established**; scanner/platform/artifact verification belongs to release owners.

### Q15 — Medium: container blast radius / profile hardening remains guidance-only
**Verified:** combined image has no USER directive (`build/Dockerfile.mgmt:51-95`); public/dev/smoke explicitly run root. Starter adds NET_ADMIN/NET_RAW/NET_BIND_SERVICE/**SYS_TIME** with no cap_drop (`deploy/docker-compose.yml:64-69`); read-only rootfs, no-new-privileges, resource/pid/log limits are commented (:128-143). Root process includes network enforcement, management auth, shell and multiple embedded services. Engine image is smaller (nftables only) but has no readiness healthcheck/USER (`Dockerfile.engine:22-36`). **Inferred:** UID0 service/shell compromise affects full appliance and, depending on Docker isolation, host/VM time via SYS_TIME; actual host capability behavior is not reproduced. Dev/smoke non-WAN networks are not marked internal, unlike starter (`dev.yml:132-164`, smoke:103-113 versus starter:185-226). Topology isolation is partly correct, but it does not protect management API from attached workloads. Offer isolated training and hardened container-workload profiles, not a promise that the full dataplane is rootless. SYS_TIME should be opt-in, not a general appliance privilege.

### Q16 — Medium: dormant eBPF skeleton is advertised as acceleration
**Verified:** `pkg/dp/ebpf/xdp.go:37-49` always XDP_PASS; `tc.go:41-56` always TC_ACT_OK; `updater.go:49-52` says TTL reaping not implemented. App constructs nftables updater, not eBPF (`pkg/app/engine/engine.go:49-56`); repository reference search found no outside-package constructor integration. `tc.go:23-38` returns an 8-byte map key spec; init mutates a freshly allocated/discarded map, so future calls still return 8 instead of the intended 12 bytes. `attachTC` claims older-kernel fallback (:62-63) but only invokes AttachTCX (:71-75). Existing tests mostly cover fallback/serialization/non-Linux stubs (`ebpf_test.go:16-159`, ebpf_other_test.go:16-77), not actual packet drops. README.md:80 and docs/mkdocs/ebpf.md:3 claim functional kernel acceleration/counters/events/automatic enablement. Treat as dormant/stub code, not security coverage or working enforcement; implement with Linux packet evidence or remove claims/code. No general dead-code analyzer was run; this is a specific disconnected subsystem, not proof of all unreachable code.

### Q17 — Medium: Linux coverage and continuous integration evidence are overstated
**Verified:** package inventory/CI activation gaps in §1; `coverage-report.sh:78,101-131` uses host platform/unweighted averages and no threshold. Historic non-Linux stubs can score highly while live DHCP/netcfg/conntrack are unproved. CI omits browser harness, sustained fuzz, forwarding/NAT/DPI scripts, explicit privileged-kernel job, benchmarks and coverage artifact. The quickstart HTTP smoke **does exist** (`ci.yml:116-211`) and checks forced password change, interfaces, routing, telemetry shapes and synthetic traffic; it is not end-to-end traffic/security-policy acceptance. `docs/mkdocs/testing.md:73` says malformed-route regressions fail in CI although no route job runs. Avoid target-count vanity: prioritize negative security/lifecycle cases and platform-tagged coverage as quality evidence, not a global percentage target alone.

### Q18 — Medium: last-admin safeguard applies to deletion, not demotion
**Verified:** `pkg/cp/users/store.go:350-378` accepts valid role changes without counting admins, whereas Delete checks last-admin (:381-394). `api/http/users_handlers.go:70-91` permits this patch; UI role editing exists (`ui/app/system/users/page.tsx:92-122`, users-sections.tsx role controls). **Inferred:** an admin can accidentally demote the sole admin and lock out policy administration, especially serious in longer-lived classroom/SRA control planes. Add transactional last-admin constraints for both operations; tests presently explicitly cover deletion (`store_test.go:171`, handlers_auth_test.go:638), not this path. Adjacent maintainability debt: profile Update contains always-true conditions (`store.go:356-364`) that unconditionally overwrite omitted name/email fields; review patch semantics instead of preserving tautologies.

### Q19 — Medium: MFA challenge/OTP replay resistance is not implemented
**Verified:** `api/http/auth_mfa.go:94-122` signs stateless five-minute login/enroll challenges without a one-use identifier, credential epoch or consume operation. `loginMFAHandler:136-161` validates current TOTP then creates a new session; no consumed challenge/OTP timestep is recorded. `pkg/cp/users/mfa.go:78-91` uses stateless TOTP validation with ±one 30-second step. **Inferred:** a captured valid challenge+code pair can mint more sessions while the OTP/challenge remain valid, even after a password change; no replay was attempted. This is distinct from stealing a session token and important for SRA assurance. Add single-use password-proof challenges, reject reused timesteps atomically, bind credential epochs, and test concurrent replay; do not claim phishing resistance for TOTP.

### Q20 — Low/Medium: CLI and effective-runtime operator contract gaps
**Verified:** `cmd/containd/main.go:231-254` direct CLI login expects only token and cannot complete the implemented MFA challenge, so an MFA-enabled account receives “empty token” rather than a second-factor prompt. It hardcodes HTTP loopback (:125), which breaks with HTTP disabled, and sets local RoleAdmin regardless of account role (:134), though API enforcement still checks the real role. It has only one direct command-entry test (`exit_code_test.go`). A hardened HTTPS/MFA cutover therefore needs CLI support/tests, not just a checkbox. Healthcheck likewise probes plain HTTP and checks only 200 (`main.go:94-113`); disabling HTTP can make a healthy HTTPS-only appliance unhealthy. `/api/v1/health` is intentionally liveness 200 (`health_handlers.go:32-55`); compose health must not be interpreted as dataplane readiness. IEC104 health content is in progress and not reassessed here.

### Q21 — Low: security/advisory/docs drift (Verified)

| Location | Drift / cross-check |
|---|---|
| `docs/README.md:4-5` | `docs/tasks.md` and `docs/spec-archive/` do not exist in tracked tree/current filesystem; missing product roadmap and historical-spec pointers. `docs/mkdocs/README.md` repeats archived-spec pointer. |
| `docs/mkdocs.yml:46-80` | No dedicated product-roadmap navigation entry; security roadmap is buried at `secure-by-design.md:291-310`. |
| `SECURITY.md:128`, `security/csaf/README.md:15`, `advisories.md:90` | Say no advisories / intentionally empty, but `security/csaf/advisories/containd-2026-001.json` exists and advisories.md:45 lists it. |
| `security/csaf/advisories/containd-2026-001.json:63-75,99-105` | Same unversioned product_id is both first_affected and fixed; human text identifies 0.1.16/0.1.17 but machine consumers cannot distinguish product versions. CSAF schema/semantic validation is manual guidance, not a workflow gate. |
| `docs/mkdocs/SPDX.md:27,29,33,37` | Describes Nginx copied from nginx-unprivileged, OpenNTPD, Debian nftables, Recharts; image installs Wolfi nginx-mainline/chrony/nftables and UI package.json lacks Recharts. README.md:86 also still says OpenNTPD. |
| `README.md:141`, `CONTRIBUTING.md:34-36` | Source-run / direct cloned-compose example omits required nonempty JWT setup. `docs/mkdocs/docker-compose.md:31-33` copies blank `.env.example` then starts compose without telling operator to generate secret; `:?` rejects it. Main quickstart script correctly generates one. |
| `docs/mkdocs/cli.md:80,98` | Lab mode is not literally no auth: a nonempty token is required, and configured secret verifies JWTs. SSH does allocate PTYs/launch bash. |
| `docs/mkdocs/audit-baseline.md:49,85,116` | Largest source is now validate.go 957, not api.ts 887; historic coverage/platform and reproducibility claims need qualification. |
| `README.md:28,104-115`; `lab-compose.md:36`; `docker-compose.md:3,79-86` | Promise stable eth0–eth7 role order, while same compose docs :102-108 correctly say kernel attach order is not guaranteed and source uses subnet matching. Teach logical zone/subnet binding rather than a guaranteed ethN table. |
| `docs/mkdocs/api-reference.md:78` | Advertises CONTAIND_MGMT_HTTP_ADDR as runtime listener variable; executable reads CONTAIND_MGMT_ADDR (`mgmt.go:231-239`). Compose performs the translation. Distinguish host template variable from process env. |
| `docs/mkdocs/api-reference.md:96,123-126`; `docs/openapi.yaml:1320-1344` | Claims strong JWT enforcement despite narrow guard; human docs and OpenAPI advertise `/api/v1/engine/config`, which is absent from server route registry. Dataplane config is `/api/v1/dataplane` (`server.go:282-283`), internal raw config is `/internal/config`. |
| `docs/mkdocs/index.md` Config reload bullet; `api-reference.md:72` | Implies partial config reload via SIGHUP, but handler only logs “not yet fully implemented” (`cmd/containd/main.go:53-58`); no reload is invoked. |
| `SECURITY.md:16` versus `update-policy.md:9-11` | “0.1.x supported” is broader than latest-stable/no assumed-backports support posture; clarify exact supported versions. |
| `pkg/cp/config/config.go:33` | Says no persisted secrets immediately above code redacting persisted VPN secrets (:55-63). |

A static relative-Markdown-link existence check of README/docs found no missing `](relative-path)` targets; it does **not** cover backticked pointers such as docs/tasks.md, anchors, external URLs, or semantically stale commands. MkDocs is not run with `--strict` in CI (`ci.yml:62`), so successful generation alone is not a docs-truth gate. `ui/public/.well-known/security.txt:2` expires in 2027 and was not expired on audit date; do not report it as stale merely because other advisory text drifted.

### Q22 — Low: file-size/onboarding/maintenance enforcement
**Verified:** tracked authored Go/TS/JS/Python/shell/C/CSS candidates contain no file >1000 lines; largest Go is `pkg/cp/config/validate.go` 957, `api/http/server_domains_test.go` 890, config.go 861. The 1432-line `docs/openapi.yaml` schema is separately reported, not an oversized executable source finding. No root/nested AGENTS.md/CLAUDE.md exists; CONTRIBUTING supplies useful boundaries but duplicated “Local Verification” headings. No CI file-size regression gate appears. Keep architectural/validation facts in repo guides; app-owned operating policy belongs outside the repo. Do not split healthy files purely to chase a number.

### Q23 — Low/Medium: bootstrap and classroom reproducibility are mutable by default
**Verified:** README.md:22-23 downloads and executes a script from main; quickstart downloads bootstrap from `CONTAIND_REF` default main (`scripts/quickstart.sh:6,30`); bootstrap downloads compose/env at that ref (`bootstrap-starter.sh:279-285`) and starter image defaults latest (`deploy/docker-compose.yml:61`). No script digest/signature verification is performed. Ref/image overrides are supported, so pinning is possible. **Inferred:** repeating a course later can select a different source/compose/image set; quickstart does not automatically verify signed release artifacts. Provide a tested release-pinned manifest/offline bundle; avoid presenting unauthenticated script execution from a moving branch as equivalent to verified image provenance.

### Q24 — Low/Medium: some tests establish presence, not the advertised success contract
**Verified:** `pkg/cp/users/store_test.go:215-222` checks successful SetPassword postconditions only **if err == nil**, never fails on an unexpected error from that valid-password call. It also never verifies the new password hash or old-session invalidation. `api/http/route_inventory_test.go:144-184` accepts all 4xx and 501/503 for every route; useful panic/shape smoke, not authorization or operation-success coverage. `pkg/dp/conntrack/conntrack_linux_test.go:10-41` only parses a sample text line, not live conntrack reads/deletions. NTP tests include fake-binary detection/status/rendering (`pkg/cp/services/ntp_test.go:184-204`), which cannot establish actual daemon/capability compatibility. Keep these useful unit tests but label their assurance level and add explicit success/failure assertions plus real integration acceptance. No test was executed; these are directly read assertion gaps.

### Q25 — Low: UI docs prebuild can bless stale generated docs
**Verified:** `ui/scripts/build-docs.js:59-75` returns null when MkDocs is unavailable. If existing docs index exists, :94-97 writes the **new source hash** without rebuilding; next invocation exits on hash equality (:82-85), even if MkDocs has since become available. If no MkDocs and no index, the script falls through successfully without building docs (:94-105). Docker has a real docs-builder, so this is a local UI-prebuild/reproducibility gap rather than proof released docs are stale. Fail explicitly or keep source/output provenance honest; do not stamp stale artifacts current. Add a small headless script test for missing tool, stale output, later tool install and build failure; no Node script was executed by this audit.

## 4. Ranked gaps versus a mature training/containerized industrial firewall

1. **Trust-boundary correctness before more SRA features.** The engine must not be controllable from student/zone traffic (Q1), and every administrative entry must honor one account-assurance contract (Q2–3,Q7,Q19–20). A web MFA badge is not a secure remote-access boundary when SSH/root shell bypasses it.
2. **Safe shared-classroom defaults and bounded blast radius.** Separate deliberate insecure-workshop behavior from ordinary onboarding; loopback/private-management exposure, per-instance credentials, secure transport, no Docker socket, optional SYS_TIME, bounded HTTP/SSH/WS and tested least-privilege profiles (Q4–8,Q15). This benefits labs and container-workload protection without expanding into ISO/appliance scope.
3. **Release acceptance and recoverable promotion.** Validate exact commit, both images/architectures and immutable artifacts before moving consumer tags. Stable courses should not ingest prereleases or half-completed releases (Q12–14,Q23). Preserve last-known-good manifests, data/config migration/restore evidence and consistent support policy.
4. **Continuous evidence tied to shipped behavior.** Commit/GOOS/image-digest labeled coverage; focused Linux DHCP/netcfg/conntrack and orchestration tests; real browser/backend security flow; isolated kernel policy tests; bounded fuzz/corpus and perf tracking (Q17). Static mock/seed/stub coverage must not masquerade as end-to-end enforcement confidence.
5. **Operational identity/TLS/audit lifecycle.** Account/session inventory and revocation; last-admin invariants; effective runtime status; complete secret-free security audits with visible persistence failures; atomic cert rotation/expiry/CA consumers and tested HTTPS-only CLI/health (Q3,Q9–11,Q18–20). External log retention must survive resets/upgrades; raw shell needs explicit SRA recording/restriction policy.
6. **Honest capability/documentation surface.** Correct eBPF/CA/SIGHUP stubs, release/SBOM claims, stale docs pointers and reproducibility assertions; adopt executable command/route/doc checks and a discoverable staged product roadmap (Q9,Q16,Q21–23).
7. **Maintainable assurance, not cosmetic metrics.** Keep size boundaries (currently satisfied), modernize stale dependency edges based on real scanner data, retain clear repository architecture/validation instructions, and avoid counting a passing non-Linux stub as a hardened capability (Q14,Q17,Q22).

### Threat model correction map (Verified omissions; proposed additions)

| Existing model | Required correction / misuse case | Affected interfaces |
|---|---|---|
| `threat-model.md:50-52` “internal API boundary” | State transport/auth/listener isolation, not merely logical planes; test direct zone-to-engine mutation denial | internal HTTP, management EngineClient, nftables input, split compose |
| :90-102 MFA/forced change / bootstrap caveat | Distinguish web vs SSH/raw shell, session assurance and post-change revocation; describe lab admin promotion/empty-secret behavior | users SQLite, HTTP, SSH, CLI, UI onboarding |
| :18-22 host compromise out of scope | Include Docker socket and SYS_TIME as appliance-granted host authority, not unrelated preexisting host compromise | dev mount, root services, kernel capabilities |
| :95 request body limits | Explicitly cover slow handshakes, SSH connection fanout and WS message limits | HTTP(S), SSH, WS console |
| :133-143 version pinning/scanning/signatures | Separate built vs tested vs signed vs promoted, image index vs platform, attachment vs signed attestation | GitHub Actions, GHCR, Cosign, Syft/Trivy, quickstart |
| :153-162 audit/evidence | Enumerate absent identity/TLS/shell records and storage-write failure/retention/tampering | audit DB, logs/syslog, UI/CLI |
| :166-172 Docker topology | Keep accurate bypass warning; add private management/engine isolation requirements and negative tests from every zone | Compose networks, port publications, local-input rules |

### Validation ownership and unknowns

- **Security/API/identity owner:** HTTP+SSH forced-change/MFA parity; role changes/last-admin; password/MFA reset surviving-token negative tests; OTP/challenge replay/concurrency; SSH reconnect throttling; shell allow/deny/recording policy. Existing auth tests are useful starting points, but no new test was authored/run here.
- **Linux dataplane/deployment owner (orchestrator's isolated lab):** verify direct engine mutation denied from every zone, split identity transport, forward/NAT/DPI traffic; privileged namespace tests, Docker Desktop/macOS versus Linux behavior and capability minimization. Do not run kernel ruleset-flush tests on shared host networking.
- **Management/operations owner:** HTTPS-only startup/CLI/health; invalid/expired/rotating cert and disk-failure audit tests; outbound trust consumer; backup/restore upgrades, read-only rootfs service write-path matrix.
- **Release/supply-chain owner:** exact commit's required checks, both architectures/images, npm/static-asset SBOM completeness, signed provenance, promotion/rollback and prerelease behavior; actual registry artifacts/scans. No remote CI success, branch protection, signature validity, architecture compatibility or current CVE count is asserted by this audit.
- **Docs/quality owner:** link/backtick pointer, route/OpenAPI and env/schema drift; examples boot with generated secrets; support/advisory consistency; file-size and local/CI command parity.
- **SRA product owner:** decide whether raw OS shell is training-only or part of protected remote access, MFA requirement for key-based SSH, MFA enrollment/recovery/step-up policy and identity/session/audit requirements. External identity, scoped roles, approvals/time bounds, brokered/recorded sessions are dependencies on the dedicated SRA roadmap, not implementations invented in this lane.

## 5. Recommended staged roadmap

Sizes describe expected files/subsystems, not elapsed time. Validation owners must execute acceptance in isolated infrastructure; no publishing belongs to this audit.

### Now — close boundaries and stop unsafe promotion

**N1. Make engine control private by construction (Q1).**
- Scope/size: approximately 8–12 files; engine startup/router, EngineClient, enforcement local input, combined/split compose and threat model/tests.
- Deliver: loopback/Unix-local boundary in combined mode, remove unconditional TCP/8081 accept, authenticated confidential split transport with pinned peer identity; explicit isolated unsafe-dev switch only if needed.
- Dependencies: decide combined versus split contract and management-network ownership. Do not conflate with IEC104 B–E in-progress reserved-path work.
- Acceptance/owner: Linux deployment + API owner: unauthenticated clients in every zone cannot read/mutate internal APIs; authorized mgmt replay/commit/health still works; negative split-peer tests; no hidden host-port reliance.

**N2. One account assurance/session policy for HTTP, SSH and CLI (Q2–3,Q6–7,Q18–20,Q24).**
- Scope/size: approximately 15–22 files across users store/schema, HTTP MFA/session handlers, SSH callbacks/shell/menu, direct CLI and targeted tests/UI copy.
- Deliver: force-change/MFA before privileged access; explicit key-auth MFA policy; per-account credential epoch, revoke-all and step-up/session-assurance semantics; one-use MFA challenge/OTP replay protection; transactional last-admin invariant; source-IP-stable throttling, connection/handshake/message limits; consistent lab credential rules; correct SetPassword test assertions/wizard errors.
- Dependencies: SRA owner decides raw-shell availability and instructor recovery; N1 removes direct bypass before assurance claims are strengthened. Keep required bootstrap/enroll/recovery paths usable.
- Acceptance/owner: identity/security owner: reused pre-password-change/MFA session and OTP challenge rejected; expired enrollment blocks SSH/OS shell as well as web; sole admin cannot be demoted/deleted; reconnect brute-force and slow handshake bounded; direct CLI completes MFA; test both lab opt-in and standard policy.

**N3. Safe container-lab onboarding and immediate exposure reduction (Q4–8,Q15).**
- Scope/size: approximately 8–14 files; compose/env/bootstrap, listener/cookie/JWT startup and docs/tests.
- Deliver: loopback/private publications by default; per-instance strong bootstrap path while retaining separately isolated reproducible workshop profile; Secure cookies/HTTPS-first external writes, minimum secret checks; no dev socket by default; SYS_TIME opt-in; HTTP/SSH/WS resource bounds.
- Dependencies: N2 and functional HTTPS-only CLI/health contract (N6). Preserve headless/offline classroom bootstrap; do not silently disable authentication or add fallback tokens.
- Acceptance/owner: deployment/security owner: fresh starter never exposes unclaimed universal admin to shared network; clear failure for weak secrets; no cleartext external credential writes; intended Docker Desktop/Linux services still work.

**N4. Gate exact release artifacts before consumer-tag promotion (Q12–14,Q23).**
- Scope/size: approximately 3–6 workflow/build/docs files; CI/release contract and verification scripts.
- Deliver: validate VERSION/changelog and exact-commit CI acceptance first, build/test/scan immutable candidate digests, sign and attach verified evidence, then promote stable tags. Prerelease must never move stable latest. Serialize promotions and retain a rollback manifest.
- Dependencies: agreed image/architecture support matrix and registry promotion permissions; branch/tag protections must be checked by repository owner, not assumed.
- Acceptance/owner: release owner: simulated prerelease/missing-changelog/scan/sign failure leaves stable tag unchanged; both images' digests and identity-matched signatures verified. No lane pushes/deploys.

**N5. Correct misleading security/capability docs now (Q9,Q16,Q21–23).**
- Scope/size: approximately 10–18 docs/UI-copy files plus optional repository-root architecture/validation guide and doc checks.
- Deliver: qualify SSH/MFA/default-password/session limitations; label CA/eBPF/SIGHUP stubs; fix missing task/archive pointers, NTP/licenses, example JWT setup, variable/route docs, stable-ethN claims, current advisory/support posture and stale-docs prebuild hash handling (Q25). Add a discoverable product-roadmap page/navigation with explicit training/container scope and in-progress B–E status.
- Dependencies: none for truth corrections; implemented security changes should update docs in same feature change. App-owned sub-agent policy must not be embedded in AGENTS.md.
- Acceptance/owner: docs/quality owner: example commands match actual routes/env and fresh startup, no false Done/zero-CVE/attestation/acceleration claims; docs CI checks code pointers and strict warnings.

### Next — build trustworthy operational and Linux evidence

**N6. Complete TLS/trust/effective-runtime and audit operations (Q9–11,Q20).**
- Scope/size: approximately 12–20 files; management listeners/reloader/startup, system/audit API, CLI/health, settings/UI and tests.
- Deliver: atomic cert-pair replacement, last-good reload and expiry diagnostics, no silent HTTPS fallback, runtime-derived listener/cert status; wire/validate actual outbound CA consumers or remove the feature; exhaustive identity/TLS/credential audit with visible storage failures; HTTPS-only CLI and health; documented bounded audit retention and off-box forwarding/recovery.
- Dependencies: N2 session policy; define TLS trust-store consumers and audit failure/retention contract. Secret storage threat model must separate DB backups from raw root-shell compromise.
- Acceptance/owner: mgmt/ops owner: rotation under load, invalid/expired cert/restart, config-versus-env status, custom CA success/negative test, password/TLS/role events present, full-disk audit failure surfaced, HTTPS-only health/CLI passes.

**N7. Commit/platform-tagged Linux quality matrix (Q17,Q24).**
- Scope/size: approximately 15–25 files across test/harness/workflows and Linux runtime packages; incremental by risk, not a new giant full-suite lane.
- Deliver: archive per-package Linux coverage and raw profiles labeled commit/GOOS/arch; target netcfg/DHCP/conntrack/SSH/command-entry orchestration; separate unit/mock/stub from privileged namespace and container traffic tests; run existing route harness and real browser/backend auth/TLS tests; bounded scheduled fuzz with corpus retention; benchmark baselines/trend gates.
- Dependencies: N1–3 for expected boundaries, isolated disposable Linux namespaces and amd64/arm64 capacity. Historical 58.9% is context only; establish fresh baseline before thresholds.
- Acceptance/owner: quality + Linux owner: fail known policy/auth regressions, fail deliberate success-path test mutation, prove actual forward/NAT/DPI and service lifecycle, show per-platform skips explicitly, publish test/corpus/coverage evidence tied to image digest.

**N8. Tested least-privilege deployment modes (Q5,Q15,Q20).**
- Scope/size: approximately 8–15 build/compose/runtime/docs/test files across mgmt/engine/embedded services.
- Deliver: enumerate writable paths/capabilities; cap_drop baseline, no-new-privileges, read-only filesystem/tmpfs, pid/memory/CPU/log bounds, no Docker socket; isolate minimally privileged management where practical, protect split transport; explicit observe-only/training/hardened-container profiles and readiness distinct from liveness.
- Dependencies: N1 authenticated split transport, N6 HTTPS-only health/CLI; verify embedded services' disk/network/kernel requirements. Do not promise rootless full dataplane or host/ISO protection.
- Acceptance/owner: deployment owner: isolated Linux and Docker Desktop profile matrix, service restart and data migration/restore; compromise of management process does not inherit engine/host authority beyond agreed contract; denied capabilities yield honest degraded status, not silent fallback.

**N9. Continuous supply-chain and advisory evidence (Q13–14,Q21,Q23).**
- Scope/size: approximately 6–12 workflow/build/manifest/CSAF/docs files.
- Deliver: scheduled dependency updates, govulncheck and source npm/runtime-image scans with justified failure policy, explicit secret scanning, version/digest pinning and controlled refresh; per-platform SBOMs for both images, source/static-UI inventory and signed attestations; exact workflow/ref identity verification; CSAF versioned product IDs and schema/semantic gate; pinned training release/offline manifests.
- Dependencies: N4 promotion boundary, supported tool/dependency matrix, fixture-secret policy (synthetic fixtures are not live secrets). Separate runtime from build-time dependencies; don't hide npm failures behind `|| true`.
- Acceptance/owner: supply-chain/release owner: dependency graph reconciles binary/UI/OS contents on both architectures, signature/SBOM substitution rejected, known vulnerable fixture or secret detection fails correct gate, fixed/affected CSAF versions are machine-distinguishable.

### Later — SRA-ready assurance and evidence-backed optimization

**N10. SRA control/evidence foundation coordinated with the SRA roadmap.**
- Scope/size: users/identity/API/UI/SSH/VPN/audit/release subsystems; multiple independently staged changes rather than an effort estimate.
- Deliver: external identity (OIDC), scoped roles, enrollment/recovery and strong privileged reauthentication, inspect/terminate identity sessions, time-bounded access and authorization evidence, optional training-shell versus brokered-recorded-session separation, durable off-box tamper-resistant audit and release-pinned classroom bundles. Full broker/approval/recording feature prioritization belongs to the SRA lane.
- Dependencies: N1–3 and N6–9; product decision about raw root shell and identity-to-network policy binding.
- Acceptance/owner: SRA/security owner: permission/session expiry/revocation affects every interface and running privileged session; evidence joins identity/approval/tunnel/command/config actions; exercise reset cannot silently erase required records.

**N11. Implement eBPF only if a measured need remains; otherwise retire dormant surface (Q16).**
- Scope/size: approximately 6–12 ebpf/engine/kernel-test/docs files if implemented; fewer files for an honest removal/capability cutover.
- Deliver: actual packet parsing/drop/map behavior, correct map layout, TTL lifecycle, explicit supported-kernel attachment, bounded failure semantics and instrumentation—or remove skeleton/capability claims, preserving nftables baseline.
- Dependencies: N7 performance and isolated-kernel evidence, stable nftables enforcement; no acceleration priority over SRA boundary fixes.
- Acceptance/owner: dataplane owner: real allowed/blocked/expiry packets and attach/detach lifecycle on supported kernels/architectures, not merely a loaded map or high non-Linux coverage percentage.

## Audit execution and prior-report reconciliation

- Read the requested brief and prior partial LaneReport first. Rechecked the prior critical engine, SSH/session, deployment, release/SBOM, coverage and docs findings against unchanged target HEAD; carried them forward with explicit static/runtime distinctions. Added verified CLI/MFA/HTTPS-only health, last-admin, OTP replay, test-assertion, effective TLS status, SIGHUP and reproducibility evidence. No source modifications, commits, file deletion, Docker, test-suite, scanner or UI execution occurred.
- Prior failure was a report-path write denial. This run wrote incrementally to the user-authorized external artifact path successfully; no attempt was made to write checkout build/ or route around that fence.
- Executed static inventory and relative-link-existence Python probes, repository/line reads and clean-status checks only: **0 tests executed**. No current statement-coverage percentages, runtime exploit reproduction, live kernel compatibility, registry/SBOM inspection, branch protection or current vulnerability results are claimed.
- NOT RUN by task design: Go/package/race/coverage suites; npm/Playwright/browser-backend integration; Docker/kernel/forward/NAT/DPI smoke; builds/vet/lint/Semgrep/Trivy/govulncheck; release/signature/SBOM/CSAF remote validation. Owners and precise acceptance scenarios are mapped above.
- Tool limits: guessed `api/http/auth_mfa_handlers.go` was absent (actual file is auth_mfa.go); a zsh `api/http/mfa*` no-match stopped a read probe; guessed `ui/components/AuthProvider.tsx` was absent, stopping that `&&` batch (actual account/session orchestration is Shell.tsx). Each was corrected via file discovery; they did not affect source or require bypass. Large tool outputs were sometimes truncated; relevant sections were reread in bounded ranges.
