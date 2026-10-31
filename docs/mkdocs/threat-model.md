# Threat Model

This document captures the current security threat model for `containd` as a containerized ICS DPI firewall used to segment Docker-defined lab environments.

It is intentionally pragmatic: it focuses on the trust boundaries and failure modes that matter to the current product shape rather than pretending `containd` is a host firewall or a general-purpose enterprise appliance.

## Scope

In scope:

- the management API and UI
- local user authentication, sessions, MFA, and RBAC enforcement
- candidate/running config lifecycle and commit/rollback behavior
- the dataplane packet path, protocol decoders, and TCP reassembly
- generated runtime configuration for proxies, DNS, VPN, NTP, AV, and related services
- release artifacts, container images, SBOMs, signatures, advisories, and CSAF documents

Out of scope:

- native host firewalling on macOS or Windows
- arbitrary host-network control outside the Docker topology the appliance is given
- threats that completely compromise the container runtime or host kernel

## Security Objectives

`containd` is designed to preserve these outcomes:

1. Only authorized users can change policy or runtime configuration.
2. Candidate config cannot silently become running config without an explicit commit path.
3. Malformed traffic should not crash the dataplane or protocol decoders.
4. Cross-zone traffic should only be allowed when the Docker topology actually routes through `containd`.
5. Operators should have usable evidence when configuration changes, policy violations, anomalies, or service failures occur.
6. Release artifacts should be attributable and auditable.

## Assets To Protect

- management credentials, sessions, MFA secrets, and JWT signing material
- candidate and running configuration databases
- firewall/NAT/IDS/DPI policy state pushed into the dataplane
- runtime service configs and generated certificates/profiles
- event, audit, inventory, anomaly, and monitor-mode evidence
- signed images, SBOMs, and CSAF/advisory outputs

## Trust Boundaries

### Browser to Management API

The UI uses cookie-backed auth for normal use. Unsafe browser writes are constrained by same-origin checks and auth middleware. Bearer-token clients remain possible for explicit automation flows.

### Management Plane to Dataplane

The management service validates, stages, and commits policy, then pushes a
runtime snapshot to the engine. The engine API is an **unauthenticated privileged
control interface**, not protected by the management `/api/v1` authentication or
RBAC middleware. Access permits runtime policy/configuration mutation.

In combined mode (`containd all`), its default bind is `127.0.0.1:8081`. Split
mode (`containd engine`) has no default: `CONTAIND_ENGINE_ADDR` must name the
engine's address on the management network, and the engine refuses to start
with a loopback or wildcard listener. The
[reserved management profile](management-reservation.md) is the exception: it
runs both processes in one network namespace and requires a loopback engine
bind.

While enforcing, the input chain admits the engine API from loopback and, for a
listener bound to one address, only on that address's own interface; no other
zone reaches it, not even by routing to that address, and revocations never cut
that path. Without enforcement nothing filters it, so every network that can
route to the listener reaches it. Only the management process or a trusted
private network may reach this listener: never publish or route it to an
untrusted network. Container-network isolation and bind configuration remain
part of the security boundary.

### Dataplane to Traffic

The dataplane processes packets routed through the appliance. It does not control traffic that bypasses the container by topology design, multi-homing, or Docker networking choices.

### Build / Release Boundary

Source code, dependencies, workflows, built images, SBOMs, signatures, advisories, and CSAF metadata form the software supply-chain boundary.

## Primary Threats

### 1. Protocol Parser Abuse

Examples:

- crafted CIP, DNP3, IEC 60870-5-104, Modbus/TCP, DNS, HTTP, or TLS traffic intended to trigger bounds errors or panics
- malformed TCP segmentation or overlapping data designed to confuse reassembly

Current mitigations:

- parser entry points validate lengths and return parse failure instead of emitting invalid events
- fuzz targets cover the major ICS decoders, core IT-DPI decoders, and TCP reassembly
- malformed-input regression tests exist alongside parser packages

Residual risk:

- parser test and fuzz coverage varies by decoder; malformed traffic remains an untrusted input

### 2. Control-Plane Compromise

Examples:

- brute-force or replay against the login/session path
- cross-origin browser write attempts
- abuse of missing or weak route protection
- privilege escalation from low-privilege users

Current mitigations:

- session auth with forced password change on first login, on web/API and SSH (standard deployments only)
- TOTP MFA and admin-required MFA with grace periods; SSH password login asks for the TOTP code, and SSH key login counts the key as the possession factor
- a password or MFA change ends the account's other sessions and SSH connections
- SSH password, key and TOTP failures are rate-limited per client address and account, and refused logins are audited; a TOTP code is accepted once
- wrong TOTP codes (5) and wrong current passwords at password or MFA changes (10) lock that check for the account for 15 minutes, across all client addresses and web and SSH; password login is never locked by them, and each lock is audited once
- route-level admin/view enforcement
- request body limits and same-origin protection for cookie-authenticated unsafe requests
- audit logging for logins, account, password, MFA and certificate changes, SSH sessions and key enrollment, and config saves and commits

Residual risk:

- RBAC provides admin/view roles, not resource-scoped authorization
- the bootstrap password remains a conscious lab-usability tradeoff
- someone who holds an account's password can keep its TOTP check locked, which blocks that account's MFA login until the password is reset; the lock audit records show it
- when `CONTAIND_LAB_MODE=1` is set, the canonical credential (`containd/containd`) is pinned and every password change is refused (`POST /api/v1/auth/me/password` and `POST /api/v1/users/:id/password` both return 403, and the SSH menu and setup wizard refuse their password steps). This trades credential rotation for reproducible workshop credentials. Lab mode is an opt-in flag that also skips the SSH account checks; standard deployments enforce the forced first-login change and MFA on web/API and SSH. See [Secure by Design § Default Passwords](secure-by-design.md#2-default-passwords) for the full transparency note, including when lab mode is and is not appropriate. Operationally, lab-mode deployments should bind containd's HTTP/SSH ports to loopback (or an instructor-private network) and treat any inbound exposure of `:2222` as high-risk because the SSH appliance shell uses the same pinned credential.

### 3. Configuration Tampering

Examples:

- hidden or accidental policy changes
- candidate config corruption
- unintended running-state drift after save or commit
- secret material leaked through config export or API responses

Current mitigations:

- candidate vs running config model with validation before commit
- explicit commit and rollback flows
- config backup/export/import support
- redaction on user-facing config surfaces where required
- UI cues for staged changes and commit behavior

Residual risk:

- service and VPN changes can disrupt connectivity; review candidate state and retain a rollback path

### 4. Supply-Chain Attacks

Examples:

- vulnerable Go or npm dependencies
- compromised build workflow or release artifact
- unsigned or untraceable published image

Current mitigations:

- version-pinned builds and release workflow validation
- signed images
- SBOM generation
- Trivy scanning
- GitHub release notes, advisories, and CSAF publication

Residual risk:

- dependency hygiene must remain continuous; this is not a one-time property

### 5. Evidence Suppression or Operational Blindness

Examples:

- configuration changes with no clear audit trail
- policy drops/anomalies that are not surfaced to operators
- service failures that are mistaken for “empty data”

Current mitigations:

- audit, events, anomaly, inventory, and learn surfaces
- syslog forwarding and metrics endpoint
- service/runtime status APIs
- UI messaging for engine availability and staged-vs-live state

Residual risk:

- operators still need to externalize and retain logs for anything beyond temporary lab troubleshooting

## Deployment-Specific Notes

For the supported container-lab model:

- Docker defines the available networks and interface attachments.
- `containd` enforces only traffic that actually traverses it.
- traffic can bypass the appliance if the topology multi-homes workloads across zones or otherwise leaves alternate paths.

This is a security property of the deployment, not just the code. The lab compose must be designed so `containd` is the intended routed path between zones.
