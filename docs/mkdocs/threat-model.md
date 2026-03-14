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
- event, audit, inventory, anomaly, and learn-mode evidence
- signed images, SBOMs, and CSAF/advisory outputs

## Trust Boundaries

### Browser to Management API

The UI uses cookie-backed auth for normal use. Unsafe browser writes are constrained by same-origin checks and auth middleware. Bearer-token clients remain possible for explicit automation flows.

### Management Plane to Dataplane

The management service validates, stages, and commits policy, then pushes a runtime snapshot to the dataplane engine over the internal API boundary.

### Dataplane to Traffic

The dataplane processes packets routed through the appliance. It does not control traffic that bypasses the container by topology design, multi-homing, or Docker networking choices.

### Build / Release Boundary

Source code, dependencies, workflows, built images, SBOMs, signatures, advisories, and CSAF metadata form the software supply-chain boundary.

## Primary Threats

### 1. Protocol Parser Abuse

Examples:

- crafted BACnet, CIP, DNP3, Modbus, OPC UA, S7comm, DNS, HTTP, or TLS traffic intended to trigger bounds errors or panics
- malformed TCP segmentation or overlapping data designed to confuse reassembly

Current mitigations:

- parser entry points validate lengths and return parse failure instead of emitting invalid events
- fuzz targets now cover the major ICS decoders, core IT-DPI decoders, and TCP reassembly
- malformed-input regression tests exist alongside parser packages

Residual risk:

- some remaining IT-DPI decoders still need the same fuzz depth as the currently covered set

### 2. Control-Plane Compromise

Examples:

- brute-force or replay against the login/session path
- cross-origin browser write attempts
- abuse of missing or weak route protection
- privilege escalation from low-privilege users

Current mitigations:

- session auth with forced password change on first login
- optional TOTP MFA and admin-required MFA with grace periods
- route-level admin/view enforcement
- request body limits and same-origin protection for cookie-authenticated unsafe requests
- audit/event logging for important auth and config actions

Residual risk:

- RBAC is still intentionally simple compared with a mature enterprise policy model
- the bootstrap password remains a conscious lab-usability tradeoff

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
- improved UI cues for staged changes and commit behavior

Residual risk:

- complex service and VPN configuration still deserve continued save/apply regression coverage

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
- improved UI messaging for engine availability and staged-vs-live state

Residual risk:

- operators still need to externalize and retain logs for anything beyond temporary lab troubleshooting

## Deployment-Specific Notes

For the supported container-lab model:

- Docker defines the available networks and interface attachments.
- `containd` enforces only traffic that actually traverses it.
- traffic can bypass the appliance if the topology multi-homes workloads across zones or otherwise leaves alternate paths.

This is a security property of the deployment, not just the code. The lab compose must be designed so `containd` is the intended routed path between zones.

## Abuse Cases To Revisit Periodically

- malformed multi-packet protocol traffic that crosses TCP segment boundaries
- config import/export and backup restore edge cases
- auth/session behavior when MFA is required but not yet enrolled
- service profile uploads and generated client/profile artifacts
- release workflow tampering and advisory completeness

## Near-Term Priorities

1. extend fuzzing to the remaining IT-DPI decoders and additional malformed packet paths
2. keep the config save/apply surfaces under regression test as service coverage grows
3. deepen performance baselines for dataplane packet handling and representative decoder paths
4. continue improving auth maturity with stronger RBAC and external auth support
