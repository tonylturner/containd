# Secure by Design

containd uses the CISA Secure by Design badge as a statement of intent and
transparency, **not government certification** or a claim that every pledge goal
is complete. This page describes operator controls and their limits, not a
compliance score.

Official references:

- [CISA Secure by Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [CISA pledge](https://www.cisa.gov/securebydesign/pledge)
- [Secure by Design principles](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf)

## 1. Multi-Factor Authentication

Local web/API accounts support TOTP MFA, JWT sessions, and `admin`/`view` roles.
Administrators can require MFA, with a seven-day enrollment grace period.
Authentication and logging are part of the base appliance.

These controls differ by channel:

- MFA and forced first-login password change apply to web/API access. The SSH
  appliance shell does **not** enforce MFA or forced password change, even in
  standard mode. Restrict SSH reachability and prefer keys.
- Changing a password or MFA settings does not revoke existing sessions.
- TOTP is local-account only. SMS, external OIDC identity, and resource-scoped
  roles are not implemented.

## 2. Default Passwords

Fresh local-account installs start with the universal bootstrap credential
`containd / containd`. Standard deployments require a password change on first
web/API login. This is not a per-instance secret and is not safe to expose to a
shared network before setup. Keep management private, set a unique non-empty
`CONTAIND_JWT_SECRET`, change the password immediately, and configure SSH keys.

### Lab-mode credential pinning

`CONTAIND_LAB_MODE=1` is an opt-in weakening for reproducible, isolated workshops:
it pins `containd / containd` and disables HTTP password changes.

- `GET /api/v1/auth/me` does not advertise `mustChangePassword: true`.
- `POST /api/v1/auth/me/password` returns 403.
- `POST /api/v1/users/:id/password` also returns 403, including for admins.
- The SSH admin shell on `:2222` uses the same pinned credential and does not
  provide a substitute MFA safeguard.

Use lab mode only for single-tenant, isolated or offline training environments
with HTTP and SSH bound to loopback or an instructor-private network. Do not use
it on hostile/shared networks or for real ICS deployments. A compromised lab
credential compromises that deployment's management boundary.

The password endpoints remain blocked while lab mode is enabled. To return to
standard authentication, remove the flag or set it to `0`, restart, and use the
standard authenticated password-change flow. Disabling the flag is not itself a
password rotation. Recreating a container with the same data volume does not
clear stored accounts; do not rely on redeployment as a credential reset. If
access is lost, keep the appliance isolated; disabling lab mode does not reset
or recover credentials.

## Deployment hardening

- Keep `CONTAIND_LAB_MODE=0` except in the isolated cases above.
- Use a unique JWT signing secret, HTTPS, and TOTP for administrative web access.
- Limit HTTP and SSH exposure; do not assume web account assurances apply to SSH.
- Isolate the **unauthenticated engine API**. Combined mode binds it to
  `127.0.0.1:8081` by default; split engine mode defaults to `:8081` and requires
  a trusted private network. `CONTAIND_ENGINE_ADDR` overrides the bind. See
  [Threat Model](threat-model.md#management-plane-to-dataplane) and
  [Reserved Management Path](management-reservation.md).
- Keep default-deny firewall policy and commit only the minimum required allows.
  Ensure network topology routes the protected traffic through the appliance.
- Preserve audit records and verify off-box log delivery. Service syslog and
  application syslog sinks are available; the DPI SIEM exporter is not wired.
  See [Logging and Evidence](logging-evidence.md).
- Install supported security updates using the [Update Policy](update-policy.md).
  Patch adoption is operator-managed; no aggregate adoption telemetry is published.

## Supply chain and disclosure

Releases include signed images, SBOMs, and versioned release notes. CI scans the
management image for unsuppressed HIGH/CRITICAL Trivy findings using
`.trivyignore`; this is not proof of an absence of vulnerabilities. See
[SBOMs and signatures](sbom.md).

[SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) is the
canonical disclosure policy. The appliance serves `/.well-known/security.txt`.
Published CSAF documents, including `containd-2026-001`, are indexed in
[Advisories and CSAF](advisories.md).

## Additional CA bundle storage

Admins can replace or clear the additional CA bundle using
`POST /api/v1/system/tls/trusted-ca`; see the
[configuration reference](config-format.md#additional-ca-bundle) for validation
and request formats. This does not replace the management server's TLS
certificate or change browser trust.

The bundle is currently storage-only: outbound clients, including FreshClam
definition downloads, do not consume it. No automatic outbound trust reload is
provided. Do not disable certificate verification to work around a rejected
private-CA endpoint.

## Known Gaps

- Web, SSH, and CLI do not apply consistent account-assurance requirements; SSH
  does not enforce MFA or forced password change.
- Password/MFA changes do not revoke existing sessions.
- Fresh installs use a universal bootstrap password rather than a per-instance
  credential; lab mode deliberately retains it.
- Audit coverage and visibility into evidence-delivery failures are incomplete.
  Event caches and best-effort syslog do not guarantee complete durable history.
- DPI CEF/JSON/Syslog export configuration has no runtime consumer.
- External identity (OIDC) and richer, resource-scoped roles are not implemented.
