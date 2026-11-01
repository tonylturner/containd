# Secure by Design

containd uses the CISA Secure by Design badge as a statement of intent and
transparency, **not government certification**. This page maps the seven pledge
goals to containd's design and defaults.

A goal is met when the shipped design meets it by default, without extra
configuration. Steps that an operator takes for a specific deployment are in
[Deployment hardening](#deployment-hardening). They do not change a status.

Official references:

- [CISA Secure by Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [CISA pledge](https://www.cisa.gov/securebydesign/pledge)
- [Secure by Design principles](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf)

## Status at a glance

| Pledge goal | Status | Default design |
| ----------- | ------ | -------------- |
| 1. Multi-factor authentication | Met with caveat | TOTP MFA for every local account on web/API and SSH password login; admins can require it. An SSH key alone signs in. |
| 2. Default passwords | Met | Forced first-login change on web/API and SSH, for password and key logins. |
| 3. Entire classes of vulnerability | Met | Memory-safe Go, default-deny forwarding, fail-closed startup and recovery, isolated engine API. |
| 4. Security patches | Met with caveat | Signed, versioned images; state persists across updates; safe boot after an upgrade. No automatic updates. |
| 5. Vulnerability disclosure policy | Met | `SECURITY.md` and a served `security.txt`. |
| 6. CVE transparency | Met | CSAF 2.0 advisories with CWE, served provider metadata. |
| 7. Evidence of intrusions | Met with caveat | Audit log, events, syslog forwarding of audit records and events, and metrics in the base product. Event forwarding is best-effort. |

- **Met**: the design and its defaults deliver the goal.
- **Met with caveat**: the design delivers the goal. A stated limit or trade-off
  remains.
- **Gap**: a design decision blocks the goal. See [Known gaps](#known-gaps).

containd has no paid tier. Every security feature on this page is in the base
product.

## Pledge goals

### 1. Multi-Factor Authentication

What the design delivers by default:

- Every local web/API account can enroll app-based TOTP MFA.
- Admins can require MFA for an account. After a seven-day enrollment grace
  period, that account can reach only MFA setup until it enrolls.
- Sessions are server-side records behind signed JWTs, with a 30-minute idle
  limit and a 4-hour maximum. Logout revokes the session. Outside lab mode,
  management refuses to start with an empty or example `CONTAIND_JWT_SECRET`.
- The last admin cannot be deleted or demoted, including by concurrent requests.
- API routes enforce the `admin` or `view` role. SSH accepts only `admin`
  accounts.
- SSH password login of an account with MFA asks for its TOTP code. An account
  whose MFA enrollment grace period has ended cannot log in over SSH either.
- A password or MFA change ends the account's other sessions, including its SSH
  connections. The session that made the change stays signed in.
- A TOTP code works once. Web/API and SSH refuse a code whose time step is not
  later than the account's last accepted one, including after a restart.
- Each MFA login or enrollment challenge works once and expires after five
  minutes. Pending and consumed state survives management restarts. A password,
  TOTP or role change invalidates pending challenges; start login or setup again.
  Incorrect codes leave the challenge usable until expiry; login code failures
  still count toward the per-account limit. Expired challenge rows are pruned
  when challenges are issued or redeemed.
- The SSH menu and setup wizard ask for the current password before they change
  the signed-in account's password, so a session opened with a key cannot set it.
- Web/API login and SSH login, including TOTP codes, are rate-limited. SSH
  password, key and TOTP failures share one limit per client address and account.
- Five wrong TOTP codes, or ten wrong current passwords at a password or MFA
  change, lock that check for the account for 15 minutes, from every client
  address on web/API and SSH. Each lock is audited once. Password login is never
  locked, so someone without the password cannot lock an account out.
- Lab mode skips the SSH account checks and the per-account limits, and accepts
  a reused TOTP code.

Caveats:

- SSH public-key login does not ask for a TOTP code. The key counts as the
  possession factor, so a key alone signs in to an MFA account. This keeps
  key-based automation working; protect admin keys accordingly.
- MFA is local-account TOTP. SMS is intentionally not supported. External
  identity (OIDC single sign-on) and resource-scoped roles are not implemented.

### 2. Default Passwords

What the design delivers by default:

- A fresh install seeds one admin account, `containd` / `containd`, and marks it
  for a forced password change.
- Until that change, a web/API session can reach only its own session, logout
  and the password-change endpoint.
- SSH asks for the change at login, for password and key logins alike, before
  the CLI, menu or shell opens. It applies the same password rules.
- A new password needs at least 8 characters with an uppercase letter, a
  lowercase letter and a digit, and must differ from the current one, so the
  bootstrap value cannot be kept.

Design note: the bootstrap credential is the same on every instance, and the
forced change at first login is what retires it, as the pledge describes.
containd often runs in offline labs and classrooms that have no channel to
distribute a per-instance secret. Bind management to a trusted network until
the first login; see [Deployment hardening](#deployment-hardening).

#### Lab-mode credential pinning

`CONTAIND_LAB_MODE=1` is an opt-in weakening for reproducible, isolated workshops.
It is off by default and in the supplied Compose file. It pins
`containd` / `containd` and refuses every password change for every user, on
every path, with the same reason:

- `GET /api/v1/auth/me` does not advertise `mustChangePassword: true`.
- `POST /api/v1/auth/me/password` and `POST /api/v1/users/:id/password` return
  403, also for admins.
- The SSH console's "Reset admin password" option and the setup wizard's
  password step print the reason and change nothing. The wizard continues with
  its other steps.
- Seeding the default admin at first boot and after a factory reset is not a
  password change and is unaffected.

Lab mode also relaxes web/API authentication. Every request gets admin access.
With a JWT secret, any validly signed, unexpired token passes without a session
lookup. Without a secret, any nonempty token passes. Factory reset does not
revoke lab tokens. SSH password login is on by default, uses the same pinned
credential, and skips the forced change and MFA checks.

Use lab mode only for single-tenant, isolated or offline training environments,
with HTTP and SSH bound to loopback or an instructor-private network. Do not use
it on hostile or shared networks, or for real ICS deployments. A compromised lab
credential compromises that deployment's management boundary.

To return to standard authentication, remove the flag or set it to `0`, restart,
and change the password through the standard flow. Disabling the flag does not
rotate, reset or recover credentials. Recreating a container with the same data
volume keeps the stored accounts.

### 3. Reducing Entire Classes of Vulnerability

What the design delivers by default:

- **Memory safety.** containd's management plane, control plane, dataplane and
  protocol decoders are Go, built with cgo disabled. Untrusted packets are parsed
  in memory-safe code. Embedded third-party services, such as ClamAV, are covered
  by the SBOM and image scanning instead.
- **Default deny.** The first matching enforcing terminal rule decides forwarded
  traffic. With no decision, traffic is dropped unless the default action is
  explicitly `ALLOW`. A later ALLOW never overrides an earlier matching
  enforcing DENY; see [rule precedence](policy-model.md#actions-and-precedence).
- **Fail closed, without lockout.** Every boot validates the stored running
  configuration. If it is invalid, management enters recovery: new transit is
  dropped and management stays reachable where it was. A reserved management
  path, when declared, compiles into every firewall as an independent allow, so
  policy cannot lock out the management network. See
  [Reserved Management Path](management-reservation.md).
- **Authenticated remote engine API.** Numeric loopback retains credential-free
  HTTP; every non-loopback listener requires TLS 1.3 mutual authentication from
  one dedicated engine secret. Combined mode binds `127.0.0.1:8081`. Split engine
  mode refuses to start without `CONTAIND_ENGINE_ADDR` and refuses loopback or
  wildcard listeners, except on a reserved management path, where both processes
  share one network namespace. While enforcing, the firewall admits the API from loopback
  and on that address's interface only. See
  [Threat Model](threat-model.md#management-plane-to-dataplane).
- **Web defenses.** Auth cookies use `SameSite=Strict`. Cookie-authenticated
  unsafe requests must be same-origin. Sensitive endpoints are rate-limited.
- **Build gates.** CI runs race-enabled tests, golangci-lint and Semgrep. It
  fails on unsuppressed HIGH/CRITICAL Trivy findings in the management image
  (suppressions are in `.trivyignore`). A clean scan is not proof that no
  vulnerability exists.

### 4. Security Patches

What the design delivers by default:

- Releases ship as versioned container images, signed with Cosign, with SBOM
  attestations. `:latest` moves only to signed stable releases.
- An update replaces the image. Configuration, users and audit data persist on
  the `/data` volume.
- If an upgrade tightens validation and the stored configuration fails it,
  management boots into fail-closed recovery. It does not refuse to start, and it
  does not apply a configuration it cannot validate.

Caveat: containd does not update itself or check for updates. ICS appliances
often run offline and under change control, so the operator schedules each
update. containd does not send telemetry, so patch adoption is not measured. See
[Update Policy](update-policy.md) and [SBOMs and signatures](sbom.md).

### 5. Vulnerability Disclosure Policy

[SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) is the
canonical disclosure policy. The appliance serves `/.well-known/security.txt`.

### 6. CVE Transparency and Completeness

containd publishes CSAF 2.0 advisories with CWE classification, and the appliance
serves CSAF provider metadata at `/.well-known/csaf/provider-metadata.json`.
Release notes and the changelog name security-relevant fixes. Published
advisories, including `containd-2026-001`, are indexed in
[Advisories and CSAF](advisories.md).

### 7. Evidence of Intrusions

What the design delivers by default:

- A persistent audit database records web/API and SSH logins, user, password and
  MFA changes, SSH logouts, key enrollment and CLI commands, management TLS
  certificate and CA bundle replacement, configuration saves and commits, factory
  resets and management boot faults.
- Refused logins and credential changes are recorded as `denied`: wrong
  passwords, unknown or non-admin SSH accounts, unauthorized SSH keys, wrong or
  reused TOTP codes, and a wrong current password or code when changing a
  password or MFA. Records name the account and client address, never the
  secret tried.
- `GET /api/v1/events` exposes firewall, DPI, IDS, AV, proxy and service events.
  Separate bounded banks keep firewall denies and IEC 104 incident evidence,
  so routine traffic does not evict them.
- The service syslog forwarder sends engine and service events and audit
  records over UDP or TCP, as JSON or RFC 5424. Application logs can go to a
  remote syslog sink.
- Audit records are retried with at-least-once attempts: each forwarder keeps a
  cursor in the audit database, so records written during a collector outage
  or before a restart are retried later. Local transport acceptance is not
  collector acknowledgment. The services status reports the backlog and the
  last error per forwarder.
- Audit write failures do not block operations. The UI, `show audit --status`
  and `GET /api/v1/evidence/status` distinguish persistence from collector
  delivery, including current degradation and recovered history. Unauthenticated
  health exposes only the worst evidence state, without errors or destinations.
- `/metrics` exposes Prometheus metrics.

Caveats:

- Event history is bounded and in memory, and event forwarding over syslog is
  best effort with retries: retained events are retried, but retention overflow
  and serialization drops are counted as loss. Source restarts disclose unknown
  continuity; management restart starts fresh telemetry tails. New destinations
  start at tail without backfill.

See [Logging and Evidence](logging-evidence.md).

## Known gaps

No pledge goal has a design gap. The caveats under each goal state the
remaining limits and trade-offs.

## Deployment hardening

These steps adapt a deployment to its network. They are guidance, not gaps.

- Change the bootstrap password before management is reachable from a shared
  network. Then enroll an admin SSH key and disable SSH password login; the SSH
  setup wizard offers both steps and refuses a change that would lock out SSH.
- Require MFA for administrative accounts.
- Keep `CONTAIND_LAB_MODE=0` except in the isolated cases above.
- Use a unique JWT secret. Replace the generated self-signed HTTPS certificate,
  and prefer HTTPS.
- Remove HTTP, HTTPS and SSH access from interfaces that do not need management.
- In split mode, set `CONTAIND_ENGINE_ADDR` to the engine's address on a trusted
  private management network, set the same `CONTAIND_ENGINE_SECRET` on both peers,
  and use an HTTPS engine URL. See [setup and rotation](docker-compose.md#engine-secret-and-rotation).
- Commit only the allow rules you need. Make sure the network routes protected
  traffic through the appliance.
- Configure a syslog forwarder, preferably over TCP, and verify that events
  and audit records arrive off-box.
- Install supported security updates; see [Update Policy](update-policy.md).

## Additional CA bundle

Admins can replace or clear the additional CA bundle using
`POST /api/v1/system/tls/trusted-ca`; see the
[configuration reference](config-format.md#additional-ca-bundle) for validation
and request formats. This does not replace the management server's TLS
certificate or change browser trust.

Management distributes the bundle's content to the engine, whose ICAP-over-TLS
and FreshClam clients verify servers against the system roots plus the bundle.
Other clients keep their own trust: the in-app console's and SSH CLI sessions'
loopback connection pins the certificate the HTTPS listener serves, OpenVPN tunnels use their per-tunnel CA,
and browsers and remote CLI hosts use their own trust stores. Do not disable
certificate verification to work around a rejected private-CA endpoint.
