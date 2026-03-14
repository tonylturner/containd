# Secure by Design

containd uses the CISA Secure by Design badge as a statement of intent and transparency, not as a government certification or a claim that every pledge detail is already complete. This page explains what the CISA initiative asks for, how containd aligns with those goals today, where the current caveat is, and what remains on the roadmap.

Official references:

- CISA Secure by Design overview: <https://www.cisa.gov/resources-tools/resources/secure-by-design>
- CISA Secure by Design pledge: <https://www.cisa.gov/securebydesign/pledge>
- CISA and partner guidance, "Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Secure by Design Software": <https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_1025_508c.pdf>

## What CISA Means by Secure by Design

CISA's broader Secure by Design guidance is not just a feature checklist. It asks software manufacturers to build products so that customers do not carry the full burden of defending them after purchase. The guidance centers on three principles:

1. **Take ownership of customer security outcomes.**
   Software makers should move security work upstream instead of leaving it to the operator after deployment.
2. **Embrace radical transparency and accountability.**
   Vendors should publish clear security guidance, vulnerability handling practices, and meaningful evidence of how they are improving.
3. **Lead from the top.**
   Security should be treated as a business requirement, not a bolt-on engineering task.

CISA also treats "secure by design" as including **secure by default**. In practice, that means security controls should be available in the base product and strong settings should not require paid upgrades or obscure expert tuning.

## What the Secure by Design Pledge Asks For

The pledge is narrower than the full guidance. It asks manufacturers to show measurable progress within one year across seven goals:

1. Multi-factor authentication
2. Reducing default passwords
3. Reducing an entire class of vulnerability
4. Increasing customer installation of security patches
5. Publishing a vulnerability disclosure policy
6. Improving CVE transparency and completeness
7. Increasing the ability for customers to gather evidence of intrusions

CISA's examples also make several expectations clear:

- MFA, SSO, and logging should be available without extra charges.
- Privileged access should prefer modern strong authentication.
- Security logs should be part of the baseline product.
- Vulnerability reporting and advisory practices should be public and predictable.

## Pledge Status at a Glance

| Commitment | Status | containd today |
| ---------- | ------ | -------------- |
| Multi-factor authentication | Done | Optional app-based TOTP MFA is built in for local accounts, including admin-enforced MFA with a 7-day grace period. |
| Reducing default passwords | Partial | Fresh installs still use a universal bootstrap password, but password change is mandatory on first login and the caveat is documented openly. |
| Reducing an entire class of vulnerability | Partial | containd already emphasizes safer defaults, signed releases, SBOMs, scanning, and defensive validation, but this remains an ongoing engineering program rather than a finished milestone. |
| Increasing customer installation of security patches | Partial | Releases, signed images, SBOMs, and update policy guidance are in place, but patch adoption still depends on operator action and is not measured centrally. |
| Publishing a vulnerability disclosure policy | Done | Public `SECURITY.md` and machine-readable `security.txt` are implemented and shipped. |
| Improving CVE transparency and completeness | Partial | containd now documents a GitHub advisory/CVE/CSAF process, but long-term completeness depends on continued execution as real advisories are published. |
| Increasing the ability for customers to gather evidence of intrusions | Done | Audit logs, events, DPI telemetry, syslog/export, and logging guidance are part of the base product. |

## containd's Position

containd is intended to meet the Secure by Design pledge in practice and align with the broader Secure by Design guidance. The current project position is:

- containd already implements a number of the expected secure-by-default controls in the base product.
- containd has one visible current caveat: fresh installs still use a universal bootstrap password that must be changed on first login.
- containd has completed the first wave of security-process work around MFA, disclosure policy, CSAF, logging guidance, and update policy, and now has a smaller follow-on roadmap focused on auth maturity and stronger bootstrap posture.

This is intentional transparency. The point of this page is to show both what is already true and what still needs to be strengthened.

## Current Caveat: Bootstrap Password

Fresh local-account installs currently start with a deterministic bootstrap credential: `containd / containd`, followed by mandatory password change on first login.

Why that exists today:

- containd is often used in offline lab, classroom, demo, and containerized training environments.
- instructors and students need a predictable first-login path that works even when there is no external identity provider, mail service, or secret-distribution system.
- containd already enforces password change on first login and supports replacing password-based access with stronger controls such as SSH keys and, in the roadmap below, app-based MFA.

Why this is still called out:

- CISA's default-password goal is specifically aimed at reducing universally shared credentials in the field.
- even with mandatory password change, a universal bootstrap password is still a meaningful caveat and should be treated as one.

Project stance:

- for lab usability and first-access reliability, containd keeps the bootstrap credential today;
- for transparent Secure by Design alignment, containd documents that choice and treats it as a caveat to be managed carefully rather than something to hide.

## Pledge Goal Mapping

### 1. Multi-Factor Authentication

Current alignment:

- containd already has authenticated local accounts, short-lived JWT sessions, role enforcement, forced password change, session invalidation, and optional app-based TOTP MFA for local accounts.
- admins can require MFA for individual local accounts, with a built-in 7-day enrollment grace period before full access is restricted.
- authentication is part of the base product, not a paid add-on.

Current caveat:

- the current MFA implementation is local-account TOTP only;
- SMS is intentionally not supported;
- broader external identity integration and richer auth policy are still future work.

Next steps:

- keep MFA focused on authenticator apps such as Google Authenticator and Microsoft Authenticator;
- add stronger external identity options later, especially OIDC;
- expand beyond the current `admin` and `view` roles into more robust role management.

### 2. Default Passwords

Current alignment:

- containd forces password change on first login for the default bootstrap account;
- operators can replace password-based access with SSH key bootstrap and stronger local credentials.

Current caveat:

- the first-install bootstrap password is still universal.

Roadmap:

- keep documenting the current rationale clearly;
- evaluate a future per-instance bootstrap path that preserves classroom usability without relying on a universal shared credential.

### 3. Reducing Entire Classes of Vulnerability

Current alignment:

- the project already emphasizes secure defaults such as default-deny firewalling, hardened cookies, restricted CORS behavior, signed releases, vulnerability scanning, and safer runtime defaults;
- CI already blocks HIGH/CRITICAL image findings and publishes signed images plus SBOMs.

Areas to keep improving:

- continue reducing whole classes of defects through safer parser design, validation, and stronger test coverage;
- track root causes over time rather than only counting fixes;
- keep using memory-safe implementation languages where practical. The core management and control-plane code is already written in Go, which avoids many classic memory-safety issues common in C/C++ products.

Next steps:

- publish a short public note on the classes containd is deliberately trying to minimize, such as injection bugs, secret exposure, and unsafe parsing behavior;
- use CVE/CWE history as an engineering learning signal rather than a vanity metric.

### 4. Security Patches

Current alignment:

- containd ships as versioned container images through GitHub Container Registry;
- releases are signed, SBOM-backed, and vulnerability-scanned;
- upgrades are operationally simple for container-lab deployments: pull a newer image and restart the appliance.

Current caveat:

- containd is a self-hosted appliance, so patch adoption still depends on operator action today;
- the project does not publish aggregate patch-adoption telemetry.

Implemented direction:

- [`Update Policy`](update-policy.md) now documents the supported release posture, operator update expectations, and the secure update workflow for lab and production-style environments;
- release notes, changelog entries, and machine-readable artifacts are meant to stay aligned so operators can update quickly.

Next steps:

- keep the update policy current as release process and support expectations evolve;
- keep security-sensitive dependency updates explicit in release notes and advisories;
- improve operator-facing upgrade guidance as the project approaches a more stable minor-release cadence.

### 5. Vulnerability Disclosure Policy (VDP)

Current alignment:

- [SECURITY.md](https://github.com/tonylturner/containd/blob/main/SECURITY.md) now acts as the project's public vulnerability disclosure policy and coordinated disclosure statement.
- containd also publishes a machine-readable `security.txt` for discoverability.

Current caveat:

- the project should continue tightening the policy over time as the advisory process matures, especially if it begins issuing more formal security advisories and CVEs on a regular basis.

Next steps:

- keep `SECURITY.md` as the human-readable disclosure policy;
- keep `security.txt` current and discoverable in shipped deployments;
- continue improving advisory and disclosure process detail as the project matures.

### 6. CVE Transparency and Completeness

Current alignment:

- containd already publishes versioned releases, signed images, SBOMs, and changelogs;
- security-sensitive dependency fixes are called out in release notes when they occur.
- containd now documents a lightweight advisory, CVE, and CSAF process in [`Advisories and CSAF`](advisories.md);
- the project publishes provider metadata and repository layout for machine-readable advisory artifacts, with actual advisory JSON to be published when real vulnerabilities require it.

Next steps:

- include CWE/root-cause information whenever practical;
- keep changelog, GitHub advisories, and CSAF documents aligned as real advisories are published.

### 7. Evidence of Intrusions

Current alignment:

- containd already includes audit logs, runtime service events, firewall and DPI telemetry, syslog forwarding, event export in CEF/JSON/Syslog, monitoring views, and Prometheus metrics;
- those capabilities are part of the base product and do not require a paid tier.
- [`Logging and Evidence`](logging-evidence.md) now documents the major evidence surfaces, forwarding options, retention expectations, and recommended lab posture.

Next steps:

- continue improving event quality for identity, configuration, and policy-change visibility.

## How containd Already Reflects the Broader Guidance

### Take Ownership of Customer Security Outcomes

Examples already present in containd:

- default-deny firewall posture
- forced password change for the bootstrap account
- signed images and published SBOMs
- vulnerability scanning in CI
- built-in audit and event logging
- embedded operational services managed through one security model instead of leaving the operator to integrate many disconnected tools

### Embrace Radical Transparency and Accountability

Examples already present in containd:

- public `SECURITY.md`
- public changelog and release notes
- signed releases and published SBOMs
- explicit documentation of the bootstrap-password caveat on this page

### Lead From the Top

For a project at containd's current stage, this means being willing to publish the security roadmap alongside the product roadmap and to treat security features as part of the base appliance, not premium extras. That is the intent of the current direction.

## Secure Configuration Guidance for Labs and Classrooms

Because containd is often used to teach segmentation and secure operations, a "good classroom configuration" should look like this:

- keep `CONTAIND_LAB_MODE=0`
- set a unique `CONTAIND_JWT_SECRET`
- change the bootstrap password immediately on first login
- prefer HTTPS and SSH keys when practical
- keep default-deny policy and commit only the minimum required allow rules
- enable audit/event forwarding when the lab design supports it
- stay on a current supported release
- enable app-based MFA for instructor and administrative accounts

The goal is not only to teach traffic segmentation. It is also to train students to recognize what a secure appliance posture looks like.

## Roadmap

### Near Term

- gather operational feedback on the local-account TOTP MFA flow and keep it lightweight
- keep the disclosure, CSAF, logging, and update-policy documents current as releases and advisories evolve
- make sure the first real public advisories use the documented GitHub advisory, release-note, and CSAF process consistently

### Medium Term

- support modern external authentication, especially OIDC
- expand beyond the current `admin` and `view` roles into more robust role management
- improve identity and auth policy controls so classroom and enterprise-style deployments can both model stronger security postures

### Longer Term

- evaluate a stronger per-instance bootstrap path that preserves first-access reliability for labs while reducing dependence on a universal bootstrap password
- continue improving the public evidence trail around advisories, patching, and measurable security progress
- revisit whether patch-adoption guidance can be made more prescriptive as the supported deployment modes stabilize

## Bottom Line

containd uses the Secure by Design badge to signal a real engineering direction:

- ship security features in the base product;
- document tradeoffs openly;
- make classroom and lab deployments teach secure habits instead of insecure shortcuts.

The project already aligns with much of the CISA Secure by Design posture. The bootstrap password remains the clearest current caveat, while external auth maturity and richer role management are the main next steps.
