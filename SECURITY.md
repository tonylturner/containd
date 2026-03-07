# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

## Reporting a Vulnerability

The containd team takes security seriously. If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email **tony@defendics.com** with a description of the vulnerability.
2. Include steps to reproduce, affected versions, and any relevant logs or configuration details.
3. If possible, suggest a fix or mitigation.

### What to Expect

- **Acknowledgment** within 48 hours of your report.
- **Assessment and triage** within 5 business days.
- **Fix or mitigation** for confirmed vulnerabilities, coordinated with you before public disclosure.
- **Credit** in the release notes (unless you prefer to remain anonymous).

### Scope

The following are in scope:

- The containd Go binary and its embedded services (DNS, VPN, proxies, IDS, AV).
- The containd Docker image and its dependencies.
- The management API, web UI, SSH console, and CLI.
- Authentication, authorization, session management, and secrets handling.
- Network enforcement (nftables rulesets, NAT, routing, conntrack).

### Out of Scope

- Third-party dependencies with their own security processes (Envoy, Nginx, Unbound, OpenVPN, ClamAV). Report those upstream and notify us so we can track and update.
- Denial of service against lab/development deployments running with default credentials.

### Hardening Guidance

For production deployments:

- Change the default JWT secret (`CONTAIND_JWT_SECRET`).
- Change the default admin password on first login.
- Restrict management UI/API binding to trusted interfaces.
- Enable HTTPS and disable plain HTTP where possible.
- Use SSH key authentication; disable password auth.
- Review and restrict firewall rules beyond the default-deny posture.
