# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Modbus/TCP deep packet inspection (function codes, register ranges, read/write classification).
- IT protocol DPI: DNS, TLS (SNI/JA3/versions/ciphers), HTTP/HTTP2, SSH, RDP, SMB, SNMP, NTP.
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
