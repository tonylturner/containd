# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5-beta] - 2026-03-11

### Security
- Bumped the Go toolchain and embedded stdlib to `1.25.8` across local builds, CI, and Docker images to address `CVE-2026-25679` and `CVE-2026-27142`.

### Changed
- Clarified the split between Dashboard and live Monitoring with first-run guidance on the dashboard and a telemetry-focused monitoring landing page.
- Routed the in-app Help button to page-specific documentation instead of always opening the docs root.
- Updated local font packaging to self-hosted npm dependencies instead of fetching Google fonts during the build.

### Fixed
- Restored exact candidate-vs-running config dirty detection in the global status bar.
- Finished the Events page live/pause control and visibility-aware polling.
- Made the Policy Wizard success state explicit about candidate config and commit requirements.
- Updated release metadata and schema/build version to `v0.1.5-beta`.

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
- Full ICS protocol DPI: Modbus/TCP, DNP3, CIP/EtherNet/IP (with EPATH and MSP sub-service parsing), S7comm, IEC 61850 MMS, BACnet, OPC UA.
- IT protocol DPI: DNS (with compression pointer support), TLS (SNI/JA3/versions/ciphers), HTTP/HTTP2, SSH, RDP, SMB, SNMP, NTP.
- ICS asset auto-discovery from observed traffic (`pkg/dp/inventory`).
- Learn mode: passive traffic learning with automatic allowlist rule generation (`pkg/dp/learn`).
- Protocol anomaly detection: malformed frames, protocol violations, rate anomalies (`pkg/dp/anomaly`).
- Signature-based IDS with 16 built-in ICS malware signatures (`pkg/dp/signatures`).
- PCAP offline analysis: upload capture files for DPI processing and policy generation (`pkg/dp/pcap`).
- Event export in CEF, JSON, and Syslog formats to file/UDP/TCP destinations (`pkg/dp/export`).
- Protocol statistics and top talkers (`pkg/dp/stats`).
- 7 ICS policy templates (Purdue baseline, maintenance windows, per-protocol defaults) (`pkg/cp/templates`).
- Schedule predicates and identity predicates on firewall rules.
- Prometheus /metrics endpoint for monitoring integration (`pkg/common/metrics`).
- TCP reassembly with out-of-order segment handling and pre-allocated buffers.
- NFQUEUE selective DPI steering with per-flow verdict caching.
- Optional eBPF XDP/TC fast path for early drops and hardware counters.
- Event spill-to-disk for high-volume event handling.
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
- JWT validation with strong secret enforcement when lab mode is disabled.
- MustChangePassword enforcement on first login.
- nftables injection prevention on firewall rule inputs.
- TLS 1.2+ with hardened cipher suite list.
- HSTS enabled by default.
- CORS with wildcard origin rejection.
- SameSite=Strict session cookies.
- Path traversal protection on all file-serving endpoints.
- Rate limiting on authentication and sensitive API endpoints.

### Performance
- Flow hash uses strings.Builder for reduced allocations.
- Verdict cache with TOCTOU fix for concurrent access safety.
- Flow sweep runs outside mutex to reduce lock contention.
- Event store uses in-place shift to avoid allocations.
- Regex caching in IDS rule evaluation.
- Schedule predicate evaluation is allocation-free.
- TCP reassembler uses pre-allocated segment buffers.
