# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.10] - 2026-03-12

### Fixed
- Removed the starter/dev compose dependency on Compose `interface_name`, restoring compatibility with Docker Engine versions older than `28.1` and fixing the CI quickstart smoke failure on GitHub-hosted runners.

### Changed
- Clarified Docker lab documentation so subnet-based auto-assign is the supported stable interface-mapping mechanism, while `interface_name` is described as an optional newer-engine feature for custom lab files.

## [0.1.9] - 2026-03-12

### Added
- Added `scripts/quickstart.sh` for the recommended two-command starter path and `scripts/bootstrap-starter.sh` for customizable lab bootstrap with cross-platform Docker/WSL-friendly setup.
- Added Windows / WSL deployment guidance and a dedicated lab-compose customization guide in the embedded docs.
- Added fresh-config bootstrap defaults for capture interfaces and dataplane enforcement, plus tests for the new environment helpers and bootstrap logic.

### Fixed
- Fixed starter and dev Docker Compose runtime privileges so nftables, routing, TUN, interface auto-assign, and block actions work in the supported container-lab deployment model.
- Fixed engine apply error handling so runtime capability failures are surfaced with useful detail instead of collapsing into generic save errors.
- Fixed starter bootstrap collisions with existing Docker networks by automatically selecting a non-overlapping starter subnet block on first setup when the defaults are already in use.

### Changed
- Switched the documented starter deployment to enforcement-on lab mode by default and clarified the ownership boundary between Docker-defined topology and containd-defined segmentation.
- Updated README and MkDocs deployment docs to center the new quick-start flow, advanced bootstrap flow, and Docker Desktop / WSL classroom guidance.
- Tightened diagnostics UI behavior so temporary block actions reflect enforcement availability and backend runtime errors directly.

## [0.1.8] - 2026-03-12

### Fixed
- Repaired the public starter compose and service write paths so interface, routing, NAT, firewall, config lifecycle, and service saves no longer degrade into generic UI failures.
- Fixed partial firewall rule updates so editing one field no longer drops the rest of the rule payload on save.
- Made direct service saves persist even when runtime apply hits an engine or service warning, and surfaced those warnings back to the UI instead of failing the request outright.
- Fixed the embedded forward and reverse proxy runtime configuration so Envoy validates cleanly, Nginx uses writable temp paths, and repeated service applies stop colliding with already-running Nginx listeners.
- Kept AV runtime state in sync even when another service apply fails, so AV update/definitions actions continue to work after mixed service changes.

### Changed
- Upgraded the public starter compose from a thin single-network quickstart to the full multi-interface lab topology used in development, with `.env`-driven Docker-managed networks and stable interface mapping.
- Clarified README and Docker Compose docs around Docker-owned topology versus containd-owned segmentation, and documented that full enforcement/runtime networking requires a Linux Docker host rather than Docker Desktop.
- Expanded CI coverage for the documented starter compose path so it now exercises core write flows instead of only health/read-only checks.
- Improved UI/API result handling across extended feature pages so warnings and backend validation details are shown directly for services, dataplane actions, and config operations.

## [0.1.7] - 2026-03-11

### Changed
- Single-sourced release versioning via the repo `VERSION` file and separated it from `SchemaVersionCurrent`, so future releases no longer need manual version edits across unrelated files.
- Release workflow now publishes the matching `CHANGELOG.md` section as the GitHub release body and verifies that the pushed tag matches the repo `VERSION` file.


## [0.1.6] - 2026-03-11

### Fixed
- Auto-wired the management plane to the local engine in combined `all` mode so the public standalone appliance can commit config changes, drive simulation, and query runtime state without extra environment variables.
- Fixed the published Docker Compose healthcheck to use `/usr/bin/containd`, matching the runtime image layout.
- Made the engine HTTP client fail fast on missing base URLs and non-2xx simulation responses instead of silently pretending control succeeded.
- Treated a missing `/proc/net/nf_conntrack` table as an empty conntrack view instead of a public quickstart error.

### Changed
- Added CI coverage for the documented standalone/public compose path, including health, login, interface state, and simulation control checks.
- Updated README and MkDocs deployment docs to describe the real combined-mode defaults and the new standalone image override flow.
- Updated release metadata and build version to `v0.1.6`.

## [0.1.5-beta] - 2026-03-11

### Security
- Bumped the Go toolchain and embedded stdlib to `1.25.8` across local builds, CI, and Docker images to address `CVE-2026-25679` and `CVE-2026-27142`.

### Changed
- Clarified the split between Dashboard and live Monitoring with first-run guidance on the dashboard and a telemetry-focused monitoring landing page.
- Routed the in-app Help button to page-specific documentation instead of always opening the docs root.
- Updated local font packaging to self-hosted npm dependencies instead of fetching Google fonts during the build.
- Simplified monitoring language so Events and Flows read more like operator tools and less like internal telemetry surfaces.
- Made topology and config details more action-oriented without changing the existing visual system.

### Fixed
- Restored exact candidate-vs-running config dirty detection in the global status bar.
- Finished the Events page live/pause control and visibility-aware polling.
- Made the Policy Wizard success state explicit about candidate config and commit requirements.
- Updated release metadata and schema/build version to `v0.1.5-beta`.
- Added clearer next-step actions in topology detail panels and reframed config workflow copy around live, staged, and review/apply states.
- Fixed multi-arch release packaging so build-only Docker stages run on the native build platform instead of hanging in emulated arm64 `npm ci` and builder steps.

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
