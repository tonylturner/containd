# containd (ICS‑NGFW) – Agent & Project Specification

Authoritative instructions for building **containd / ICS‑NGFW**, a single-image, ICS/OT-aware NGFW appliance. Use this file as the primary reference for architecture, features, tech stack, coding style, and delivery milestones.

---

## 0. Product Goals

- Commercial-grade operator experience: Web GUI + SSH/CLI, strong defaults, auditability, backups/export/import, safe upgrades.
- OT/ICS-aware: first-class assets (PLC/HMI/SIS/RTU/etc.), ICS DPI + policy primitives, ICS-centric dashboards/alerts.
- Deployable anywhere: single appliance container by default; host mode on Linux NICs; future K8s-ready architecture.

Non-goals (initially): full TLS MITM; full SIEM replacement; extensive L2 switch features beyond routing/segmentation.

---

## 1. Stack, Runtime Model, Packaging

- Go (latest), Gin REST API (`/api/v1`); Next.js (TypeScript) with Tailwind, shadcn/ui, React Flow, charts.
- **Single Go binary** `containd` with subcommands: `engine`, `mgmt`, `all` (default, runs both).
- **Single Docker image** (`containd` tag) containing the binary and built UI; entrypoint `containd all`.
- Capabilities: needs NET_ADMIN/NET_RAW for enforcement; avoid SYS_ADMIN. Run mgmt/UI/SSH as non-root; isolate engine privilege in code.

---

## 2. Enforcement Strategy

- Baseline enforcement via Linux kernel: routing/forwarding in kernel; conntrack state; **nftables** for firewall/NAT; dynamic sets/maps for speed.
- Userspace compiles/install nftables rules, performs selective DPI/IDS, updates dynamic sets, exports telemetry.
- Verdict actions include allow/deny/reset, alert, temp block (flow/host), rate-limit, tag.
- Selective DPI path using NFQUEUE/AF_PACKET mirror; IPS verdicts update nftables sets and optionally kill conntrack.
- eBPF plan (optional): XDP early drop/counters, TC hooks, ring buffer events; versioned/optional with compatibility checks.

---

## 3. Repository Layout (target)

```
containd/
  cmd/
    containd/           # main with subcommands engine/mgmt/all
  pkg/
    dp/
      enforce/          # nftables/netlink programming + conntrack
      capture/          # NFQUEUE/AF_PACKET mirrors, pcap hooks
      flow/             # flow/session model + enrichment
      rules/            # compiled policy structures + evaluator
      dpi/              # generic DPI framework
      ics/              # ICS protocol decoders
      ids/              # IDS/IPS rules & evaluation
      verdict/          # verdict types/actions
      engine/           # orchestrates dp subsystems
    cp/
      store/            # DB access (SQLite default)
      config/           # config model + schema versioning
      policy/           # high-level policies/objects
      compile/          # compile policies -> dp bundles (nft + dpi + ids)
      identity/         # users/groups/sessions mapping
      services/         # syslog, ntp, dns config mgmt
      audit/            # audit log subsystem
    cli/                # CLI command framework (shared)
    common/             # logging, metrics, errors, types
  api/
    http/               # Gin handlers, routers, DTOs
    internal/           # internal RPC between mgmt<->engine
  ui/                   # Next.js app
  ebpf/                 # XDP/TC programs (future)
  Dockerfile.mgmt       # single appliance image (current)
  Dockerfile.engine     # optional engine-only image (current)
  docker-compose.yml    # single-container compose
  docs/                 # architecture, dataplane-enforcement, ebpf, policy-model, etc.
```

Note: current repo uses `cmd/ngfw-engine` and `cmd/ngfw-mgmt`; migrate toward single `containd` binary/subcommands over time.

---

## 4. Config, Persistence, Safety

- Default DB: SQLite (persistent volume). Later Postgres optional.
- Stores interfaces/zones, objects, ICS assets, policies (FW/IDS), identity, services (syslog/NTP/DNS), audit log, short-retention telemetry indexes.
- Config lifecycle: **candidate/running/commit/rollback**, commit-confirmed with auto-rollback, diff, safe apply to avoid lockout.
- Export/import: canonical JSON (schema_version, objects/assets/policies/services/identity/admin), deterministic ordering, dry-run validate, full overwrite; later partial merge. Redact secrets unless explicitly requested; secrets encrypted at rest with master key (file/env).
- Audit logging: record who/when/source/what/result for every mutation; viewable/exportable/forwardable via syslog.

---

## 5. Data Plane & DPI/IDS

- Multi-stage pipeline:
  1) Kernel fast path (nftables, conntrack, NAT) for zone rules.
  2) Selective DPI path (NFQUEUE/AF_PACKET) for L7/ICS inspection.
  3) IDS/IPS path (native) triggering dynamic nftables updates + conntrack kill as needed.
  4) Telemetry export (flows/events/alerts), bounded local retention + forwarding.
- Flow model for enrichment (asset/identity), DPI state, IDS, telemetry; kernel remains forwarding authority.
- Verdicts: ALLOW_CONTINUE, DENY_DROP/RESET, ALERT_ONLY, BLOCK_FLOW_TEMP, BLOCK_HOST_TEMP, RATE_LIMIT_FLOW, TAG_FLOW.
- DPI safeguards: per-flow/global memory caps, timeouts, backpressure (fail-open default for lab, configurable).
- ICS DPI plan: Modbus first (function codes, unit ID, register ranges), then DNP3/IEC104/S7/CIP/OPC UA.

---

## 6. ICS/OT Capabilities

- Asset model: first-class assets (PLC, SIS, HMI, Historian, EWS, RTU, Gateway, Vendor laptop, etc.) with zone, IPs/hostnames, criticality, allowed services, tags.
- ICS policy primitives: Modbus read/write classes, function codes, unit ID, register ranges; later DNP3/IEC104 command categories; S7/CIP/OPC UA visibility then control.
- OT policy templates: Purdue baseline; maintenance window; SIS hardening (ship defaults).

---

## 7. Identity-Aware Policy

- Identity sources: local users/groups (v1); later OIDC/LDAP.
- Session mappings from VPN/jump host/lab console.
- Rule matching: user/group/role/device/time schedule; identity-aware ICS rules (e.g., engineering writes during maintenance).

---

## 8. Management (API/UI/CLI/SSH)

- REST API `/api/v1`: health/version/time; interfaces/zones; objects/assets; identity; policies (FW/IDS/ICS); config lifecycle (running/candidate/diff/commit/rollback/commit-confirmed); telemetry (flows/events/alerts); services (syslog/DNS/NTP); audit log.
- Web UI (Next.js): dashboard (health/throughput/alerts), topology (React Flow), policies (FW/ICS/IDS), alerts/events, config diff/commit/rollback, export/import, services, audit, identity.
- SSH CLI: network-device style; configure terminal, show running/candidate, diff, commit/rollback/commit-confirmed, audit, export/import. CLI uses same control-plane APIs.

---

## 9. System Services

- Syslog: local structured logs; forwarders (UDP/TCP); format options; forward IDS alerts, policy denies, audit events.
- NTP: client config + status.
- DNS: caching resolver, upstream forwarders, optional local zones.

---

## 10. Security & Hardening

- Auth/RBAC: admin/operator/auditor/lab roles; auth required by default for UI/API; SSH key auth default (passwords only in lab); rate-limit logins.
- HTTPS default with self-signed cert; support custom cert install/rotate.
- Least privilege: mgmt services non-root; engine isolated for net admin tasks.

---

## 11. Observability

- Prometheus metrics endpoint (optional recommended); optional OpenTelemetry later.
- Log level controls/sampling; packet capture hooks for debugging (explicit operator action).

---

## 12. Deployment

- Docker compose lab: single service with NET_ADMIN/NET_RAW, persistent volume for DB/certs/keys; multi-homed networks.
- Host mode: bind engine to NICs; systemd unit for `containd all` or split subcommands; mgmt on mgmt interface only.
- Kubernetes (future): privileged daemonset + policy distribution; same image.

---

## 13. Implementation Phases (updated)

- **Phase 0**: scaffold repo; `containd` subcommands; mgmt API/UI skeleton; SQLite store; nftables programming skeleton; health.
- **Phase 1**: zone firewall + NAT via nftables; candidate/commit/rollback + audit; UI/CLI basics; syslog forwarding + NTP status.
- **Phase 2**: selective DPI (NFQUEUE/mirror) + Modbus visibility; ICS read/write primitives in policy.
- **Phase 3**: native IDS/IPS + ICS enforcement; nftables set updates + conntrack kill; policy templates (Purdue, SIS).
- **Phase 4**: eBPF acceleration (XDP/TC) optional; kernel→userspace events.
- **Phase 5**: identity + additional ICS protocols (DNP3/IEC104); expand policy primitives.
- **Phase 6**: hardening + K8s packaging; RBAC/auth, secrets management.

---

## 14. Coding Style & Constraints

- Clear, idiomatic Go/TS; modular boundaries between DP/CP/MP; immutable rulesets and atomic swaps; native DPI/IDS; kernel-assisted enforcement baseline with optional eBPF acceleration; all functionality exposed via REST, UI, and SSH CLI.
