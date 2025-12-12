# containd (ICS‑NGFW) – Consolidated Agent & Project Specification

Authoritative, consolidated instructions for building **containd / ICS‑NGFW** as a **single‑image appliance**. This file supersedes all other root‑level specs; historical drafts are archived under `docs/spec-archive/`.

---

## 0. Product Principles

1) **Single appliance image by default**: users run one container/image in labs and small deployments; split mgmt/engine remains optional.
2) **Everything feels native**: embedded OSS components (Envoy/Nginx/Zeek/Unbound/OpenNTPD) are configured through containd UI/CLI/API, lifecycle‑managed by containd, and their events are normalized into containd’s event model.
3) **Kernel‑assisted enforcement baseline**: Linux forwarding + conntrack + nftables are the production fast path; userspace augments via selective DPI/IDS and dynamic nftables sets. eBPF is optional acceleration.
4) **OT/ICS first‑class, plus strong IT coverage**: assets and ICS policy primitives are core; IT protocol DPI and proxy features are built‑in, not bolt‑ons.

---

## 1. Stack, Runtime Model, Packaging

- **Go** (latest stable) for CP/DP/MP orchestration; **Gin** REST APIs under `/api/v1`.
- **Next.js (TypeScript)** UI with Tailwind + shadcn/ui; React Flow for topology; charts later.
- **Single Go binary** `containd` with subcommands: `engine`, `mgmt`, `all` (default).
- **Single Docker image** `containd` containing the binary and built UI assets; entrypoint `containd all`.
- Container capabilities: `CAP_NET_ADMIN`, `CAP_NET_RAW`; avoid `SYS_ADMIN`. Run mgmt/UI/SSH non‑root; isolate privileged DP operations in code.

**Embedded daemons (optional, native UX):**
- Forward proxy: **Envoy** explicit forward proxy (Apache‑2.0).
- Reverse proxy: **Nginx** (BSD‑like).
- IT DPI/telemetry: **Zeek** (BSD‑3‑Clause, optional).
- DNS resolver: **Unbound** (BSD‑3‑Clause).
- NTP client: **OpenNTPD** (ISC).

**Process supervision requirement:** `containd all` includes a Go supervisor that starts/stops/reloads embedded daemons, validates configs before reload, tracks health, and exposes status via API/UI/CLI. Use `tini` only for signal forwarding.

---

## 2. Architecture & Enforcement

### 2.1 Planes (logical, even in one process)
- **Data plane (DP)**: nftables/conntrack enforcement, capture, flow model, DPI/IDS, verdicts, dynamic sets, telemetry.
- **Control plane (CP)**: SQLite persistence, config lifecycle, services/proxies/sensors config, policy compilation → DP snapshots + nftables rulesets/sets, audit, identity (phased).
- **Management plane (MP)**: REST API, UI, SSH CLI, web console, dashboards, auth/RBAC.

### 2.2 Baseline enforcement
- L3/L4 zone firewall and NAT in **nftables** with sets/maps for performance.
- Userspace compiles/installs rulesets and updates dynamic sets for temp blocks, tags, rate limits.
- IPS verdicts may delete conntrack entries for immediate effect.

### 2.3 Selective DPI/IDS path
- Selective interception via **NFQUEUE** first; AF_PACKET mirror for passive inspection; eBPF ringbuf later.
- DPI decoders emit normalized events; IDS evaluates events/flows; IPS verdicts update dynamic nftables sets.

### 2.4 eBPF (optional)
- XDP early drops/counters; TC hooks later; versioned and optional. System must work without eBPF.

---

## 3. Config, Persistence, Safety

- Default DB: **SQLite** (persistent volume). Stores interfaces/zones, objects, assets, policies (FW/ICS/IDS/Proxy), identity, services, audit, bounded telemetry indexes.
- **Candidate/running lifecycle** with diff, commit, commit‑confirmed (auto‑rollback), rollback.
- Canonical, deterministic JSON export/import with schema versioning and upgrade paths; secrets redacted by default and encrypted at rest.
- All runtime toggles (capture/enforcement/DPI mock/proxy enablement/etc.) are persisted in config and settable via UI/CLI/API; avoid long container flag lists.
- Appliance defaults include **8 physical interfaces** pre-seeded in config: `wan`, `dmz`, `lan1`–`lan6`. They appear automatically in UI/CLI in a default/unassigned state and can be configured via UI/CLI/JSON. Future virtual/tunnel interfaces are added dynamically when VPNs/tunnels are defined.
- Default zones are pre-created: `wan`, `dmz`, `lan`, `mgmt`. By default, interfaces map as: `wan`→`wan`, `dmz`→`dmz`, `lan1`→`mgmt`, `lan2`–`lan6`→`lan`.
- Management UI/API binds to **all interfaces by default** (`:8080` / 0.0.0.0) so the web UI is reachable on WAN/DMZ/LAN in lab setups. Binding is configurable via persisted `system.mgmt.listenAddr` and can be narrowed to a specific address/interface for production. Localhost access must always remain possible for operators.
- Fresh appliances provision with a **default‑deny firewall posture** (default action `DENY` for any→any any service/protocol). A built‑in top rule `allow-mgmt-ui` allows TCP/8080 access to the management UI/API from any interface; operators can tighten this later.

---

## 4. Policy Model

### 4.1 Objects & Assets
- Hosts/subnets/groups/services; **assets** as first‑class (type, zone, IPs/hostnames, criticality, tags).
- Rules reference assets/groups, not just IPs.

### 4.2 Firewall rules
- Match on zones, objects/assets, services, schedules, identity (phased), application/protocol (IT + ICS).
- Actions: allow/deny/reset, log, rate‑limit, tag, mirror (phased), temp blocks.

### 4.3 ICS primitives (core)
- **Modbus/TCP**: read/write classes, function codes, unit ID, register/coil ranges; per‑asset read‑only modes.
- Phased: DNP3, IEC‑104, S7comm/CIP/OPC UA.

### 4.4 IT DPI minimums (core)
- DNS (qname/rrtype), TLS (SNI/ALPN), HTTP (method/host/path/status), SSH banner, RDP/SMB/SNMP/NTP basic visibility.
- Policy hooks over metadata first, deeper controls later.

---

## 5. Proxies (Native UX)

### 5.1 Forward proxy – Envoy
- Explicit forward proxy v1 using Envoy’s forward‑proxy/filter chain; transparent steering later.
- UI/CLI config: enable/disable, listen zones/ports, client allowlists (objects/assets), domain ACLs, upstream chaining (phased), logging → unified events.

### 5.2 Reverse proxy – Nginx
- UI/CLI config for “published apps”: listeners, TLS termination, upstream pools, host/path routing, health checks, basic allow/deny and rate‑limits (phased), logs/metrics → unified events.

No raw daemon config editing exposed as the primary UX.

---

## 6. IDS/IPS & Telemetry

- Always‑on lightweight native detection over DPI events/flows, especially ICS.
- Optional **Zeek** integration for rich IT/ICS telemetry, lifecycle‑managed and logs normalized.
- Unified event schema includes firewall decisions, DPI/ICS events, IDS alerts, proxy logs, audit/system events; bounded local retention + forwarding (syslog required; Prometheus/OTLP later).

---

## 7. Management UX

- **Commercial‑style dashboard** with system status, traffic/session charts, top apps/protocols, IDS alerts, OT/ICS panels (PLC access, Modbus read/write), and proxy panels.
- **Left‑nav appliance UI** with entry points for config and monitoring.
- **Web console** in UI using the same CLI engine as SSH (xterm.js + WebSocket), audited like SSH.

---

## 8. Security & Hardening

- Auth/RBAC roles: admin/operator/auditor/lab; auth required by default.
- HTTPS default with self‑signed cert; custom cert install/rotate.
- SSH key auth default; passwords only in lab mode; login rate limiting.
- Secrets encrypted at rest; redacted exports unless explicitly included.

---

## 9. Repository Layout (target)

Maintain the target layout from earlier specs; current repo still uses `cmd/ngfw-engine` and `cmd/ngfw-mgmt` but should migrate toward `cmd/containd` with subcommands.

---

## 10. Implementation Roadmap

Use as many phases as needed; sequencing priority:
1) Appliance‑grade CP foundation (config lifecycle, audit, export/import, RBAC, services plumbing).
2) Baseline DP enforcement (zones/NAT via nftables, dynamic sets, conntrack kill).
3) Selective DPI framework + Modbus visibility + ICS primitives in policy.
4) Commercial UI: dashboard, topology placeholder, policies, alerts/events, config lifecycle UI, web console.
5) IT DPI minimums + proxy integration (Envoy + Nginx) with native UX and unified events.
6) Optional Zeek integration with native UX.
7) eBPF acceleration and performance hardening.

`docs/tasks.md` is the authoritative task tracker aligned to this roadmap.

---

## 11. Coding Style & Constraints

- Clear, idiomatic Go/TS; strict DP/CP/MP boundaries.
- Immutable DP snapshots and atomic swaps.
- Least‑privilege runtime; no raw third‑party config UX.
