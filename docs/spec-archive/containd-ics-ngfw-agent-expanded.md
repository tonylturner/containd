# [ARCHIVED] Consolidated into agents.md. Do not edit.
# containd (ICS‑NGFW) – Single‑Image Appliance Spec (Agent Instructions)

You are an AI coding agent building **containd**, an open‑source next‑generation firewall designed for **ICS/OT environments**.
The product name is **containd**; the repository/container name is **containd**. (Use **containd** for module names, binaries, and Docker image tags unless a file already uses a different name.)

This project is implemented as a **single Docker image / appliance** by default, suitable for:
- Drop‑in use in a docker‑compose OT lab, and
- Real deployments bound to physical interfaces on Linux,
- With a growth path to Kubernetes.

This document is the authoritative reference for architecture, features, tech stack, code style, and delivery milestones.

Source: expanded from the previously supplied single‑appliance spec. fileciteturn0file0

---

## 0. Product Goals

### 0.1 Core outcomes

Build a high‑performance, open‑source NGFW that is:

- **Commercial‑grade** in operator experience:
  - Web GUI + SSH/CLI (network device style)
  - Strong defaults, auditability, rollback safety
  - Config export/import, backups, upgrades
- **OT/ICS‑aware**:
  - First‑class assets (PLC/HMI/SIS/RTU, etc.)
  - ICS DPI + ICS policy primitives
  - ICS‑centric dashboards and alerts
- **Deployable anywhere**:
  - **Single appliance container** by default (lab friendly)
  - Host mode on Linux with real NICs
  - K8s‑ready architecture (later)

### 0.2 Non‑goals (initially)

- Full TLS MITM decryption in v1 (collect metadata only: SNI/ALPN/JA3-like fingerprints, if implemented).
- Full SIEM replacement (export/forward telemetry; keep bounded local retention).
- Full L2 switch features (STP, VLAN trunking) beyond what’s required for routing + segmentation.

---

## 1. Stack, Runtime Model, and Packaging

### 1.1 Languages & frameworks

- **Go** (latest stable) for control/mgmt plane and the data plane engine.
- **Gin** for REST APIs (`/api/v1`).
- **Next.js (TypeScript)** for web GUI:
  - TailwindCSS
  - shadcn/ui
  - React Flow (topology + policy visualization)
  - Charts (Recharts or D3 wrapper)

### 1.2 Single binary with subcommands

Build **one Go binary** named `containd` with subcommands:

- `containd engine` – runs the **data plane** only
- `containd mgmt` – runs **control plane + APIs + UI + SSH CLI** only
- `containd all` – runs **engine + mgmt** in one process/container (**default**)

`containd all` must be safe and stable for:
- Lab deployments (docker-compose)
- Small single-node “real” deployments

### 1.3 Single Docker image

Produce **one Docker image**: `ghcr.io/<org>/containd:<tag>`

The image includes:
- `containd` binary
- Built Next.js UI assets embedded or copied into a static assets directory

Entrypoint defaults to `containd all`.

The same image can be used with explicit commands for advanced deployments, but *consuming projects* should only reference **one image name**.

### 1.4 Capabilities and privilege model

- The appliance container requires elevated networking privileges for enforcement:
  - `CAP_NET_ADMIN`, `CAP_NET_RAW`
  - (Optional later) `CAP_SYS_ADMIN` should be avoided; prefer least privilege.
- In host mode, engine needs access to netlink, nftables, and (optional) eBPF load.

Mgmt plane should not require NET_ADMIN, but in single-container mode it shares caps. Still implement internal privilege separation where possible:
- Run HTTP/UI/SSH as non-root inside the container.
- Keep the engine component isolated in code (separate packages; strict APIs).

---

## 2. Core Architectural Decision: Kernel‑Assisted Enforcement + eBPF Acceleration

### 2.1 Enforcement baseline (must implement)

**Baseline enforcement uses the Linux kernel:**
- **Routing/forwarding** in kernel
- **State tracking** via conntrack
- **Firewall policy** via **nftables** (preferred) with sets/maps for speed
- **NAT** via nftables (where required)

The data plane is not a “pure userspace router”. Userspace exists primarily to:
- Compile and install nftables rulesets
- Perform selective DPI/IDS and generate verdicts
- Update nftables dynamic sets/maps for block/allow/tags
- Export telemetry (flows/events/alerts)

Why:
- This gives production-grade forwarding/NAT correctness immediately (MTU, fragmentation, neighbor discovery, etc.)
- Preserves a path to high performance and correctness.

### 2.2 DPI/IDS interception strategies (phased)

Support these strategies, selected per policy:

1. **Metadata-only DPI** (cheap):
   - Parse early packets (ClientHello SNI, HTTP headers, DNS) without full stream reassembly where possible.

2. **Selective deep inspection** (default for ICS ports/services):
   - For flows that match policies requiring DPI (e.g., `tcp/502`, `dnp3`, `iec104`):
     - Use nftables/iptables to redirect a subset of traffic to userspace using:
       - NFQUEUE (initial approach), or
       - AF_PACKET mirror/tap (monitoring)
   - Userspace performs protocol parsing and emits verdicts.

3. **IPS blocking**:
   - On “block flow/host” verdict:
     - Add flow/IP into nftables set/map for immediate enforcement
     - Optionally kill conntrack entries for the flow
     - Optionally send TCP RST (careful; not always applicable)

### 2.3 eBPF plan (include in architecture now)

Add support for Linux eBPF as an **acceleration and visibility layer**:

- **XDP** (ingress):
  - Early drops based on fast rule subsets (e.g., known-bad, basic zone allow/deny)
  - Lightweight per-packet counters
  - Optional sampling/mirroring triggers

- **TC eBPF** (ingress/egress):
  - More flexible policy hooks
  - Tagging, rate-limiting primitives (phased)

- **Ring buffer/perf events**:
  - Export flow observations from kernel to userspace efficiently

Design constraint:
- eBPF is optional; the product must function without it.
- eBPF programs are versioned and loaded dynamically with compatibility checks.

---

## 3. Repository Layout

Create a monorepo:

```text
containd/
  cmd/
    containd/             # main() with subcommands: engine, mgmt, all
  pkg/
    dp/                   # data-plane core
      enforce/            # nftables/netlink programming + conntrack interaction
      capture/            # NFQUEUE/AF_PACKET mirrors, optional pcap capture
      flow/               # flow/session model + enrichment
      rules/              # compiled policy structures for fast matching
      dpi/                # generic DPI framework
      ics/                # ICS protocol decoders + models
      ids/                # IDS/IPS rules and evaluation
      verdict/            # verdict types + enforcement actions
      engine/             # orchestrates dp subsystems
    cp/                   # control-plane config + compile
      store/              # DB access layer (SQLite default)
      config/             # config model + schema versioning
      policy/             # high-level policies & objects
      compile/            # compile high-level policies -> dp bundles (nft + dpi + ids)
      identity/           # users/groups/sessions mapping
      services/           # syslog, ntp, dns config mgmt
      audit/              # audit log subsystem
    cli/                  # CLI command framework (shared)
    common/               # logging, metrics, errors, types
  api/
    http/                 # Gin handlers, routers, DTOs
    internal/             # internal RPC between mgmt<->engine (in-proc or localhost)
  ui/                     # Next.js app
  ebpf/                   # eBPF/XDP programs + build artifacts
    xdp/
    tc/
    include/
  deploy/
    docker/
      Dockerfile
      docker-compose.lab.yml
    k8s/
      # future manifests
  docs/
    architecture.md
    dataplane-enforcement.md
    ebpf.md
    ics-dpi.md
    policy-model.md
    cli.md
    config-format.md
    services.md
    deploy-host.md
    deploy-k8s.md
```

---

## 4. Configuration, Persistence, and “Appliance-Grade” Safety

### 4.1 DB choice and responsibilities

Default DB: **SQLite** stored on a persistent volume path (container) or filesystem (host mode).

SQLite stores:
- Interfaces, zones
- Objects (hosts/subnets/groups/services)
- ICS assets and groups
- Policies (firewall + IDS)
- Identity users/groups/sessions
- System services config (syslog/NTP/DNS)
- Audit log of config changes
- Bounded retention telemetry indexes (optional, limited)

Do **not** treat SQLite as a SIEM. Use it for appliance config and short retention operational views.

Optional future:
- Postgres support for HA deployments or multi-node mgmt; keep SQLite the default.

### 4.2 Candidate config / commit model (must implement)

Implement a robust config lifecycle:

- `running config` – what is currently enforced
- `candidate config` – staged changes not yet applied
- `commit` – atomically apply candidate -> running and push to engine
- `rollback` – revert to previous running config versions
- `commit confirmed <timeout>` – apply changes but auto-rollback if not confirmed

This is critical to prevent lock-outs and to match commercial appliance UX.

### 4.3 Config export/import

Support JSON backup/export/restore:

- Canonical JSON schema includes:
  - schema_version
  - objects, assets, policies, services, identity, admin users/roles
- Export should be deterministic (stable ordering) for diffs and GitOps.

Support:
- Full export
- Full restore (overwrite)
- Dry-run validation
- Optional partial merge later (explicit)

CLI and UI must expose export/import.

### 4.4 Audit logging (must implement)

Every config mutation must produce an immutable audit record:
- who (user/role)
- when (timestamp)
- source (SSH session, UI, API client IP)
- what (structured diff: before/after, or patch)
- result (success/failure)

Audit log is:
- Viewable in UI/CLI
- Exportable
- Forwardable via syslog

### 4.5 Secrets handling

Do not store sensitive secrets in plaintext in the DB export by default.

- In DB: store secrets encrypted at rest using a master key provided via:
  - file mount (`/etc/containd/master.key`) or
  - environment var (lab mode only)
- Export:
  - redact secrets unless `--include-secrets` is explicitly requested (CLI) and UI prompts clearly.

---

## 5. Data Plane: Models, Pipelines, and Performance Constraints

### 5.1 Policy evaluation pipeline

Design a multi-stage pipeline:

1. **Fast L3/L4 path** (kernel):
   - nftables decides allow/deny/NAT for most traffic
   - zone-to-zone policy enforced here

2. **Selective DPI path** (userspace):
   - only flows requiring L7/ICS inspection are copied/queued to userspace
   - DPI decoders emit events and candidate verdicts

3. **IDS/IPS path**:
   - IDS rules evaluate events/flows
   - IPS verdicts cause dynamic nftables updates (block sets) and optional conntrack kill

4. **Telemetry path**:
   - export flow logs, DPI events, IDS alerts
   - local bounded retention + forwarding

### 5.2 Flow model

Maintain a flow/session model primarily for:
- enrichment (asset, identity)
- DPI state and stream reassembly
- IDS rule evaluation
- telemetry export

Avoid relying solely on userspace flow tracking for correctness of routing; kernel handles forwarding.

### 5.3 Verdict types (formalize this)

Define a standard verdict interface:

- `ALLOW_CONTINUE`
- `DENY_DROP`
- `DENY_RESET` (TCP)
- `ALERT_ONLY`
- `BLOCK_FLOW_TEMP` (flow tuple)
- `BLOCK_HOST_TEMP` (src/dst IP or asset)
- `RATE_LIMIT_FLOW`
- `TAG_FLOW`

Verdicts must include:
- reason code
- severity
- rule ID
- expiration (for temp blocks)

### 5.4 DPI safeguards

Implement strict resource controls:

- Per-flow reassembly memory cap
- Global DPI memory budget
- Timeouts/evictions
- Backpressure:
  - If DPI overloaded, default behavior must be predictable:
    - either fail-open (allow) or fail-closed (deny) based on zone policy
  - default should be **fail-open for lab**, configurable for production.

---

## 6. ICS/OT First-Class Capabilities

### 6.1 Asset model (required)

Make “assets” first-class objects, not just IPs:

Asset types:
- PLC, SIS PLC, HMI/SCADA, Historian, Engineering Workstation, RTU, Gateway, Vendor Laptop, etc.

Assets include:
- zone
- IPs/hostnames
- criticality
- allowed protocols/services
- tags (plant, unit, function, vendor)

Rules should be able to reference:
- assets and groups of assets (e.g. “SIS group”)
- not only raw IPs/ports

### 6.2 ICS protocol primitives (design for operator intent)

For each ICS protocol, define stable policy primitives.

**Modbus/TCP**
- allow/deny by:
  - read vs write function classes
  - explicit function codes
  - unit ID
  - register/coil ranges (including named ranges)
- optionally enforce “read-only” modes per asset group

**DNP3**
- allow/deny by function/object group/variation (phased)

**IEC‑104**
- allow/deny by command categories (phased)

**S7comm / CIP / OPC UA**
- begin with identification + visibility, then add policy controls progressively

### 6.3 OT policy templates (ship with defaults)

Include built-in templates (“safe modes”):

- Purdue baseline:
  - IT → DMZ limited
  - DMZ → OT Control minimal required
  - OT Safety very restrictive
- Maintenance window:
  - allow engineering group write operations for defined time window
- SIS hardening:
  - deny all writes to SIS except explicit maintenance role

These templates speed up lab use and deliver “commercial feel” early.

---

## 7. Identity-Aware Policy

### 7.1 Identity sources

Support:
- Local users/groups (v1)
- OIDC / LDAP integration later
- Session mappings from:
  - VPN endpoints
  - jump host/EWS agents
  - lab console integration

Maintain:
- `IdentitySession { user, groups, device, ip, ttl }`

### 7.2 Rule matching

Firewall and ICS rules can match:
- user
- group
- role
- device tag/type
- time schedule

Example:
- Engineering group can write Modbus to PLC group during maintenance window.
- Contractor group read-only to HMI; no access to SIS.

---

## 8. Management: API, Web UI, SSH CLI

### 8.1 REST API (Gin)

Expose `/api/v1` endpoints for:

- system: health, version, time/NTP status
- interfaces/zones
- objects: hosts/subnets/groups/services
- assets: ICS assets and groups
- identity: users/groups/sessions
- policies:
  - firewall rules
  - IDS rules
  - ICS protocol rules
- config lifecycle:
  - get running/candidate
  - diff candidate vs running
  - commit / commit-confirmed / rollback
- telemetry:
  - flows
  - events (DPI/ICS)
  - alerts (IDS)
- services:
  - syslog config and forwarders
  - DNS config
  - NTP config
- audit:
  - list audit records

### 8.2 Web UI (Next.js)

Requirements:
- modern dashboard aesthetic
- dark mode desirable
- all major features must be accessible from UI and CLI

Key screens:
- Dashboard (health, throughput, top alerts)
- Topology (React Flow): zones, interfaces, assets, live flows overlays
- Policies:
  - firewall rule table/editor
  - ICS rule editor (protocol primitives)
  - IDS rules editor
- Alerts & Events:
  - filters by asset/protocol/severity/user/time
- Config:
  - candidate/running diff
  - commit/rollback UI with commit-confirmed timer
  - export/import
- Services:
  - syslog, dns, ntp
- Audit log view

### 8.3 SSH CLI (network device style)

Implement a CLI with:
- `configure terminal`
- `show running-config`
- `show candidate-config`
- `diff`
- `commit`
- `commit confirmed 300`
- `rollback 1`
- `show audit`
- `export config json`
- `import config json <file>`

CLI must operate on the same underlying CP APIs; no divergent config logic.

---

## 9. System Services (Enterprise features)

### 9.1 Syslog

- local structured logs
- syslog forwarding:
  - multiple targets
  - UDP/TCP
  - format options

Forward at least:
- IDS alerts
- policy deny events (configurable volume)
- audit log events (recommended always)

### 9.2 NTP

- appliance NTP client configuration
- show sync status in UI/CLI

### 9.3 DNS

- local caching resolver with upstream forwarders
- optional local zone records for lab convenience

---

## 10. Security Defaults & Hardening

### 10.1 Authentication and RBAC

- UI and API authentication required by default
- RBAC roles:
  - admin
  - operator (policy changes)
  - auditor (read-only)
  - lab-student (limited)

### 10.2 SSH defaults

- Default: SSH key auth enabled
- Password auth disabled by default (allowed in lab mode only)
- Rate-limit login attempts

### 10.3 HTTPS defaults

- Default: HTTPS enabled for UI/API with auto-generated self-signed cert
- Support custom cert install/rotate

### 10.4 Principle of least privilege

- mgmt services run as non-root
- engine may require root/caps for net admin tasks; isolate privilege in code

---

## 11. Observability

Implement:
- Prometheus metrics endpoint (optional, recommended)
- OpenTelemetry export optional (later)
- Log level controls and sampling knobs
- Packet capture hooks for debugging:
  - export minimal pcap samples for a flow (with explicit operator action)

---

## 12. Deployment Scenarios

### 12.1 Docker compose lab appliance

Single service:
- multi-homed across IT/DMZ/OT networks
- persistent volume for SQLite DB and certs/keys

Example:
```yaml
services:
  containd:
    image: ghcr.io/you/containd:latest
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./data:/var/lib/containd
      - ./keys:/etc/containd
    networks:
      - it_net
      - dmz_net
      - ot_control_net
      - ot_safety_net
    ports:
      - "8443:8443"
      - "2222:22"
```

### 12.2 Host mode

- Bind engine to physical NICs
- systemd unit runs `containd all` or split commands
- management reachable on mgmt interface only by default

### 12.3 Kubernetes (future)

Clarify K8s expectation:
- not necessarily “multi-NIC gateway”
- likely node-level enforcement with privileged daemonset + policy distribution
- maintain one image, different commands

---

## 13. Implementation Phases (Updated)

### Phase 0 – Scaffolding + enforcement skeleton
- Create repo structure
- `containd` subcommands
- Mgmt API skeleton + UI skeleton
- SQLite store + migrations
- nftables programming skeleton (list interfaces, install base rules)
- Health endpoints

### Phase 1 – Zone firewall + NAT via nftables (real enforcement)
- Define zones, interfaces
- Implement policy compile -> nftables rules
- Candidate/commit/rollback + audit logs
- UI/CLI for basic policies
- Syslog forwarding + NTP status

### Phase 2 – Selective DPI pipeline + Modbus visibility
- Add NFQUEUE or mirror capture for selected ports
- Implement Modbus decoder
- Emit ICS events and show in UI
- Add ICS “read-only vs write” primitives (visibility first)

### Phase 3 – Native IDS/IPS + ICS enforcement
- IDS rules on Modbus events
- IPS verdict updates nftables sets/maps + conntrack kill
- Add templates: Purdue baseline, SIS hardening

### Phase 4 – eBPF acceleration (XDP/TC)
- Add optional XDP early drop/counters
- Add kernel-to-userspace event streaming
- Keep fallback to non-eBPF mode

### Phase 5 – Identity + additional ICS protocols
- identity sessions + group-based matching
- add DNP3 and IEC104 parsers
- expand policy primitives

### Phase 6 – Hardening + K8s packaging
- RBAC, auth hardening, secrets management
- K8s manifests and documented modes

---

## 14. Coding Style & Constraints

- Prefer clear, idiomatic Go/TS.
- No giant god-packages; keep boundaries between DP/CP/MP.
- No locks in hot path; immutable rulesets and atomic swaps.
- Core DPI and IDS are **native** to this project.
- Kernel-assisted enforcement (nftables/conntrack) is the baseline; eBPF is an optional acceleration layer.
- Everything is configurable through:
  - REST API
  - Web UI
  - SSH CLI

Use this document as the authoritative guide when scaffolding and implementing containd/ICS‑NGFW.
