# [ARCHIVED] Consolidated into agents.md. Do not edit.
# containd / ICS‑NGFW – Integrated Proxy + IDS/DPI + “Commercial UI” Spec (Single‑Image Appliance)

This is the **Codex build spec / agent file** for a single‑image, single‑container NGFW appliance with:
- ICS‑first firewalling + DPI
- Common IT protocol coverage
- **Forward proxy + reverse proxy** (embedded, but configured through native UI/CLI)
- Optional integration of **Suricata** (IDS/IPS) and **Zeek** (network telemetry) that still feels **native**
- SSH CLI **and** an in‑UI console that behaves identically to SSH CLI
- A main dashboard and reporting views that feel like commercial NGFWs

> Out of scope for v1 (can come later): HA clustering, captive portal, and a general plugin marketplace/ecosystem.

---

## 0. Non‑negotiables (Product Principles)

1) **Single appliance image by default**  
   Consumers (e.g., OT lab ranges) should add **one service** referencing **one image**.

2) **Everything feels native**  
   Even if we embed 3rd‑party components (Squid/HAProxy/Suricata/Zeek), the UX must be:
   - configured via our UI/CLI/API,
   - status/metrics visible in our dashboard,
   - logs/alerts ingested and normalized by our system.

3) **Kernel‑assisted enforcement baseline**  
   Linux kernel does routing/state/NAT; we program policy via **nftables + conntrack**.  
   eBPF is optional acceleration.

4) **OT/ICS is first‑class, not a bolt‑on**  
   Asset model + ICS protocol controls are core.

---

## 1. Runtime & Packaging

### 1.1 One binary with subcommands

Build **one Go binary** called `containd`:

- `containd engine` – data plane only
- `containd mgmt` – control plane + UI/API + SSH/CLI only
- `containd all` – **both** engine and mgmt (default for the appliance)

### 1.2 One Docker image

Publish **one image**: `ghcr.io/<org>/containd:<tag>`

The image includes:
- the `containd` binary
- built Next.js UI assets
- packaged system services/binaries:
  - **Squid** (forward proxy)
  - **HAProxy** (reverse proxy / L7 LB) *(or Nginx if preferred; choose one and standardize)*
  - **Suricata** *(optional but supported; for IDS/IPS signatures)*
  - **Zeek** *(optional but supported; for rich telemetry/metadata)*
  - DNS resolver (recommend **Unbound** or dnsmasq; pick one)
  - NTP client (chrony or systemd-timesyncd; pick one)

**Critical constraint:** These external components must be controlled by our config model and surfaced as “native”.

### 1.3 Process supervision

The container runs a single entrypoint:
- `containd all`

Inside `containd all`, implement a **component supervisor** that can:
- start/stop/reload Squid, HAProxy, Suricata, Zeek, DNS, NTP (as configured),
- validate configs before reload,
- watch health and restart on failure,
- expose component status to UI/CLI/API.

Avoid adding a heavy init system; keep supervision in Go unless a minimal supervisor is required.

### 1.4 Privileges

Container requires:
- `CAP_NET_ADMIN`, `CAP_NET_RAW`

Try to run mgmt services (HTTP/UI/SSH) as non‑root; engine and system-level operations can run with necessary privileges.

---

## 2. Core Architecture

### 2.1 Planes (even inside one container)

- **Data Plane (DP)**: enforcement, DPI, flow/conn state, dynamic blocklists
- **Control Plane (CP)**: config/policy store, compile, push into DP + components
- **Management Plane (MP)**: UI/API/CLI, audit, auth/RBAC, dashboards

### 2.2 Enforcement baseline: nftables + conntrack (mandatory)

Implement the firewall as kernel-assisted:

- Zone-based policy enforced in nftables
- NAT handled in nftables
- State via conntrack
- Dynamic decisions (e.g., block host/flow temporarily) done via:
  - updating nftables sets/maps
  - optionally removing conntrack entries for immediate effect

### 2.3 eBPF acceleration (planned, optional)

Add optional eBPF:
- **XDP** for early drops/counters (fast denylist, basic allow/deny)
- **TC** for more flexible hooks
- Export kernel events to userspace via ring buffer for high-performance telemetry

System must work fine without eBPF.

---

## 3. Configuration, Persistence, and Safety

### 3.1 DB: SQLite default

Use **SQLite** for appliance config, stored on a persistent volume:
- interfaces/zones
- objects/groups/services
- assets and asset groups
- policies (FW + DPI + IDS)
- user/group/RBAC and identity sessions
- system services config (syslog, NTP, DNS, proxies, sensors)
- audit log
- bounded retention for recent alerts/events/flows (optional)

Do **not** aim to be a SIEM. Provide forwarding/export.

### 3.2 Candidate config + commit/rollback (required)

Implement appliance-grade config lifecycle:

- `running config`
- `candidate config`
- `commit`
- `commit confirmed <timeout>` (auto rollback if not confirmed)
- `rollback <n>`

Must be available via:
- SSH CLI
- UI (diff view + commit timer)
- API

### 3.3 JSON export/import

Provide deterministic JSON export/import:
- export running config
- import as candidate (validate + preview diff)
- commit to apply
- redact secrets by default

---

## 4. Policy Model (Firewall + DPI + Proxies + IDS/Telemetry)

### 4.1 Objects and assets

Support object types:
- host, subnet, fqdn (optional), address group
- service (proto/ports), service group
- user/group/role
- **asset** (PLC/HMI/SIS/RTU/EWS/etc.), asset group, tags, criticality

Rules should reference **assets/groups** (not only IPs).

### 4.2 Firewall rules

Rule match fields:
- src/dst zone
- src/dst object/asset/group
- service/proto/port
- schedule
- identity (user/group/role) when available
- application/protocol (IT + ICS)

Actions:
- allow / deny / reset
- log
- rate limit (basic)
- tag (for chaining)
- mirror (optional)

### 4.3 DPI policy primitives

DPI must cover **ICS and common IT protocols**:

**ICS protocols (first-class):**
- Modbus/TCP: function codes, read vs write, unit id, register/coil ranges
- DNP3 (phase)
- IEC‑104 (phase)
- S7comm / CIP / OPC UA visibility first, then controls

**IT protocols (must include):**
- DNS (qname, rrtype)
- HTTP (host, method, path; HTTP/2 visibility as feasible)
- TLS (SNI, ALPN; fingerprinting optional later)
- SSH (client/server banners metadata)
- RDP (metadata where feasible)
- SMB (visibility where feasible)
- SMTP (basic metadata)
- NTP (basic)

Start with strong metadata parsing + policy hooks; expand to deeper controls over time.

---

## 5. Proxies (Forward + Reverse) – Embedded but Native UX

### 5.1 Forward proxy (Squid)

Embed Squid as the forward proxy implementation.

Modes:
1) **Explicit forward proxy**
   - Clients are configured to use proxy
2) **Transparent forward proxy** (optional phase)
   - Redirect HTTP/HTTPS (CONNECT) via nftables to Squid

Capabilities to expose in UI/CLI:
- enable/disable proxy
- listen interfaces/zones/ports
- allowed client subnets/assets/groups
- upstream proxy chaining (optional)
- auth integration (later; keep hooks)
- ACLs by:
  - destination domains (allow/deny)
  - categories/tags (optional later)
  - identity groups (future)
- logging:
  - proxy access logs ingested into our telemetry
  - syslog forwarding of proxy events

**Native UX requirement:** Users should never need to edit squid.conf directly. We generate it from our config model.

### 5.2 Reverse proxy (HAProxy)

Embed HAProxy as the reverse proxy/L7 load balancer.

Capabilities to expose in UI/CLI:
- define “published apps”:
  - frontends (listen address/port, TLS termination)
  - backends (targets, health checks, balancing)
  - routing (host-based, path-based)
- TLS certificate management:
  - self-signed default; custom cert upload
  - ACME automation can be later
- security controls:
  - basic allow/deny by source zone/object
  - rate limit basic (optional)
- logging + metrics:
  - per-frontend/backend stats in dashboard
  - request logs in event pipeline

**Native UX requirement:** HAProxy config is generated from our model; UI provides a first-class editor for apps/frontends/backends.

---

## 6. IDS/IPS and Telemetry: “Native”, with Optional Suricata/Zeek

### 6.1 Philosophy

We want a **native experience** even if we leverage mature open-source engines.

We will support three tiers:

1) **Native lightweight detection** (always-on):
   - basic signatures and anomaly rules on our DPI events (especially ICS)
2) **Suricata integration** (optional but supported):
   - signature-based IDS/IPS, mature rule ecosystem
   - can run IDS-only or IPS (NFQUEUE) depending on deployment
3) **Zeek integration** (optional but supported):
   - rich protocol telemetry and logs for IT + ICS visibility
   - used primarily for reporting and deep metadata, not necessarily enforcement

All alerts/events must be normalized into our internal schema and shown in our UI as first-class.

### 6.2 Suricata integration details

- Manage Suricata as a supervised component.
- Expose in UI/CLI:
  - enable/disable
  - mode: IDS-only / IPS (NFQUEUE)
  - rule sources:
    - local rules
    - remote feeds (optional later)
  - tuning knobs (performance, interfaces, queues)
  - status, drops, alert counts
- Ingest Suricata alerts (EVE JSON) into our event store.
- Map alerts to assets/zones/identities where possible.

**UX requirement:** Suricata should feel like “Built-in IPS” with a native configuration UI. We may mention it uses Suricata under the hood, but the operator uses our UI.

### 6.3 Zeek integration details

- Manage Zeek as a supervised component.
- Run in sensor mode on selected interfaces.
- Ingest Zeek logs/events into our normalized event pipeline.
- Expose in UI/CLI:
  - enable/disable
  - interfaces
  - scripts/policies selection (later)
  - status and log volume
- Use Zeek outputs to enrich:
  - application identification
  - asset discovery (optional)
  - reporting dashboards

**UX requirement:** Zeek should feel like “Traffic Insights / Network Analytics”.

---

## 7. “Commercial Firewall” UI + In-UI Console

### 7.1 Main dashboard (commercial-style)

Create a dashboard that looks and feels like modern NGFW dashboards:

- **Top status row**
  - system health (CPU/mem/disk)
  - version/build/channel
  - uptime
  - interface link state
  - time sync status
- **Traffic charts**
  - throughput over time (per interface/zone)
  - sessions/flows over time
  - top apps/protocols (IT + ICS)
- **Security panels**
  - IDS alerts (last hour/day, by severity)
  - top blocked rules
  - top offenders (src IP/asset)
- **OT/ICS panels**
  - top PLCs accessed
  - Modbus read/write ratio
  - top “unsafe” actions (writes/commands)
- **Proxy panels**
  - forward proxy requests/sec
  - reverse proxy requests/sec
  - top destinations/services

### 7.2 Navigation layout

Left nav (suggested):
- Dashboard
- Topology (React Flow)
- Policies
  - Firewall
  - ICS Controls
  - IDS/IPS (Native/Suricata)
- Objects & Assets
- Traffic & Sessions
- Alerts & Events
- Proxies
  - Forward Proxy
  - Reverse Proxy
- Reports
- System
  - Interfaces/Zones
  - DNS/NTP/Syslog
  - Users/RBAC
  - Config (candidate/commit/export/import)
- Console (Web CLI)

### 7.3 In-UI console/CLI that behaves like SSH

Implement an in-UI terminal that uses **the same CLI engine** as SSH:

- Frontend: xterm.js (or similar) with a clean “appliance console” look
- Backend: WebSocket session that binds to the CLI interpreter
- Must support:
  - config mode
  - show commands
  - commit/rollback
  - paging for long outputs
  - copy/paste
  - session timeout
- Audit:
  - record commands executed (at least in audit log)
  - associate with user and source (UI session)

**Important:** The web console must be a first-class management path, not a toy.

---

## 8. Observability and Reporting

### 8.1 Normalized event pipeline

Create a unified schema for:
- flow/session events
- DPI events (IT + ICS)
- IDS alerts (native)
- Suricata alerts (if enabled)
- Zeek logs/events (if enabled)
- proxy logs (squid/haproxy)
- firewall deny events
- audit events

Store locally with bounded retention and allow export/forward.

### 8.2 Export and integrations

- Syslog forwarding (required)
- Optional later:
  - Prometheus metrics endpoint
  - OpenTelemetry export
  - NetFlow/IPFIX export

---

## 9. Security Defaults

- SSH:
  - key auth on by default
  - password auth allowed only in “lab mode”
- UI/API:
  - HTTPS default with self-signed cert generation
  - RBAC:
    - admin, operator, auditor, lab-student
- Secrets:
  - encrypted at rest
  - redacted in exports by default
- Audit logs:
  - immutable and forwardable

---

## 10. Implementation Milestones (Updated Roadmap)

### Phase 0 – Scaffolding + integrated UI skeleton
- Repo structure, monorepo
- `containd` subcommands + `all` default
- SQLite store + migrations
- Auth/RBAC scaffolding
- UI: login + shell layout + dashboard skeleton
- Web console skeleton (xterm.js + WS)

### Phase 1 – Real firewall enforcement (nftables/conntrack) + “commercial” dashboard v1
- Zone firewall + NAT
- Candidate/commit/rollback + audit
- UI: policy editor, interface/zone pages
- Dashboard: throughput, sessions, alerts, system info
- CLI: show/config/commit workflows

### Phase 2 – IT protocol visibility + Proxy integration v1
- DPI metadata: DNS/HTTP/TLS
- Squid forward proxy (explicit) integrated + UI/CLI
- HAProxy reverse proxy integrated + UI/CLI
- Ingest proxy logs into unified events

### Phase 3 – ICS DPI v1 + OT-focused dashboards
- Modbus parser + controls (read/write, function codes, ranges)
- OT dashboards: PLC access, read/write ratios, unsafe actions
- Policy templates (Purdue baseline, SIS hardening)

### Phase 4 – “Native IPS” with Suricata option + unified alerts
- Native IDS rules engine baseline
- Suricata integration (optional) managed + UI/CLI
- Unified alerts and reporting views

### Phase 5 – Zeek option + rich reporting
- Zeek integration (optional) managed + UI/CLI
- Reporting pages: top talkers/apps, DNS/HTTP summaries, OT/ICS reports

### Phase 6 – eBPF acceleration (optional) + performance hardening
- XDP early drops/counters
- kernel-to-userspace event streaming
- tuning controls in UI

---

## 11. Codex Instructions

When implementing, follow these rules:

- Do not expose “raw” configs of Squid/HAProxy/Suricata/Zeek to the user as the primary method.
  - Users configure via our UI/CLI.
  - We render configs from templates.
- All components must have:
  - enable/disable
  - status page
  - logs view
  - health checks
  - audit entries for config changes
- The web console and SSH CLI must share the same command engine and produce identical outputs.
- Keep defaults safe:
  - deny-by-default policies between zones until explicitly allowed (templates help)
  - protect mgmt plane access

---

## 12. Licensing & Notices (practical requirement)

We may embed GPL components (e.g., Squid, Suricata). Ensure the build includes:
- license notices
- source offer / references as required
- clear attribution in “About” page in the UI

(Keep this lightweight but compliant.)

---

## 13. Deliverable

Produce a working, single-container appliance that can be dropped into an OT lab by adding **one service** in docker-compose and that provides:
- web UI
- integrated dashboard
- in-UI console
- SSH CLI
- forward + reverse proxy features (native UX)
- IT + ICS protocol visibility
- optional Suricata + Zeek integrations (native UX)
