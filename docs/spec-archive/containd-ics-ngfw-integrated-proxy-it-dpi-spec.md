# [ARCHIVED] Consolidated into agents.md. Do not edit.
# containd (ICS‑NGFW) – Integrated Appliance Spec (Proxies + IT & ICS DPI/IDS)

You are an AI coding agent building **containd**, an open‑source next‑generation firewall designed for **ICS/OT environments**, packaged as a **single Docker image / appliance** by default.

This spec expands the current plan to include:
- **Forward proxy** and **reverse proxy** features (embedded, UI/CLI managed; feels native)
- Stronger coverage of **common IT protocols** alongside ICS protocols
- Optional integration of **Suricata** (IDS/IPS signatures) and **Zeek** (DPI/telemetry), **embedded inside the same image** and managed by containd so the UX remains integrated and “native”.

> Non-goals for now: HA clustering, captive portal, plugin ecosystem. Those can be added later.

---

## 0. Product Goals

### 0.1 Core outcomes

Build a high‑performance, open‑source NGFW appliance that is:

- **Single-container appliance** by default (lab + real deployments)
- **Commercial-grade operator experience**
  - Web GUI + SSH/CLI
  - Candidate config + commit/rollback safety
  - Audit logs
  - Config export/import
  - Enterprise services: syslog/NTP/DNS (+ optionally DHCP later)
- **OT/ICS-aware**
  - Assets (PLC/HMI/SIS/RTU) as first-class objects
  - ICS protocol DPI and ICS-specific policy primitives
  - ICS-centric dashboards and alerts
- **Also strong on IT protocols**
  - HTTP/TLS/DNS visibility and filtering
  - SSH/RDP/SMB/SNMP/etc. recognition and policies (phased)
- **Proxy-capable**
  - Forward proxy (Squid) and reverse proxy (HAProxy or Nginx)
  - Managed natively via the same UI/CLI/config model

### 0.2 Explicit scope decisions

- No HA clustering in v1 (no VRRP/conntrackd). May add later.
- No captive portal in v1.
- No “plugin marketplace” in v1. Instead, embed a small number of carefully chosen OSS components (Squid/HAProxy/Suricata/Zeek) behind a native UX.

---

## 1. Stack, Runtime Model, and Packaging

### 1.1 Languages & frameworks

- **Go** (latest stable) for control/mgmt + data plane orchestration
- **Gin** for REST APIs (`/api/v1`)
- **Next.js (TypeScript)** UI:
  - TailwindCSS + shadcn/ui
  - React Flow (topology + flow visualization)
  - Charts (Recharts or D3 wrapper)

### 1.2 Single binary with subcommands

Build one Go binary named `containd`:

- `containd engine` – data plane only
- `containd mgmt` – control plane + APIs + UI + SSH CLI only
- `containd all` – engine + mgmt in one container (**default**)

### 1.3 Single Docker image

Publish one image:

- `ghcr.io/<org>/containd:<tag>`

The image contains:
- `containd` binary
- built UI assets
- optional embedded daemons:
  - Squid (forward proxy)
  - HAProxy or Nginx (reverse proxy)
  - Suricata (IDS/IPS signatures)
  - Zeek (DPI/telemetry)

> These daemons must be managed by containd so they appear “native”, not bolted-on.

### 1.4 Process model: built-in supervisor (required)

Because the appliance may run multiple embedded daemons, implement a **service manager** inside `containd`:

- starts/stops/reloads:
  - squid
  - haproxy/nginx
  - suricata (optional)
  - zeek (optional)
- maintains health state for UI/CLI
- collects logs into the unified logging pipeline
- handles graceful reload:
  - write config → validate → reload with SIGHUP or native reload mechanism

Do not rely on a full init system. Use `tini` in container entrypoint for signal handling and implement supervision in Go.

---

## 2. Enforcement Architecture: Linux Kernel + nftables + eBPF (optional acceleration)

### 2.1 Baseline enforcement (must)

- Use Linux kernel forwarding and conntrack.
- Enforce L3/L4 policy with **nftables** (preferred).
- Use nftables sets/maps for high performance:
  - zone-to-zone allow/deny
  - dynamic blocklists (host/flow)
  - tagging/marking for QoS and proxy steering

### 2.2 DPI/IDS interception (phased)

Support these strategies:

1) **Metadata DPI** (cheap)
- Extract TLS SNI/ALPN, DNS qnames, HTTP host/path where possible
- Do not require full stream reassembly for basic features

2) **Selective deep inspection**
- Only send flows needing inspection into expensive path:
  - ICS ports/services (502, 20000, 2404, 44818, 4840, etc.)
  - “IT protocols requiring L7 policy”
- Mechanisms:
  - NFQUEUE (initial)
  - mirror/tap via AF_PACKET for passive inspection
  - later: eBPF ring buffer events for flow summaries

3) **Inline blocking (IPS)**
- On verdict “block”, update nftables set/map
- Optionally terminate active flows by deleting conntrack entries
- TCP RST injection optional and protocol-aware

### 2.3 eBPF plan (include now)

Add optional eBPF for performance and visibility:

- XDP (ingress):
  - early drops for known-bad + fast allow/deny rules
  - counters and sampling
- TC eBPF (ingress/egress):
  - tagging/marking, rate limiting primitives (later)
- ringbuf/perf events:
  - export flow observations to userspace

The appliance must operate without eBPF; eBPF is an optimization path.

---

## 3. Config Model & Persistence (SQLite default)

### 3.1 DB choice

Default: **SQLite** stored on a persistent volume.

SQLite stores:
- system network config (interfaces/zones/routes)
- objects (hosts/subnets/groups/services)
- assets (ICS asset inventory)
- policies (firewall + DPI/IDS + proxy policies)
- identity users/groups/sessions
- service configs (syslog/NTP/DNS/proxies)
- audit log entries
- bounded retention UI indexes for events/alerts

### 3.2 Candidate config + commit/rollback (required)

Implement:
- running config
- candidate config
- diff (candidate vs running)
- commit
- commit-confirmed (with auto rollback timer)
- rollback to previous versions

Expose via UI and CLI.

### 3.3 JSON export/import (required)

Provide canonical, versioned JSON config:

- deterministic export ordering
- redaction of secrets by default
- optional include-secrets flag with explicit confirmation

APIs:
- `GET /api/v1/config/export`
- `POST /api/v1/config/import`
- support validate-only

---

## 4. Unified Logging & Telemetry

### 4.1 Local + forward

Implement unified structured event pipeline:

- events include:
  - firewall decisions (allow/deny)
  - DPI/ICS events
  - IDS alerts
  - proxy access logs (forward/reverse)
  - admin/audit events
  - system service events (NTP sync status, etc.)

Local retention must be bounded and configurable.

Forwarding options:
- syslog forwarding (UDP/TCP; optional formats)
- later: OTLP/Prometheus exporters

### 4.2 “Native UX” requirement

Even if using Suricata/Zeek/Squid/HAProxy internally, all events must be normalized into the containd event schema for UI/CLI display.

---

## 5. DPI/IDS Strategy: Native UX with Embedded Engines

### 5.1 Principle: “native from operator perspective”

You may use OSS components for detection and protocol parsing, but:

- Configuration must be via containd’s **UI/CLI/APIs**
- containd generates config files for embedded daemons
- containd owns lifecycle: start/stop/reload/health
- containd normalizes output logs/events into one event model
- UI must not look like “here is a raw Suricata config editor”

### 5.2 DPI coverage: IT + ICS

#### Minimum IT DPI (v1/v2)
- DNS: qname, response codes, NXDOMAIN, categories (later)
- TLS: SNI/ALPN/cert metadata (no MITM in v1)
- HTTP: method/host/path/status/user-agent (where visible)
- SSH: banner + version
- RDP: handshake/cookie metadata (basic)
- SMB: protocol negotiation metadata (basic)
- SNMP: versions/community visibility (basic)
- NTP: basic detection + time anomalies (optional)

#### ICS DPI (core)
- Modbus/TCP: read/write classes, function codes, unit ID, address ranges
- DNP3: function/object groups (phased)
- IEC‑104: command categories (phased)
- S7comm/CIP/OPC UA: identification first, then policy primitives

### 5.3 IDS strategy options (both supported)

**Option A: Native IDS rules engine**
- Keep your own rule model (YAML/JSON) for:
  - ICS protocol rules
  - IT protocol metadata rules
  - behavior/anomaly rules
- Output alerts into unified event pipeline.

**Option B: Embedded Suricata (recommended for signature depth)**
- Run Suricata inside the same appliance image.
- Use NFQUEUE/AF_PACKET modes as appropriate.
- Maintain Suricata rulesets internally.
- Present Suricata features in UI as:
  - “Signature Packs” (enable/disable)
  - “Policies/Profiles” (balanced/security/performance)
  - “Alerts” and “Tuning”
- Suricata config should be generated by containd from the same policy model.

### 5.4 Zeek integration (recommended for broad protocol telemetry)

If you want broad IT protocol visibility quickly:
- Run Zeek inside the appliance for passive telemetry
- Containd manages Zeek scripts and capture sources
- Normalize Zeek logs into containd event schema
- UI presents it as “Protocol Telemetry” not “Zeek logs”

### 5.5 Verdict integration (IPS)

If Suricata triggers an IPS decision:
- containd translates “block” actions into nftables set/map updates
- optional conntrack kill
- ensure decision path is deterministic and audited

---

## 6. Proxies (Forward + Reverse) – Embedded, Native UX

### 6.1 Forward proxy (Squid)

Implement forward proxy support using Squid embedded in the image.

Support in v1/v2:
- Explicit proxy mode (clients configured to use proxy)
- ACLs:
  - by source zone/object/user group
  - by destination domain/IP/category (basic)
- Auth:
  - start with local users (basic auth)
  - later integrate with OIDC/LDAP
- Logging:
  - access logs normalized into containd events
- Optional later:
  - SSL bump / MITM (high risk; defer)
  - ICAP, AV integration (defer)

Containd responsibilities:
- generate squid.conf from native config model
- validate and reload Squid
- expose status, metrics, and access logs in UI/CLI

### 6.2 Reverse proxy (HAProxy or Nginx)

Implement reverse proxy support using HAProxy (recommended) or Nginx.

Support in v1/v2:
- HTTP/HTTPS termination
- Path-based routing
- Websockets support
- Load balancing across backends
- Health checks
- Per-route ACLs and allowlists
- Certificate management:
  - start with local cert upload
  - add ACME automation later (optional)

UI must provide:
- “Sites” or “Applications” model
- frontends, routes, backends
- status and access logs
- integration with identities (who can access)

Containd responsibilities:
- generate haproxy.cfg/nginx.conf from native config
- reload safely (zero downtime if possible)
- normalize logs and expose in UI/CLI

### 6.3 Proxy + firewall policy integration

Provide policy hooks:
- firewall rule action `PROXY_FORWARD` to direct traffic to Squid (explicit use initially)
- reverse proxy “published services” automatically generate firewall allowances on mgmt interface/zone
- log correlation:
  - correlate flow IDs with proxy request IDs where feasible

---

## 7. Identity-Aware Policy (IT + ICS)

Support:
- local users/groups (v1)
- external IdP later (OIDC/LDAP/RADIUS)
- identity session mapping to IP/device/session

Identity must influence:
- firewall rules
- proxy policies
- ICS write authorization

Example:
- Engineering group can perform Modbus writes during maintenance window.
- Contractors can browse allowed domains via forward proxy only.

---

## 8. Management: API, UI, CLI (Integrated UX)

### 8.1 REST API (Gin)

Expose `/api/v1` endpoints for:
- system health/version/time
- interfaces/zones
- objects/assets/groups
- policies (firewall, DPI, IDS, proxy)
- telemetry (flows, events, alerts)
- config lifecycle (candidate/running/diff/commit/rollback)
- services:
  - syslog
  - NTP
  - DNS
  - forward proxy (Squid)
  - reverse proxy (HAProxy/Nginx)
  - Suricata
  - Zeek
- audit log

### 8.2 Web UI requirements

The UI must look like a single cohesive appliance:

Navigation:
- Dashboard
- Topology (React Flow)
- Policies
  - Firewall
  - Application/Protocol controls (IT + ICS)
  - IDS/IPS
- Proxies
  - Forward Proxy
  - Reverse Proxy
- Telemetry
  - Flows
  - Events
  - Alerts
- Services
  - DNS / NTP / Syslog
- Administration
  - Users/RBAC
  - Config export/import
  - Audit log
  - Certificates (for reverse proxy; later ACME)

Do not expose “raw config file editors” in UI. Provide structured forms and tables.

### 8.3 SSH CLI commands (add proxy + IDS controls)

CLI must support:
- `configure terminal`
- `show running-config`
- `show candidate-config`
- `diff`
- `commit`
- `commit confirmed 300`
- `rollback 1`

Add:
- `set proxy forward enable`
- `set proxy forward acl ...`
- `set proxy reverse site ...`
- `show proxy forward status`
- `show proxy reverse status`

Add:
- `set ids enable suricata`
- `set ids policy balanced`
- `show ids alerts`
- `show dpi stats`
- `show zeek status`

---

## 9. Security Defaults & Hardening

- SSH key auth default; password auth disabled by default (lab override)
- HTTPS UI default (self-signed ok) + cert upload/rotate
- RBAC roles:
  - admin, operator, auditor, lab-student
- Audit log on every config change
- Secrets encrypted at rest; redacted exports by default
- Resource caps for DPI/reassembly; predictable fail-open/closed behavior configurable per zone

---

## 10. Deployment Scenarios

### 10.1 Default: single appliance container

Example (lab):

```yaml
services:
  containd:
    image: ghcr.io/you/containd:latest
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./data:/var/lib/containd
      - ./etc:/etc/containd
    networks:
      - it_net
      - dmz_net
      - ot_control_net
      - ot_safety_net
    ports:
      - "8443:8443"   # UI/API
      - "2222:22"     # SSH
```

### 10.2 Host mode

Bind to physical NICs and run `containd all`. Expose management only on a designated mgmt interface by default.

---

## 11. Updated Delivery Phases (Practical Roadmap)

### Phase 0: scaffold + base appliance
- repo structure, Go/Next init
- `containd` subcommands
- SQLite store + migrations
- candidate/running config skeleton
- basic UI skeleton + login/RBAC skeleton

### Phase 1: kernel enforcement baseline
- nftables/conntrack baseline
- zone policies, objects, NAT basics
- commit/rollback + audit log

### Phase 2: IT protocol metadata DPI
- DNS + TLS SNI/ALPN + basic HTTP metadata pipeline
- event normalization + UI views

### Phase 3: ICS DPI v1 (Modbus) + OT templates
- Modbus parser + read/write primitives
- templates: Purdue baseline, SIS hardening
- ICS events UI

### Phase 4: proxies embedded and integrated
- embed Squid + native config UI/CLI
- embed HAProxy/Nginx + native config UI/CLI
- unify proxy logs and forward to syslog

### Phase 5: Suricata and/or Zeek embedded (native UX)
- Suricata mode with rule packs and UI-managed tuning
- Zeek mode for protocol telemetry and UI views
- verdict integration (IPS blocks -> nftables sets)

### Phase 6: eBPF acceleration + expanded IT protocols
- optional XDP/TC
- additional protocol visibility (SMB/RDP/etc.)
- performance tuning and hardening

---

## 12. Implementation Rules for the Agent

- Single Docker image by default (appliance).
- Any embedded OSS components must be:
  - installed in the image
  - supervised by containd
  - configured by containd
  - presented in UI/CLI as native features
- Baseline enforcement is kernel nftables/conntrack; eBPF is optional optimization.
- Do not build HA/captive portal/plugin ecosystem now.

This spec is the authoritative definition for what to build.
