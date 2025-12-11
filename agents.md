# containd – Agent & Project Specification

You are an AI coding agent building **containd**, an open‑source next‑generation firewall designed for **ICS/OT environments**.

Use this document as your primary reference for architecture, features, tech stack, and coding style when creating and evolving this project. It is intended for use in tools like Cursor/Cortex as an agent configuration file.

---

## 0. Purpose & Vision

**Goal:** Build a high‑performance, open‑source NGFW that:

- Runs as:
  - A **container** in OT/ICS labs (docker‑compose),
  - A **host‑level firewall** bound to physical NICs,
  - Eventually a **Kubernetes** workload (DaemonSet / CNI‑style).
- Provides **commercial‑grade NGFW capabilities**, with a special focus on **industrial control systems (ICS)** and **operational technology (OT)** networks.
- Includes **native IDS/IPS and DPI** as **first‑class components**, not external add‑on containers.
- Offers **both**:
  - A modern **web GUI** for management,
  - A **network‑style CLI over SSH**, plus REST/JSON APIs and config export/import.

This project will be used as the firewall/IDS core inside a larger OT lab platform, but must also be usable as a standalone NGFW.

---

## 1. Tech Stack & Packaging

### 1.1 Languages & Frameworks

- **Backend / Engine / Control Plane:** Go (latest stable)
- **HTTP API:** Gin (`github.com/gin-gonic/gin`)
- **Frontend UI:** Next.js (TypeScript)
  - App Router
  - TailwindCSS
  - shadcn/ui for components
  - React Flow for topology / graphs
  - A charting library (e.g. Recharts or D3‑based)

### 1.2 Processes / Binaries

Create at least two main binaries:

1. `ngfw-engine` – **data plane**
   - Packet capture & injection
   - Flow tracking & stateful firewall
   - DPI, ICS protocol parsing
   - IDS/IPS enforcement

2. `ngfw-mgmt` – **control & management plane**
   - REST APIs (Gin)
   - Serves the web UI (Next.js build)
   - Runs an embedded **SSH server** exposing the CLI
   - Manages config, policies, system services (syslog, NTP, DNS)
   - Pushes compiled policy to `ngfw-engine`

### 1.3 Packaging & Deployment

- Build **container images**:
  - `ngfw-engine` image
  - `ngfw-mgmt` image
- Support:
  - Docker / docker‑compose for lab deployments
  - Host deployments (systemd services)
  - Future: Kubernetes manifests for engine (DaemonSet) + mgmt (Deployment)

---

## 2. Repository Layout

Create a monorepo structured like:

```text
ics-ngfw/
  cmd/
    ngfw-engine/       # data-plane main
    ngfw-mgmt/         # management/control-plane main
  pkg/
    dp/                # data-plane core
      capture/         # packet I/O (AF_PACKET, raw sockets, XDP later)
      flow/            # flow/session tracking
      rules/           # compiled rule engine for enforcement
      dpi/             # DPI framework
      ics/             # ICS protocol parsers
      ids/             # IDS/IPS rule evaluation
      engine/          # coordination (load rules, run workers)
    cp/                # control-plane & config logic
      config/          # persistent config model, DB access
      policy/          # high-level policy objects (firewall, IDS)
      compile/         # compile policies -> DP rule bundles
      identity/        # user/device/session mapping
      services/        # syslog, NTP, DNS config logic
    cli/               # CLI command engine (shared by SSH/local)
    common/            # shared types, logging, errors, metrics
  api/
    http/              # Gin handlers, routers, DTOs
    internal/          # engine control RPC / internal APIs
  ui/                  # Next.js app
  deploy/
    docker/
      Dockerfile.engine
      Dockerfile.mgmt
      docker-compose.lab.yml
    k8s/               # future manifests
  docs/
    architecture.md
    dataplane.md
    ics-dpi.md
    cli.md
    services.md
    config-format.md
    deploy-host.md
```

Keep the repo clean, modular, and idiomatic for Go and TypeScript.

---

## 3. Architecture Overview

### 3.1 Planes

1. **Data Plane (DP)** – `ngfw-engine`
   - High‑speed packet capture / injection
   - Flow tracking & stateful firewall
   - DPI & ICS protocol decoding
   - IDS/IPS rule evaluation
   - Enforcement actions (allow/drop/reset/mirror/rate-limit)

2. **Control Plane (CP)** – part of `ngfw-mgmt` (`pkg/cp`)
   - Stores full configuration & policies
   - Compiles high‑level policies into a DP‑friendly rule bundle
   - Pushes rule bundles and runtime parameters to data plane
   - Manages system services (syslog, NTP, DNS, etc.)

3. **Management Plane (MP)** – `ngfw-mgmt` + `ui/` + `pkg/cli`
   - Gin REST API for UI & external automation
   - Next.js web GUI
   - SSH server exposing a network‑style CLI
   - Config backup/export/restore in JSON
   - Integration with identity providers (later)

### 3.2 Operating Modes (Data Plane)

Support these modes for the engine:

- **Router/Firewall (L3)**  
  Multiple interfaces, each mapped to a **zone** (`it`, `dmz`, `ot_control`, `ot_safety`, etc.). IP forwarding with policy enforcement on flows.

- **Transparent/Bump‑in‑wire (L2/L3)**  
  Bridged deployment between two or more interfaces; firewall operates on bridged traffic.

- **Monitor/IDS‑only**  
  Sniff traffic on one or more interfaces; generate alerts but do not block.

In **Docker lab** mode:

- Attach engine to multiple Docker networks (one per zone).
- Optionally act as the default gateway for those networks.

In **host** mode:

- Bind engine to physical NICs by name (e.g. `eth0`, `enp3s0f1`, etc.).

---

## 4. Data Plane Details

### 4.1 Packet I/O & Flow Tracking

- Implement capture using AF_PACKET or raw sockets (via `gopacket` or similar).
- Design for:
  - Multi‑queue RX (one goroutine per RX queue)
  - Batching and lock‑free buffers between capture and worker goroutines
- Flow model:
  - 5‑tuple key: `{srcIP, dstIP, srcPort, dstPort, protocol}` + direction
  - State: TCP state, timestamps, timers
  - Enriched metadata:
    - `srcZone`, `dstZone`
    - L7 protocol (e.g. `http`, `dns`, `modbus`)
    - ICS metadata (function codes, addresses, etc.)
    - Identity attributes (userId, groupIds, deviceId) if known

### 4.2 Rule Engine (Enforcement)

Implement a compiled, read‑only rule structure used in the enforcement fast path:

- Conditions (match fields):
  - Zones (source/dest)
  - IP/networks, address groups
  - L4 protocol, ports
  - L7 protocol / app classification
  - ICS protocol fields (e.g. `modbus.function_code`, `modbus.address_range`)
  - Identity (user, group, role, device type)
  - Time schedules

- Actions:
  - `ALLOW`
  - `DENY` (drop/reset)
  - `ALERT`
  - `MIRROR` (to interface/collector)
  - `RATE_LIMIT`
  - `TAG` (apply labels for subsequent rules)

Treat enforcement rule sets as **immutable snapshots**. Control plane builds and pushes new versions, and engine switches pointer atomically.

---

## 5. DPI & IDS/IPS (Native, Built‑In)

### 5.1 DPI Framework

In `pkg/dp/dpi` (generic) and `pkg/dp/ics` (ICS‑specific):

- Define a generic decoder interface:

```go
type Decoder interface {
    Supports(flow *Flow) bool
    OnPacket(flow *Flow, pkt *ParsedPacket) ([]Event, error)
    OnFlowEnd(flow *Flow) ([]Event, error)
}

type Event struct {
    FlowID     string
    Proto      string            // e.g. "http", "modbus", "dnp3"
    Kind       string            // e.g. "request", "response", "command"
    Attributes map[string]any    // protocol-specific fields
    Timestamp  time.Time
}
```

- Provide decoders for common protocols:
  - HTTP (methods, paths, headers)
  - TLS metadata (SNI, ALPN)
  - DNS queries/responses

- Provide **ICS decoders** (phased):
  - Modbus/TCP:
    - Function code, unit ID, address, quantity, etc.
  - DNP3
  - IEC‑60870‑5‑104
  - S7comm / Profinet
  - CIP/EtherNet/IP
  - OPC UA (basic node/service info)

DPI decoders emit `Event`s that go to:

- Rule engine (for ICS‑aware policy decisions)
- IDS engine
- Telemetry / logs

### 5.2 IDS/IPS Engine

Implement IDS/IPS **inside this project** (no external Suricata/Zeek required):

- Signature‑based rules:
  - Simple rule representation (YAML/JSON) matching on:
    - L3/L4 fields
    - DPI attributes (HTTP path, DNS name, ICS function codes, etc.)
    - Flow/time properties (e.g. frequency, sequence)
  - Each rule can trigger:
    - `alert` (log)
    - `drop/reset` (IPS)
    - `tag` (for further processing)

- Behavioral/anomaly rules (phased in):
  - E.g. “unexpected Modbus writes to SIS PLC registers”
  - E.g. “burst of start/stop commands to critical motors”

IDS alerts should:

- Be stored locally (DB or structured log)
- Be available via REST API and web UI
- Be forwardable via syslog

---

## 6. Control Plane & Config

### 6.1 Persistent Config Model

Use a DB (start with SQLite or Postgres via a clean abstraction) to store:

- **System & Network**:
  - Interfaces, zones, IP config
- **Objects**:
  - Hosts, subnets, address groups
  - ICS assets:
    - Type (PLC, HMI, SIS, Historian, RTU, etc.)
    - Zone, IPs, roles, criticality
  - Services (ports/protocols)
- **Identity**:
  - Users, groups, roles
  - Session mappings (user ↔ device ↔ IP)
- **Policies**:
  - Firewall policies (ordered rule sets)
  - IDS rule sets
- **System Services**:
  - Syslog & forwarding targets
  - NTP servers
  - DNS settings (local resolver, forwarders, zones)
- **Admin & Auth**:
  - Admin users & roles
  - Auth methods & settings

### 6.2 Config Export/Import (JSON)

Support full JSON‑based configuration backup and restore:

- Canonical JSON format containing:
  - System/network settings
  - Objects & identity
  - Policies
  - Services (syslog, NTP, DNS)
  - Admin & auth config
  - Schema version

- Provide APIs:
  - `GET /api/v1/config/export` → returns full JSON config
  - `POST /api/v1/config/import` → accepts JSON to apply
    - Support dry‑run & validation
    - Support full overwrite initially; partial merges later

All config operations must be accessible via:

- REST API
- Web UI
- CLI (via commands that call the control plane)

---

## 7. SSH Server & CLI

### 7.1 SSH Server

`ngfw-mgmt` runs an embedded **SSH server**:

- Configurable port (e.g. 22 in host mode, 2222 in lab mode)
- Auth:
  - Local username/password
  - SSH keys (authorized_keys)
  - (Optional later) external auth (RADIUS/LDAP/OIDC)

Use a mature Go SSH library; do not implement SSH protocol from scratch.

### 7.2 CLI Design

Implement a network‑appliance style CLI in `pkg/cli`:

- Shared by SSH sessions and optional local console.
- Supports commands like:

  - `show version`
  - `show interfaces`
  - `show zones`
  - `show running-config`
  - `show config json`
  - `configure terminal`
  - `set interface eth0 zone dmz`
  - `set firewall rule <id> ...`
  - `delete firewall rule <id>`
  - `set syslog server <ip> [port] [proto]`
  - `set ntp server <ip-or-hostname>`
  - `set dns forwarder <ip>`
  - `backup config <name>`
  - `restore config <name>`

- Features:
  - Hierarchical commands (config context)
  - `show` and `set` patterns
  - Inline help (`?`) and basic completion (if feasible)

CLI must:

- Operate via the **same control‑plane APIs** as the web UI.
- Have **no separate config file format** – everything maps to the canonical config model.
- Support `show running-config` and `show config json`.

---

## 8. System Services: Syslog, NTP, DNS

### 8.1 Syslog

Implement:

- Local structured logging (internal logs + events).
- Syslog forwarding:
  - One or more remote syslog targets.
  - Configurable protocol (UDP/TCP) and port.
  - Configurable format (RFC3164/RFC5424 if needed).

Management:

- Web UI:
  - Syslog settings page (targets, test send).
- CLI:
  - `set syslog server <ip> [port] [proto]`
  - `show syslog`

All IDS/IPS and major firewall events should be optionally forwardable to syslog targets.

### 8.2 NTP

Implement NTP client configuration:

- The appliance synchronizes its time from configured NTP servers.
- Management:
  - Web UI: “Time & NTP” page (servers, sync status).
  - CLI: `set ntp server <ip-or-hostname>`, `show ntp status`.

Optional later:

- Act as NTP server for downstream hosts in lab mode.

### 8.3 DNS

Implement local DNS service:

- Caching resolver with configurable upstream forwarders.
- Optional local zones (e.g. `.lab` for ICS assets).

Management:

- Web UI:
  - DNS settings page (forwarders, local records).
- CLI:
  - `set dns forwarder <ip>`
  - `set dns search-domain <domain>`
  - `set dns record <name> <type> <value>` (if local zones supported)

DNS should be usable in both:

- Lab mode (naming PLCs/HMIs).
- Real deployments.

---

## 9. Identity & Policy

Design an **identity layer** in `pkg/cp/identity`:

- Support:
  - Local users & groups
  - External identity providers later (OIDC, LDAP, etc.)
- Map identities to network sessions:
  - From:
    - VPN server (username ↔ IP)
    - Jump host/EWS agents
    - Other out‑of‑band mechanisms in the lab
- Store identity sessions and expose them to the data plane as part of flow context.

Extend policy model to match on identity:

- Example rules:
  - “Engineering group allowed Modbus writes to plant PLCs; contractors read‑only.”
  - “Only OT admins can reach SIS PLCs over ICS protocols.”

---

## 10. Web UI (Next.js)

The web UI should expose **all** configuration and monitoring features also available via CLI.

Key sections:

1. **Dashboard**
   - System health (CPU, RAM, throughput)
   - Top alerts (IDS)
   - ICS highlights (top PLCs, top ICS function codes, etc.)

2. **Topology / Network View**
   - React Flow-based view of:
     - Zones, firewall, interfaces, ICS assets
   - Click nodes to see:
     - Properties, policies, and recent alerts/flows

3. **Firewall Policies**
   - Table & editor for rules
   - ICS‑aware rule editor:
     - Protocol = Modbus, function codes, register ranges, etc.

4. **IDS & Alerts**
   - List alerts with filters (time, severity, asset, user)
   - Drilldown into ICS events

5. **Objects & Identity**
   - Hosts, networks, ICS assets
   - Users, groups, and identity mappings

6. **System Services**
   - Syslog configuration
   - NTP configuration
   - DNS configuration

7. **Config & Administration**
   - Export/Import config (JSON)
   - Admin users and authentication settings

---

## 11. Deployment Scenarios

### 11.1 Docker Lab (docker-compose.lab.yml)

- `ngfw-engine`:
  - Attached to multiple lab networks (IT, DMZ, OT control, OT safety)
  - Optionally default gateway for those networks
- `ngfw-mgmt`:
  - On management network (IT/console)
  - Exposes:
    - HTTPS port for API/UI
    - SSH port for CLI

### 11.2 Host (Bare Metal)

- `ngfw-engine`:
  - Bound to physical NICs
  - Configurable via CLI and web UI
- `ngfw-mgmt`:
  - Runs as systemd service
  - Provides local management

### 11.3 Kubernetes (Future)

- Engine:
  - Packaged as a DaemonSet (or CNI plugin) for cluster nodes.
- Management:
  - Deployment + Service + Ingress for web UI/API/SSH.

---

## 12. Implementation Phases

Implement incrementally. Each phase should produce working code with basic tests.

1. **Phase 0 – Scaffolding**
   - Create repo structure.
   - Initialize Go modules and Next.js app.
   - Implement:
     - `ngfw-engine` skeleton with `/health`.
     - `ngfw-mgmt` skeleton with `/api/v1/health` and static UI placeholder.
   - Add `docker-compose.lab.yml` that runs both containers.

2. **Phase 1 – L3/L4 Stateful Firewall (Single Interface)**
   - Implement packet capture, basic flow tracking, L3/L4 rules.
   - Implement config model for interfaces, zones, and rules.
   - Expose basic policy APIs and UI/CLI to manage them.

3. **Phase 2 – Multi‑Interface, Multi‑Zone Firewall**
   - Attach engine to multiple interfaces/networks.
   - Implement zone‑based policy enforcement.
   - Build topology view in the UI.

4. **Phase 3 – DPI & ICS (Modbus First) + IDS**
   - Implement TCP reassembly.
   - Implement Modbus/TCP decoder & ICS DPI events.
   - Implement IDS rule engine for Modbus events.
   - Add ICS rules editor & alerts UI.

5. **Phase 4 – SSH/CLI, Config Export/Import, Syslog/NTP/DNS**
   - Embed SSH server; implement CLI engine and mapping to config.
   - Implement JSON config export/import.
   - Implement syslog forwarding, NTP, DNS settings (API, CLI, UI).

6. **Phase 5 – Additional ICS Protocols, Identity, Hardening**
   - Implement DNP3, IEC‑104, S7, etc.
   - Integrate identity mapping & identity‑aware policies.
   - Add authentication/authorization for UI/CLI.
   - Optimize performance (multi‑queue, batching, optional XDP).

---

## 13. Coding Style & Constraints

- Prefer **clear, idiomatic Go and TypeScript** over cleverness.
- Keep modules small and focused; avoid giant “god” packages.
- Data plane:
  - Avoid locks in the fast path if possible.
  - Favor immutable rule sets and atomic swaps.
- Control plane:
  - Central source of truth for config.
  - Validation and consistent defaults.
- Management:
  - All functionality exposed via:
    - REST API
    - Web UI
    - CLI over SSH
- No external DPI/IDS containers for core features:
  - IDS and DPI **must live inside this project** as native components.

Use this document as the authoritative guide when scaffolding the project, creating files, and making architectural decisions.
