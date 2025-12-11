# ICS‑NGFW – Single‑Image Appliance Spec (Agent Instructions)

You are an AI coding agent building **containd**, an open‑source next‑generation firewall designed for **ICS/OT environments**, implemented as a **single Docker image / appliance** by default.

Use this document as your primary reference for architecture, features, tech stack, and coding style when creating and evolving this project. It is intended to be dropped into tools like Cursor/Cortex as an agent configuration / project spec.

---

## 0. Purpose & Vision

**Goal:** Build a high‑performance, open‑source NGFW that:

- Runs primarily as a **single-container appliance**:
  - Drop‑in firewall node for OT/ICS labs (docker‑compose).
  - Can bind to **real NICs** on bare metal.
  - Can be used as a **Kubernetes** workload later.
- Provides **commercial‑grade NGFW capabilities**, with a special focus on **industrial control systems (ICS)** / **operational technology (OT)** networks.
- Includes **native IDS/IPS and DPI** as **first‑class components**, not external add‑on containers.
- Offers:
  - A modern **web GUI** for management,
  - A **network‑style CLI over SSH**,
  - REST/JSON APIs,
  - JSON config export/import for backup and migration.

This project will be used as the firewall/IDS core inside a larger OT lab platform, but must also be usable as a standalone NGFW appliance.

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

### 1.2 Single Binary, Multiple Roles

Build **one Go binary** named `ics-ngfw` with subcommands:

- `ics-ngfw engine` – runs **data plane** only.
- `ics-ngfw mgmt` – runs **control plane + APIs + web UI + SSH/CLI** only.
- `ics-ngfw all` – runs **both engine and management** in a single process/container.
  - This is the **default mode** for appliance / lab deployments.

Internally these can share packages, but externally there is **one binary** and **one image**.

### 1.3 Single Docker Image

Produce a **single Docker image**, e.g. `ghcr.io/you/ics-ngfw:latest`, that contains:

- The `ics-ngfw` binary.
- The built Next.js UI assets for the mgmt HTTP server.

The container entrypoint should default to `ics-ngfw all`, so the typical runtime is **one container that does everything**.

The same image can also be run with explicit subcommands if needed (e.g. separate engine/mgmt containers in advanced deployments), but other projects only ever reference **one image name**.

---

## 2. Repository Layout

Create a monorepo structured like:

```text
ics-ngfw/
  cmd/
    ics-ngfw/          # main() with subcommands: engine, mgmt, all
  pkg/
    dp/                # data-plane core
      capture/         # packet I/O (AF_PACKET, raw sockets, XDP later)
      flow/            # flow/session tracking
      rules/           # compiled rule engine for enforcement
      dpi/             # DPI framework
      ics/             # ICS protocol parsers (Modbus, DNP3, etc.)
      ids/             # IDS/IPS rule evaluation
      engine/          # coordination (load rules, run workers)
    cp/                # control-plane & config logic (mgmt plane)
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
  # Deployment assets at repo root (single-container workflow)
  Dockerfile.mgmt      # builds single ics-ngfw image (appliance)
  Dockerfile.engine    # optional engine-only image
  docker-compose.yml   # single-container compose
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

Even though runtime uses **one container**, keep a logical split into three planes:

### 3.1 Planes

1. **Data Plane (DP)** – inside `ics-ngfw engine`
   - High‑speed packet capture / injection.
   - Flow tracking & stateful firewall.
   - DPI & ICS protocol decoding.
   - IDS/IPS rule evaluation.
   - Enforcement actions (allow/drop/reset/mirror/rate-limit).

2. **Control Plane (CP)** – inside `ics-ngfw mgmt`
   - Stores full configuration & policies.
   - Compiles high‑level policies into DP‑friendly rule bundles.
   - Pushes rule bundles and runtime parameters to data plane (via internal APIs).
   - Manages system services (syslog, NTP, DNS, etc.).
   - Handles config export/import.

3. **Management Plane (MP)** – inside `ics-ngfw mgmt`
   - Gin REST API for UI & external automation.
   - Next.js web GUI (served as static assets).
   - SSH server exposing network‑style CLI.
   - Auth, RBAC, and admin functions.

In `ics-ngfw all` mode, both DP and CP/MP run in the same process/container and communicate via in‑process interfaces or localhost HTTP/internal API.

### 3.2 Operating Modes (Data Plane)

Support these modes via configuration:

- **Router/Firewall (L3)**  
  Multiple interfaces, each mapped to a **zone** (`it`, `dmz`, `ot_control`, `ot_safety`, etc.). IP forwarding with policy enforcement on flows.

- **Transparent/Bump‑in‑Wire (L2/L3)**  
  Bridged deployment between two or more interfaces; firewall operates on bridged traffic.

- **Monitor/IDS‑Only**  
  Sniff traffic on one or more interfaces; generate alerts but do not block.

In **Docker lab mode**:

- Attach container to multiple Docker networks (one per zone).
- Treat each attached network as an NGFW interface/zone.
- Optionally, act as default gateway per network.

In **host mode**:

- Bind to physical NICs by name (e.g. `eth0`, `enp3s0f1`, etc.).

---

## 4. Data Plane Details

### 4.1 Packet I/O & Flow Tracking

- Use AF_PACKET or raw sockets (via `gopacket` or similar) for initial capture.
- Design for:
  - Multi‑queue RX (one goroutine per RX queue).
  - Batching and lock‑free queues between capture and worker goroutines.

Flow model:

- 5‑tuple key: `{srcIP, dstIP, srcPort, dstPort, protocol}` + direction.
- State: TCP state (SYN, ESTABLISHED, FIN, etc.), timestamps, timers.
- Enriched metadata:
  - `srcZone`, `dstZone`.
  - L7 protocol (e.g. `http`, `dns`, `modbus`).
  - ICS metadata (function codes, addresses, etc.).
  - Identity attributes (userId, groupIds, deviceId) if known.

### 4.2 Rule Engine (Enforcement)

Implement a compiled, read‑only rule structure used in the fast path:

- Conditions (match fields):
  - Zones (source/dest).
  - IP/networks, address groups.
  - L4 protocol, ports.
  - L7 protocol / app classification.
  - ICS protocol fields (e.g. `modbus.function_code`, `modbus.address_range`).
  - Identity (user, group, role, device type).
  - Time schedules.

- Actions:
  - `ALLOW`.
  - `DENY` (drop/reset).
  - `ALERT`.
  - `MIRROR` (to interface/collector).
  - `RATE_LIMIT`.
  - `TAG` (apply labels for subsequent rules).

Treat enforcement rule sets as **immutable snapshots**. CP builds and pushes new versions; DP swaps them atomically (no locking in the fast path).

---

## 5. DPI & IDS/IPS (Native, Built‑In)

### 5.1 DPI Framework

In `pkg/dp/dpi` (generic) and `pkg/dp/ics` (ICS‑specific):

Define a decoder interface:

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

Implement decoders for:

- Generic protocols:
  - HTTP (methods, paths, headers).
  - TLS metadata (SNI, ALPN).
  - DNS queries/responses.

- ICS protocols (phased):
  - Modbus/TCP.
  - DNP3.
  - IEC‑60870‑5‑104.
  - S7comm / Profinet.
  - CIP/EtherNet/IP.
  - OPC UA (basic node/service information).

DPI decoders emit `Event`s to:

- Rule engine (for ICS‑aware policy decisions).
- IDS engine.
- Telemetry/logging.

### 5.2 IDS/IPS Engine

Implement IDS/IPS **within the same project** (no external Suricata/Zeek container for core functionality):

- Signature‑based rules (YAML/JSON):
  - Match on L3/L4 attributes, DPI attributes and ICS‑specific fields.
  - e.g. “Modbus write_multiple_registers to specific registers on SIS PLC”.
- Behavioral/anomaly rules (phased):
  - Unusual ICS behavior, frequency‑based rules, time‑of‑day anomalies.

Each IDS rule may generate:

- `alert` (log only).
- `drop/reset` (IPS).
- `tag` for further rule chaining.

Alerts are:

- Stored locally.
- Exposed via REST.
- Forwardable via syslog.

---

## 6. Control Plane & Config

### 6.1 Persistent Config Model

Use a DB (SQLite or Postgres) to store:

- System & network:
  - Interfaces, zones, IP config.
- Objects:
  - Hosts, subnets, address groups.
  - ICS assets (PLC, HMI, SIS, Historian, RTU, etc.), with zone, IPs, roles, criticality.
- Identity:
  - Users, groups, roles.
  - Session mappings (user ↔ device ↔ IP).
- Policies:
  - Firewall policies (ordered rule sets).
  - IDS rule sets.
- System services:
  - Syslog & forwarding targets.
  - NTP servers.
  - DNS settings (local resolver, forwarders, zones).
- Admin & auth:
  - Admin users & roles.
  - Auth methods & settings.

### 6.2 Config Export/Import (JSON)

Define a canonical JSON config format:

- Contains system/network settings, objects, identity, policies, services, admin/auth.
- Include schema/version metadata.

Expose:

- `GET /api/v1/config/export` → full JSON.
- `POST /api/v1/config/import` → apply JSON.
  - Support dry‑run/validation.
  - Start with full overwrite; partial merge can come later.

CLI should provide wrapper commands to export/import the same JSON.

---

## 7. SSH Server & CLI

### 7.1 SSH Server

`ics-ngfw mgmt` (and thus `ics-ngfw all`) runs an embedded SSH server:

- Configurable port (e.g. 22 or 2222).
- Auth:
  - Local username/password.
  - SSH keys (authorized_keys).
  - Later, optional external auth (RADIUS/LDAP/OIDC).

Use a stable Go SSH library.

### 7.2 CLI Design

Implement a network‑appliance style CLI in `pkg/cli`, shared across:

- SSH sessions.
- Optional local console.

Command style:

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

CLI behavior:

- All commands operate through the control‑plane configuration layer (no direct DB hacks).
- `show running-config` renders current config in CLI syntax.
- `show config json` prints JSON config.
- `backup` / `restore` tie into JSON export/import.

---

## 8. System Services: Syslog, NTP, DNS

### 8.1 Syslog

Implement:

- Local structured logging of events.
- Syslog forwarding:
  - One or more remote syslog targets.
  - Configurable protocol (UDP/TCP) and port.
  - Optionally configurable format.

Manage via:

- Web UI: Syslog settings page (targets, test message).
- CLI: `set syslog server`, `show syslog`.

### 8.2 NTP

Implement NTP client:

- Appliance syncs time to configured NTP servers.

Manage via:

- Web UI: Time & NTP settings.
- CLI: `set ntp server`, `show ntp status`.

Optional later: offer NTP server for downstream lab hosts.

### 8.3 DNS

Implement local DNS service:

- Caching resolver with configurable upstream forwarders.
- Optional local zones/records.

Manage via:

- Web UI: DNS settings, forwarders, local records.
- CLI: `set dns forwarder`, `set dns search-domain`, `set dns record` (if local zones supported).

---

## 9. Identity & Policy

Design an identity layer in `pkg/cp/identity`:

- Support:
  - Local users & groups.
  - Future external IdP (OIDC, LDAP, etc.).
- Store mappings from identities to sessions (user ↔ device ↔ IP).

Policy model should allow matching on identity:

- Example rules:
  - “Engineering group can perform Modbus writes on plant PLC group.”
  - “Contractors group read‑only access to specific HMIs.”
  - “Only OT admins can reach SIS PLCs.”

Identity info should be available to the data plane via rule bundles or runtime updates.

---

## 10. Web UI (Next.js)

The web UI (in `ui/`) must surface all major configuration and monitoring features that CLI has.

Sections:

1. **Dashboard**
   - System health (CPU, RAM, throughput).
   - Top alerts (IDS).
   - ICS summary (top PLCs, function codes, etc.).

2. **Topology / Network View**
   - React Flow-based visualization:
     - Zones, firewall appliance, interfaces, ICS assets.
   - Clicking a node shows:
     - Properties.
     - Policies.
     - Recent alerts/flows involving that node.

3. **Firewall Policies**
   - Table + editor UI.
   - ICS-aware inputs (protocol, function codes, register ranges, etc.).

4. **IDS & Alerts**
   - Alert list with filters (time, severity, asset, user).
   - Drilldown into ICS events.

5. **Objects & Identity**
   - Hosts, networks, ICS assets.
   - Users, groups, identity mappings.

6. **System Services**
   - Syslog configuration.
   - NTP configuration.
   - DNS configuration.

7. **Config & Administration**
   - Export/import config (JSON).
   - Admin users and auth settings.

---

## 11. Deployment Scenarios

### 11.1 Default: Single Appliance Container (Recommended)

In lab and many real deployments, run as a **single container appliance**:

```yaml
services:
  ics_ngfw:
    image: ghcr.io/you/ics-ngfw:latest
    command: ["ics-ngfw", "all"]   # or omit; 'all' is default
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - it_net
      - dmz_net
      - ot_control_net
      - ot_safety_net
    ports:
      - "8443:8443"    # HTTPS UI/API
      - "2222:22"      # SSH CLI
```

- Container attaches to multiple networks (zones).
- Internally runs both data plane and management.

### 11.2 Optional: Split Roles Using the Same Image

For advanced setups, run two containers from the **same image**:

- One with `ics-ngfw engine`.
- One with `ics-ngfw mgmt`.

This allows separation of concerns without publishing multiple images.

### 11.3 Bare Metal Host

- Install `ics-ngfw` binary on a Linux host.
- Run:
  - `ics-ngfw engine` bound to physical NICs.
  - `ics-ngfw mgmt` for config, UI, and CLI.
- Manage via web UI and SSH CLI.

### 11.4 Kubernetes (Future)

- DaemonSet or privileged pod for data plane.
- Deployment + Service + Ingress for mgmt plane.
- Still using **one image** and different commands.

---

## 12. Implementation Phases

Implement incrementally. Each phase should result in working code + basic tests.

1. **Phase 0 – Scaffolding**
   - Create repo structure.
   - Initialize Go modules and Next.js app.
   - Implement `cmd/ics-ngfw` with subcommands:
     - `ics-ngfw engine` (stub).
     - `ics-ngfw mgmt` (stub).
     - `ics-ngfw all` (runs both stubs).
   - Simple health endpoints for engine and mgmt.
   - Add `Dockerfile` + `docker-compose.lab.yml` to run single appliance container.

2. **Phase 1 – L3/L4 Stateful Firewall (Single Interface)**
   - Implement packet capture, flow tracking, basic L3/L4 rules.
   - Implement minimal config model (interfaces, zones, rules).
   - Expose basic policy APIs and minimal UI + CLI commands.

3. **Phase 2 – Multi‑Interface, Multi‑Zone Firewall**
   - Support multiple interfaces/networks and zone‑based policy.
   - Improved rule model and enforcement.
   - Topology view in UI.

4. **Phase 3 – DPI & ICS (Modbus First) + IDS**
   - TCP reassembly and Modbus/TCP decoder.
   - ICS DPI events and ICS rule matching.
   - IDS engine for Modbus.
   - ICS rules editor + alerts UI.

5. **Phase 4 – SSH/CLI, Config Export/Import, Syslog/NTP/DNS**
   - SSH server and network‑style CLI.
   - JSON config export/import.
   - Syslog forwarding, NTP, DNS settings via API/UI/CLI.

6. **Phase 5 – Additional ICS Protocols, Identity, Hardening**
   - Add DNP3, IEC‑104, S7, etc.
   - Identity mapping and identity‑aware policies.
   - Authn/Authz for UI/CLI.
   - Performance tuning (multi‑queue, batching, optional XDP).

---

## 13. Coding Style & Constraints

- Prefer **clear, idiomatic Go and TypeScript** over cleverness.
- Keep packages small and focused. Avoid giant “god” packages.
- Data plane:
  - Minimize locks in hot paths.
  - Use immutable rule sets with atomic swaps.
- Control plane:
  - Single source of truth for config.
  - Validation and consistent defaults.
- Management:
  - All functionality must be accessible via:
    - REST API.
    - Web UI.
    - CLI over SSH.
- Core IDS and DPI are **native** to this project:
  - Do not rely on external IDS/IPS containers for primary features.

Use this document as the authoritative guide when scaffolding the project, creating files, and making architectural decisions. In other projects, this NGFW should appear as a **single appliance container** by default, referenced by a single image name.
