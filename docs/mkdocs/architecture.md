# containd Architecture

containd separates policy management from packet processing. The default
container runs both in `containd all`; split deployments run `containd mgmt`
and `containd engine` separately. See [Docker Compose](docker-compose.md).

## Planes

- **Management plane**: the UI, REST API, and appliance CLI provide authentication,
  configuration, audit records, diagnostics, and telemetry queries.
- **Control plane**: SQLite stores candidate and running configuration. Validation
  and compilation produce immutable rule snapshots and nftables rulesets. Service
  managers render configuration and supervise embedded daemons.
- **Data plane**: the engine applies Linux network configuration and nftables
  policy, captures traffic, reassembles TCP streams, decodes protocols, evaluates
  DPI policy, and records events. Native IDS rules produce alerts.

## Control and packet flow

1. An administrator stages candidate changes, reviews them, and commits them.
   The management service pushes the running snapshot to the engine.
2. nftables and conntrack enforce the zone firewall and NAT. NFQUEUE can hold
   selected packets for userspace inspection; AF_PACKET capture only observes
   copies. See [Enforcement](dataplane-enforcement.md).
3. Decoded events feed telemetry, IDS, anomaly and signature checks, and protocol
   statistics. Generic ICS inventory excludes IEC 104. Explicit live watches and
   PCAP imports feed the shared evidence learner; IEC 104 command suggestions
   require review.
   See [Data Plane](dataplane.md) and [ICS DPI](ics-dpi.md).
4. Operators query bounded event history and persistent audit records through
   the management API. Service syslog forwarding and application-log syslog
   sinks send records to external collectors; see
   [Logging and Evidence](logging-evidence.md).

The engine API is a **privileged control interface**: numeric loopback uses
credential-free HTTP; every non-loopback listener requires secret-derived mutual
TLS. Keep its network private; see the
[trust boundary](threat-model.md#management-plane-to-dataplane).

## Services and packaging

The management image installs Wolfi `nginx-mainline`, `chrony`, `unbound`,
`clamav`, `openvpn`, and `nftables`, and copies Envoy into the image. The engine
image installs Wolfi `nftables`, `clamav` and CA roots, because the engine owns
the antivirus backend in every deployment. WireGuard uses Linux kernel interfaces.
Enabling a service and supervising its daemon is separate from having its binary
in the image. See [Services](services.md) and [Third-Party Licenses](SPDX.md).

## Source boundaries

- `api/http`, `pkg/app/mgmt`, `pkg/cli`: management interfaces and lifecycle.
- `pkg/cp/config`, `pkg/cp/compile`, `pkg/cp/templates`: configuration, compilation,
  and policy templates.
- `pkg/cp/services`: embedded service managers.
- `pkg/dp/enforce`, `pkg/dp/netcfg`: nftables and Linux network programming.
- `pkg/dp/engine`, `pkg/dp/capture`, `pkg/dp/dpi`: runtime packet pipeline,
  including TCP reassembly.
- `pkg/dp/ics`, `pkg/dp/itdpi`: four ICS and eight IT protocol decoders, plus
  utility detection helpers.
- `pkg/dp/ids`, `pkg/dp/inventory`, `pkg/dp/learn`, `pkg/dp/anomaly`,
  `pkg/dp/signatures`, `pkg/dp/stats`, `pkg/dp/pcap`: event consumers and offline
  analysis.

See [Code Boundaries](code-boundaries.md) for contributor guidance.

## Network setup and topology in the UI

Zones, Interfaces, Routing and NAT share a **Zones → Logical interfaces →
Connectivity → Review** navigation strip, with a separate NAT link. Navigation
never adopts devices or stages settings; Review opens the Config diff directly.
In Interfaces, logical-interface and live-device counts occupy a separate line
below navigation. The logical interface list comes before Create interface.
Each row keeps its device, zone, link and addresses together. Mode, type and
live/access/gateway attention indicators accompany Device, not the action buttons.
**Inspect** reveals Type, Mode, Network and Access, including
MAC, MTU, detected versus configured addresses and gateway. Edit opens inspection;
Save still stages the same candidate settings. Saved bridge/VLAN, gateway or
customized access settings open inspection by default. Detected network devices
also show their associated logical interface and zone.
Read-only inspection and live-device Retry remain available after a failed
configuration refresh; configuration editing stays unavailable until a successful
configuration read.

**Auto-assign** stages bindings; **Reconcile live** is a separate, immediate action
that replaces live static addresses from running settings. Management reservation,
safeguard and boot-fault messages remain above the interface workspace, including
when inspection is collapsed. Review and commit staged settings in Configuration.

Topology opens on **Logical**. **Live** identifies running network, traffic and
conduit observations; **Saved target** identifies candidate zone targets, not live
protection. Security leads with target gaps and offers direct conduit inspection.
Its automated requirement checks are not a standards assessment. **Physical**
keeps deployment security attention visible independently of its inspector; select
Host, Runtime, Container or Process to inspect the corresponding OS, resources,
paths, environment and runtime details. Layer and conduit selection support the
keyboard; graph navigation, zoom and detail-panel controls remain available.
The Host inspector labels CPU count and usage, total/used/available memory and
storage separately. Unavailable layer data is marked **Unknown**, without healthy
styling or fabricated resource measurements. Host networking attention explains
the shared host interfaces and loopback and links to the
[threat model](threat-model.md#management-plane-to-dataplane).
