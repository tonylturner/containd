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
- `pkg/dp/engine`, `pkg/dp/capture`, `pkg/dp/reassembly`: runtime packet pipeline.
- `pkg/dp/ics`, `pkg/dp/itdpi`: eight ICS and eight IT protocol decoders, plus
  utility detection helpers.
- `pkg/dp/ids`, `pkg/dp/inventory`, `pkg/dp/learn`, `pkg/dp/anomaly`,
  `pkg/dp/signatures`, `pkg/dp/stats`, `pkg/dp/pcap`: event consumers and offline
  analysis.

See [Code Boundaries](code-boundaries.md) for contributor guidance.
