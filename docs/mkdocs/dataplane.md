# Data Plane Overview

The Linux engine applies immutable policy snapshots and processes traffic on the
interfaces and paths assigned to the appliance. Traffic taking another route is
outside its control.

## Packet pipeline

1. nftables and conntrack handle zone firewalling, NAT masquerade, and DNAT port
   forwarding. The engine also applies interface addresses, routes, and basic
   policy routing through netlink.
2. NFQUEUE steers selected packets to inline DPI. AF_PACKET capture observes
   copies instead; it cannot hold or retract the observed packet.
3. Flow tracking and TCP reassembly supply connection context to protocol
   decoders. Generic DPI uses a per-flow verdict cache. IEC 104 uses a separate
   stateful inspection envelope and session gate rather than relying on that
   generic cache.
4. Firewall rules evaluate to `ALLOW` or `DENY`. Enforced DPI denials drop the
   packet and best-effort reset only that TCP session, without installing a host
   or service block. Generic TCP denial tombstones last 10 seconds and are
   capped at 16,384; later payload still fails closed as a mid-stream pickup.
   UDP denials drop only the datagram. IEC 104 retains its stateful abort/reset
   path. A native IDS alert alone is not a packet drop.
5. Decoded events feed bounded telemetry, anomaly and signature checks, and
   protocol statistics. Asset discovery and automatic rule learning consume
   non-IEC-104 ICS events only.

## Protocol coverage

`DefaultDecoders()` supplies **12 protocol decoders: 4 ICS + 8 IT**, shared with
PCAP analysis:

- ICS: Modbus/TCP, DNP3, IEC 60870-5-104, and CIP/EtherNet/IP.
- IT: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP, and RDP.
- ICS marker and port detector are additional utility registrations, not protocols.

Protocol toggles select decoders; they do not create matching firewall rules.
See [ICS DPI](ics-dpi.md) for predicates, learn-mode limits, and IEC 104 behavior.

## Policy and runtime state

Rules match zones, CIDRs, transport/port ranges, identity bindings, schedules
and ICS predicates; see
[Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).
A packet is allowed when any matching ALLOW rule exists; otherwise a matching
DENY or RESET applies; otherwise the default action applies. Rule order does
not decide. IEC 104 object evaluation instead defaults to deny inside its
inspection envelope. Snapshot swaps are atomic.

The [ruleset preview](policy-model.md#templates-and-preview) uses the same
compiler construction as apply on an isolated candidate. Its runtime sample
describes the IEC 104 queue-ownership decision, not a promise about later queue
ownership or the last installed ruleset. Preview never binds queues or changes
live enforcement.
With enforcement disabled in the candidate, preview skips nftables compilation
and reports that nothing would be applied.

For enablement, privileges, capture modes, and failure limits, see
[Enforcement](dataplane-enforcement.md). For staging and commit semantics, see
[Policy Model](policy-model.md).

## Routing ownership and upgrades

Every routing apply, including commit, rollback, restart replay, periodic
reconciliation, and explicit reconcile, converges the IPv4 routes and policy
rules marked with protocol **98**. Reserve that protocol for containd in its
network namespace. Priorities are ordering, not ownership: rules at any accepted
priority are removed when absent from running config, while foreign rules even
at priorities 10000–19999 remain. Empty routing intent clears all marked entries.
Unchanged entries are retained without deleting and re-adding them.

An existing foreign route with the same table, destination, TOS, metric and
next hop satisfies intent without being adopted; an explicitly configured
output interface must also match. Identical foreign policy rules likewise
satisfy intent without being adopted or duplicated. Removing such intent leaves
those entries unchanged. This includes a Docker-created default route that
already matches the outbound quickstart configuration.

If a simple foreign unicast route has the same table, destination, TOS and metric
but a different next hop, containd saves its complete payload before replacing
it with a protocol-98 route. Removing that route from intent restores the original
foreign route, including its protocol, scope, preferred source and route metrics.
Unsupported or ambiguous collisions (for example multipath or blackhole routes)
fail with route details rather than replacing entries that cannot be represented
by static-route intent. Unrelated Docker and reserved management entries remain
untouched. A failed commit uses the existing running-config recovery path.

The displaced-route journal is `/data/routing-displaced.json` in the engine data
directory. `CONTAIND_ROUTING_STATE_PATH` overrides its location. Keep that path
writable and persistent; failure to save the journal prevents replacement. The
journal is scoped to the current kernel boot and network namespace, so it
survives an engine process restart in that namespace but is not replayed into a
new container namespace. Run only one engine per namespace, and use a separate
journal path for each namespace. Do not delete the journal while routes are
displaced. If an external actor installs a conflicting route before restoration,
reconcile reports a conflict and retains the journal instead of overwriting it.

Earlier versions already marked static routes with protocol 98, so those routes
converge automatically on upgrade. Earlier policy rules have no reliable
ownership marker. They are deliberately **not** deleted by priority range,
including during explicit reconcile: doing so could remove another application's
rules. Before the first upgraded apply, inspect `ip -4 -details rule show` in the
appliance namespace against the old running configuration and remove only the
individually verified old containd rules (with their exact priority, table and
source/destination selectors). Do not flush the 10000–19999 range. Restarting the
container with a fresh network namespace also discards legacy rules; preserve
Docker and management networking through the normal deployment configuration.
