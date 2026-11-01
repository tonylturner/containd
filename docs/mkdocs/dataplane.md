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
4. Ordered terminal rules decide admission with `ALLOW`, `DENY` or `RESET`;
   `RATE_LIMIT` and `TAG` are nonterminal effects. Enforced DPI denials drop the
   packet and best-effort reset only that TCP session, without installing a host
   or service block. Generic TCP denial tombstones last 10 seconds and are
   capped at 16,384; later payload still fails closed as a mid-stream pickup.
   UDP denials drop only the datagram. IEC 104 retains its stateful abort/reset
   path. A native IDS alert alone is not a packet drop.
5. Decoded events feed bounded telemetry, anomaly and signature checks, and
   protocol statistics. Generic asset discovery consumes non-IEC-104 ICS events.
   Explicit live watches and PCAP imports feed the same evidence learner;
   IEC 104 command suggestions require review before monitor-only staging.

## Protocol coverage

`DefaultDecoders()` supplies **12 protocol decoders: 4 ICS + 8 IT**, shared with
PCAP analysis:

- ICS: Modbus/TCP, DNP3, IEC 60870-5-104, and CIP/EtherNet/IP.
- IT: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP, and RDP.
- ICS marker and port detector are additional utility registrations, not protocols.

Protocol toggles select decoders; they do not create matching firewall rules.
See [ICS DPI](ics-dpi.md) for predicates, monitor-mode limits, and IEC 104 behavior.

## Policy and runtime state

Rules match zones, CIDRs, transport/port ranges, identity bindings, schedules
and ICS predicates; see
[Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).
The first matching enforcing terminal rule in configured order wins; otherwise
firewall.defaultAction applies. Monitor rules never decide.
IEC 104 object evaluation instead defaults to deny inside its
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

## Interface address ownership and upgrades

Commit, rollback, restart replay, and periodic/event reconciliation add desired
interface addresses and remove only stale addresses created by containd.
An identical existing address satisfies intent without becoming owned. Docker
and other foreign primary and secondary addresses remain, as do IPv6 link-local
addresses and the reserved management device. Removing the last static address
or its interface binding also removes stale owned addresses. Deletion precedes
addition; while deleting IPv4 addresses, containd temporarily enables
`promote_secondaries` on that device and restores its previous value afterward.
This prevents deleting an owned primary from implicitly deleting foreign or
desired same-subnet secondaries. Failure to enable promotion prevents deletion.

Ownership uses one persisted set, `/data/interface-addresses.json`, overridden
by `CONTAIND_ADDRESS_STATE_PATH`. Keep this engine path writable and persistent;
read/decode/write failures are reported, not treated as an empty set. Records
identify kernel boot, network namespace, device name, index, MAC, and host CIDR.
They survive an engine process restart in the same namespace; a new boot or
container network namespace starts with no owned addresses. Run one engine per
namespace with a separate state path. Do not edit the set or externally reuse a
recorded address tuple while containd owns it; remove it through configuration
first. The set is ownership authority, not an inventory of all live addresses.

The persisted set works for both IP families without requiring newer address
protocol attributes or IPv4-only labels. It does not raise the Linux kernel
requirement of Docker/WSL deployments. `IFA_PROTO` exists in Linux 5.19, but the
deployment requirements do not guarantee that kernel floor, and address labels
do not cover IPv6. Secondary promotion exists since Linux 2.6.12; containd writes
it through the per-device rtnetlink API (present in Linux 2.6.39), not `/proc/sys`,
which Docker normally mounts read-only. Only a successful exclusive address
creation is recorded. An interrupted creation before its durable save leaves an
unowned address. Ownership is revoked
durably before deletion; interruption or a deletion failure in that window can
also leave an unowned address. These conservative cases require inspection and
explicit repair, rather than risking deletion of another owner's address.

Addresses installed by **0.1.36 and earlier** have no ownership records. They
remain unowned on upgrade, even if they match running configuration. Inspect
legacy addresses in the appliance namespace and remove only individually
verified stale containd addresses, or recreate the container namespace through
normal deployment procedures. Never flush Docker or management addressing.

The admin-only `POST /api/v1/interfaces/reconcile`, with
`{"confirm":"REPLACE"}`, is the explicit destructive repair operation. It removes
unmatched **foreign and owned** addresses only on configured interfaces declaring
addresses, while preserving link-local addresses and the reserved management
device. Routine reconciliation never requests this mode.

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
