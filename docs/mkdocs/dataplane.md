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
4. Firewall rules evaluate to `ALLOW` or `DENY`. Generic enforced DPI denials can
   install temporary flow blocks. IEC 104 can drop the held packet and abort/reset
   a session. A native IDS alert alone is not a packet drop.
5. Decoded events feed bounded telemetry, anomaly and signature checks, and
   protocol statistics. Asset discovery and automatic rule learning consume
   non-IEC-104 ICS events only.

## Protocol coverage

`DefaultDecoders()` supplies **16 protocol decoders: 8 ICS + 8 IT**, shared with
PCAP analysis:

- ICS: Modbus, DNP3, IEC 60870-5-104, CIP/EtherNet/IP, S7comm, IEC 61850 MMS,
  BACnet, and OPC UA.
- IT: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP, and RDP.
- ICS marker and port detector are additional utility registrations, not protocols.

Protocol toggles select decoders; they do not create matching firewall rules.
See [ICS DPI](ics-dpi.md) for predicates, learn-mode limits, and IEC 104 behavior.

## Policy and runtime state

Rules match zones, CIDRs, transport/port ranges, and supported ICS, identity, and
schedule predicates. Evaluation is ordered, with a default action when no generic
rule matches. IEC 104 object evaluation instead defaults to deny inside its
inspection envelope. Snapshot swaps are atomic.

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

Docker-created connected/default routes and reserved management routes/rules
are not routing-owned entries. A configured route colliding with a foreign route
fails apply instead of replacing it. Resolve that conflict explicitly outside
containd or choose a different route metric/table. A failed commit uses the
existing running-config recovery path to restore the previous routing intent.

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
