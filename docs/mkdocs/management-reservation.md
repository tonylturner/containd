# Reserved management path

A deployment can reserve plain-HTTP management for exact IPv4 peers independently
of student interface-access flags and firewall policy:

```sh
export CONTAIND_MGMT_RESERVATION='{"subnet":"10.99.99.0/24","sources":["10.99.99.10","10.99.99.3"],"listen":":8080"}'
export CONTAIND_ENGINE_ADDR=127.0.0.1:8081
export CONTAIND_ENFORCE_ENABLED=1
```

Pass the same declaration to both processes in split mode, in the **same network
namespace**. The management process waits for a matching, active engine guard before
starting services. Combined mode resolves the authority once and shares it.
The standalone binary uses `CONTAIND_MGMT_ADDR` for its effective HTTP bind;
the standard Compose files map `CONTAIND_MGMT_HTTP_ADDR` to that variable.

Unset or empty means no reservation. Otherwise startup strictly validates JSON
(including unknown/duplicate keys), IPv4 sources, port, and the live network. Exactly
one up interface/address must match `subnet`. Its actual host address and prefix
are retained, not the subnet's network address. Sources must be unique, distinct
from that local address, and in the declared subnet. The deployment must place
them on-link. Ambiguity or a malformed declaration is fatal.
This is process authority, never an editable Config or snapshot field.

## Guarantees

Every compiled firewall has an independent INPUT allow after invalid-packet drop:

```nft
iifname "eth7" ip saddr { 10.99.99.10, 10.99.99.3 } ip daddr 10.99.99.2 tcp dport 8080 accept;
```

The device is discovered at boot; it need not be `eth7`. The HTTP access gate uses
only the socket peer and local address/port, never Host or forwarded headers. The
request still passes through the **ordinary router and authentication**. HTTPS
and SSH have no reservation. This is an additional allow, not an exclusive ACL:
other peers retain ordinary policy-controlled access.

Replies use priority-1 policy rules, immediately after the kernel local rule,
one exact local/source pair each. Table **104000**, outside user table IDs 1–252,
holds source /32 on-link routes through the reserved device with the reserved
local address. Route protocol **99** is distinct from managed protocol 98.
Routing REPLACE and ownership reconciliation preserve these pins.

The engine subscribes to netlink before services start. If a VPN or other runtime
actor assigns a reserved source locally, the guard removes that address and any
matching /32 route in kernel table 255. The VPN intentionally loses the address.
Repair is event-driven, with a full scan on startup, ownership reconciliation,
and resubscription. Subscription errors/overflow are faulted and retried rather
than silently disabling protection. A transient takeover can interrupt traffic
until repair; this is not an atomic prevention mechanism.

`/health` and `/internal/ownership` expose `managementReservation` guard status,
including a sticky fault counter and last fault. `management.reservation.fault`
events name the address and interface. Service attribution is `unknown` when the
kernel cannot establish an owner. Current errors/subscription unavailability are
visible even when the last successful repair has cleared its immediate error.

## Substrate checks

The pure `config.ValidateManagementReservation` and exported component predicates
reject changes that undermine the substrate:

- Anything other than exactly one unaddressed physical logical binding of the
  reserved device; DHCP/static addressing, another binding, virtual parents or
  bridge/bond membership using that device.
- The reserved local address or a source assigned elsewhere, VPN prefixes
  containing the local address, and a WireGuard device named like the reserved
  device (even disabled, because disabling deletes it).
- DHCP pools/reservations allocating protected addresses.
- Overlapping TCP DNAT/port forwards, or other service/HTTPS/SSH listeners claiming
  the reserved address/port or a wildcard. Management listener checks also
  protect HTTP's wildcard socket and loopback convenience listener from HTTPS/SSH
  collisions, even when the secondary bind names another local address.
- HTTP disabled, redirect to HTTPS, incompatible HTTP bind/port (including the
  legacy alias), enforcement disabled, or a non-loopback engine bind.
- Explicit priority ≤1 rules matching reserved replies. Priority 0 means automatic
  managed priority, not kernel priority 0, and remains allowed.

Logical names, zones and every access flag remain free: **all access flags may be
false**. Default deny, ordinary rules, routes, later/disjoint policy rules and
managed/external OpenVPN profiles remain allowed. Profiles are not read by the
validator; pushed addresses are handled by the runtime guard.

The full validator is installed at persistence/replay boundaries; component guards
also protect the engine's partial interfaces, routing, services and configuration
APIs. DNAT snapshots are checked before any kernel application or state swap.

## Persistence, boot and operator visibility

Starter and dev Compose pass `CONTAIND_MGMT_RESERVATION` through. In reserved
mode, also set the loopback engine bind and enforcement variables shown above.

The store captures immutable validation context at construction. Save, staging,
promotion, confirmation and rollback use it. Store open upgrades snapshots and
handles pending expiry without rejecting a conflicting stored running config.
Boot then creates defaults only when empty, normalizes default NIC bindings in a
candidate-preserving `Repair` transaction, and checks the repaired running config.
Repair validates ordinary structure, not reservation compliance: a legacy conflict
must not prevent management recovery. Non-reservation repair failures warn and
continue. Custom rows and unrelated candidate edits/IDS banks remain intact.

A valid unaddressed reserved binding is pinned during normalization. A default
row merely having the current device name is **not** ownership when the NICs have
renumbered: stale addressed default rows are reassigned by live subnet discovery.
Custom rows are not silently renamed, unbound or stripped of addresses.
Runtime replay never moves a reserved binding.

First boot and factory reset share one appliance-defaults builder, including
bootstrap environment defaults, SSH fields and reserved autobinding. Set the
normal `CONTAIND_AUTO_*_SUBNET` variables for the deployment's eight default NICs.
Reserved defaults enable enforcement and use the reserved HTTP port. Factory
reset validates the exact autobound replacement **before** revoking sessions or
wiping any database. A valid deployment can reset while reserved; ambiguous or
incomplete NIC discovery can still produce a genuine pre-wipe refusal. Reset
clears the boot fault and applies the defaults to services and engine.

### Boot fault mode

A remaining **stored-config** reservation conflict never stops management.
Instead, startup persists a boot fault and emits one
`management.reservation.boot_fault` event (also retained in audit). Conflicting
stored HTTP/HTTPS/SSH listener settings are replaced with reservation-safe
appliance defaults **in memory for this boot only**. The API still shows the
stored values for diagnosis. Conflicting deployment environment listeners and
engine binds remain fatal: the operator must fix the deployment.

Initial service rendering and engine replay are blocked while the boot fault
holds, without repeated apply attempts or warning spam. Staging is not recovery:
a validated commit or rollback clears the fault transactionally and resumes
normal apply; factory reset also recovers. A later boot whose normalization
resolves the conflict clears the persisted fault as well.

**This is management recovery, not a fail-closed dataplane mode.** Before its
first apply a fresh engine has no loaded rule snapshot and no compiled/applied
nftables ruleset (`ruleset` is empty and `appliedAt` is the zero timestamp).
Capture uses deployment startup settings (none by default); stored interfaces,
routes, services, DPI and PCAP settings have not been replayed. The env-backed
return-path pin and source-address guard are active independently. The compiled
INPUT allow exists only after a ruleset apply, not from the guard alone. In a
fresh container namespace there is no containd firewall table (Docker DNS NAT
chains may still exist): there is no student firewall/default-deny enforcement.
Existing kernel rules or a still-running split engine retain their prior state; management does not claim they have been
reset or are safe. The reserved HTTP access gate and normal authentication still
serve recovery. Do not infer traffic isolation from a healthy management guard.

## Faults and visibility

`GET /api/v1/system/management-reservation` requires the normal API authentication.
It returns device, local host prefix, exact sources, HTTP port, engine guard
health/fault history, the persistent boot fault (`bootFault`) and the last refused
rollback. Without a reservation it returns exactly `{"active":false}`. Interfaces displays a read-only explanatory
note; neither the view nor config imports can change the authority.

Unsafe manual rollback returns an error and records `config.rollback.refused`
in structured logs plus a persistent operator fault. Unsafe timed rollback
(including expiry at store open) **keeps running and candidate, retains previous,
clears pending**, and records the same fault. It never applies or repeatedly
retries the unsafe target. Fault-recording failures remain errors and do not
clear pending.

## Threat boundary

The guarantee covers policy/API edits, including import, rollback and replay.
It does not cover a root shell,
host/Compose/environment changes, network deletion, source spoofing, denial of
service, process failure or revoked credentials. An uploaded OpenVPN profile's
script hooks are root code execution and outside this boundary. A script-free
profile or remote VPN server assigning a reserved source loses it to the guard.

## Linux acceptance

From the repository root, with Docker Desktop running:

```sh
bash pkg/dp/netcfg/management-kernel.sh
```

The disposable container has NET_ADMIN/SYS_ADMIN (for its second network namespace)
and TUN access. It publishes no ports, changes no host network and removes itself.
It makes real TCP connections over veth with strict reverse-path filtering,
competing rules at 2/9000/10000, competing routes, REPLACE/reconcile, local-table
takeover and an actual OpenVPN source assignment. Recovery and visible faults are
required within five seconds. Ordinary test runs skip this opt-in kernel matrix.

## Isolated management smoke

Run `bash scripts/smoke-mgmt-reservation.sh` from the worktree root; see
`test/mgmt-reservation/README.md`. This separate Compose project publishes no
ports and proves health/login, an all-access-off commit, exact-source-only
reachability, substrate rejection, deterministic NIC renumbering, residual-conflict
boot/no-apply, and safe commit/factory-reset recovery. It never connects to
or changes the RangerDanger stack. Guard history is process-local; the last
refused rollback survives store reopen.
