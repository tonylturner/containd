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

## Partial appliances and default binding

Default interfaces bind independently to a unique **up** NIC matching their
`CONTAIND_AUTO_<NAME>_SUBNET`, or `CONTAIND_<NAME>_SUBNET` when the AUTO hint is
unset. Missing or ambiguous explicit subnet matches stay
unbound; names, the default route and index order cannot override that authority.
Five- and seven-NIC appliances do not need eight NICs to initialize a reservation.
Default bindings are rediscovered by subnet on restart, including NIC renumbering.

Management INPUT rules contain bound device names, never unbound logical names.
If a listener has logical access grants but none of its bindings exists on a
NIC, enforcement permits that listener on discovered NICs **except explicitly
disabled device bindings**. This is the unbound-appliance recovery invariant, not
a permanent reservation. Once a granted binding exists, only granted bindings
are used, even if administratively down. Turning every access flag off creates
no recovery allow. Management
health reports `managementBinding.state: "unbound-appliance"` and `recoveryPorts`;
`"configured"` means ordinary bindings/policy apply, and `"unknown"` means the
running config or engine interface state could not be read.

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

Configuration validation rejects changes that undermine the reserved path:

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

## Persistence, boot and operator visibility

Starter and dev Compose pass `CONTAIND_MGMT_RESERVATION` through. In reserved
mode, also set the loopback engine bind and enforcement variables shown above.

Saving, importing, committing, confirming and rolling back must preserve the
reservation. Default NIC bindings are rediscovered by subnet on restart, while
custom bindings and unrelated candidate edits remain intact. A valid unaddressed
reserved binding stays pinned. Custom rows are not silently renamed, unbound,
or stripped of addresses; correct stale custom bindings explicitly.

First boot and factory reset use deployment defaults, including the reservation,
enforcement and reserved HTTP port. Set subnet hints for the default roles that
exist in your deployment. Factory reset checks the replacement configuration
**before** revoking sessions or wiping data; ambiguous or incomplete discovery
can refuse the reset. A successful reset clears the boot fault and applies defaults.

### Boot fault mode

A remaining **stored-config** reservation conflict never stops management.
Instead, startup persists a boot fault and emits one
`management.reservation.boot_fault` event (also retained in audit). Conflicting
stored HTTP/HTTPS/SSH listener settings are replaced with reservation-safe
appliance defaults **in memory for this boot only**. The API still shows the
stored values for diagnosis. Conflicting deployment environment listeners and
engine binds remain fatal: the operator must fix the deployment.

Initial stored service rendering and normal engine replay are blocked while the
boot fault holds. Instead, management pushes one minimal recovery dataplane
configuration through the engine API: enforcement on, no capture interfaces, DPI,
stored interfaces, routing, zones, rules, NAT or services, and default deny.
Recovery retries if the engine is unavailable. Staging alone does not clear the
fault: a validated commit or rollback resumes normal apply; factory reset also
recovers. A later boot whose binding rediscovery resolves the conflict clears
the persisted fault as well.

**Recovery: new transit dropped.** Once the engine reports the recovery ruleset
applied, all new forwarded connections are denied. Existing/related connections
remain accepted by the ordinary compiler. INPUT defaults to drop with loopback,
established/related and the env-backed reserved HTTP rule; the compiler's existing
ICMP accepts remain, and the loopback engine API needs no rule of its own. This does not promise zero traffic
before the first successful apply or enforcement if the kernel/engine cannot
apply rules. No stored runtime configuration is replayed. Existing interfaces,
routes or services in a still-running split engine are not torn down: recovery
replaces enforcement, not the underlying network/service ownership state.

The reservation API and Interfaces view report whether recovery enforcement is
actually applied, pending or failed. The engine reports the version of the
snapshot it last applied; recovery counts as applied only when that is the
recovery snapshot (`management-recovery`, a version stored configurations
cannot use) and the apply succeeded, including in split mode where the engine
also admits its own API address. Guard health or a successful recovery request
alone does not establish that transit is blocked. A safe commit or rollback
replaces recovery enforcement with the normal running configuration.

With a reservation, only HTTP serving the reserved local address/port is
mandatory. Failed optional HTTPS, SSH and convenience loopback listeners are
logged and exposed as boot-only `listenerFaults`; they do not prevent startup or
block applying otherwise safe policy. If a wildcard HTTP socket is unavailable
because another address is occupied, management independently binds the reserved
address and reports the failed broader listener. A failure to bind that exact
endpoint is fatal. Environment conflicts with the reservation remain fatal.
Without a reservation HTTP/HTTPS bind failures retain their previous fatal
behavior (SSH remains best effort). Correct stored listener settings and restart
to restore the optional listener: an ordinary commit does not rebind sockets.
Management HTTP, legacy HTTP, HTTPS and SSH listener values are structurally
validated at staging/commit/import: empty (default), `host:port` or `:port`, with
numeric ports 1–65535. Validation does not require the host address to be local;
bind availability is a runtime check.

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

## Verification and limitations

Guard history is process-local; the last refused rollback survives a restart.
The guard repairs address takeovers after they occur, so brief interruptions are
possible. A reservation does not replace backups, authentication, or isolation
of the unauthenticated engine API.

For opt-in Linux kernel and isolated Compose verification, see
[test/mgmt-reservation/README.md](https://github.com/tonylturner/containd/blob/main/test/mgmt-reservation/README.md).
