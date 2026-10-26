# Enforcement Strategy

## Linux nftables path

**nftables is the enforcement path**, with conntrack for connection state. It
implements zone firewalling, NAT masquerade, DNAT port forwarding, and temporary
host/flow block sets. Linux kernel support, the `nft` executable, and suitable
network privileges (including `CAP_NET_ADMIN`) are required; packet capture also
needs the privileges supplied by the supported container deployment.

The engine defaults `CONTAIND_ENFORCE_ENABLED` to false at startup. Running
configuration controls subsequent applies through `dataplane.enforcement`; set
that field to true in candidate and commit for kernel rule application. Starting
capture or seeing decoded events does not prove that firewall policy is installed. Review the ruleset preview and engine status
through `GET /api/v1/dataplane/ruleset` and check for apply errors.

The engine owns only its own nftables tables, named after `dataplane.enforceTable`
(default `containd`). Each apply replaces the policy table
`inet <enforceTable>_policy` in one transaction and keeps the persistent table
`inet <enforceTable>` (temporary blocks and revocations, below). Other tables in
the namespace, such as Docker's embedded DNS rules or the DHCP redirect table
`inet containd_dhcp`, are left untouched. Everything else in
`inet <enforceTable>`, such as the policy chains and sets an older containd
version kept there, is removed on the next apply; flow blocks from an older
version carry over with their remaining timeout. Disabling enforcement deletes
the tables the running engine installed. Renaming the table replaces the old
tables with the new ones on the next apply. A table name starts with a letter
or underscore, followed by letters, digits, underscores and hyphens.

nftables cannot evaluate identity or schedule predicates. On a rule it decides,
an `ALLOW` with either predicate is not installed, and a `DENY` drops without
the predicate's condition. See
[Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).

## Capture is not inline enforcement

- **AF_PACKET** observes packet copies and cannot prevent delivery of a packet
  already observed. ICS rules in effective enforce mode are therefore rejected
  at validation while `nfqueueGroup` is 0; use learn mode with AF_PACKET.
- **NFQUEUE** holds selected packets for userspace verdicts. Set the candidate
  dataplane's `nfqueueGroup` to a nonzero queue (for example 101), preserve the
  rest of the dataplane settings, and commit. The queue and rules must be active
  on the routed packet path. A denied command is dropped inline; later packets
  of the flow are blocked by the cached verdict and a temporary flow block.
  Generic DPI can cache per-flow verdicts; IEC 104 retains session-level
  inspection.

DPI effective mode is per-rule `ics.mode`, then global `dpiMode`, then `learn`.
Learn suppresses the corresponding DPI denial, **not** independent nftables
firewall decisions or an explicit enforce-mode rule. See
[ICS DPI modes](ics-dpi.md#dpi-modes).

IEC 104 enforce rules require DPI enabled, its decoder enabled, NFQUEUE capture,
and no overlapping DPI exclusion. Inside the IEC inspection envelope unmatched,
malformed, unsupported, or broadcast object traffic cannot be allowed by a broad
TCP rule. Enforce-mode tracking exhaustion is fail closed; learn-mode exhaustion
accepts new connections without inspection. These are protocol-specific limits,
not a universal fail-open/fail-closed guarantee. AV has separate failure settings;
see [Config Format](config-format.md).

## ICS rule coverage

Every firewall rule that names an ICS protocol reports its coverage: whether a
prohibited command is actually stopped, not only which mode is configured.

| State | Meaning |
| --- | --- |
| `monitoring` | The effective mode is learn: the rule observes by design. |
| `enforcing` | An inline path inspects every flow in the rule's scope. |
| `partial` | Enforcing, but an exclusion lets some flows in scope skip inspection. |
| `not_enforcing` | The effective mode is enforce, but nothing stops a prohibited command. |

Each lowered state carries reasons with a code and a message:

| Code | Cause |
| --- | --- |
| `no-inline-path` | `nfqueueGroup` is 0 (validation prevents this; a direct engine apply can still carry it). |
| `enforcement-disabled` | `dataplane.enforcement` is false, so nothing steers traffic to the engine. |
| `dpi-disabled` | The DPI master switch is off. IEC 104 envelopes are inspected regardless. |
| `decoder-disabled` | The rule's protocol decoder is off in `dpiIcsProtocols`. |
| `queue-unavailable` | The engine does not hold the configured queue; the kernel drops the rule's traffic instead of inspecting it. |
| `exclusion-overlap` | An IP or CIDR exclusion meets the rule's addresses (not IEC 104). |
| `domain-exclusion` | A domain exclusion can resolve into the rule's scope (not IEC 104). |

Exclusion reasons name the exclusion in `value`. A learn rule keeps
`monitoring` and lists the reasons that limit what it observes. Unrelated
exclusions never lower a rule. Coverage appears in:

- `GET /api/v1/dataplane/ruleset`: `icsCoverage` for the candidate, from its
  settings alone, and `engineStatus.icsCoverage` for the applied rules under the
  running engine's settings and state. Applied exclusion reasons carry
  `matches`, the connections that exclusion has exempted from inspection since
  the rules were last applied.
- `POST /api/v1/firewall/rules/preview`: `icsCoverage` for the previewed rule
  under the running engine.
- `GET /api/v1/health`: `icsEnforcement`, counts only (see
  [API Reference](api-reference.md)).

Generic decoders still pass a packet whose payload they cannot parse; only
IEC 104 fails closed on malformed traffic.

## Actions and temporary blocks

Firewall policy actions are `ALLOW` and `DENY`. The generic dynamic updater
implements temporary host and flow blocks; enum names such as rate-limit or tag
do not establish an implemented enforcement action. Native IDS matches produce
alerts, not automatic IPS action.

Administrators can request temporary blocks through:

- `POST /api/v1/dataplane/blocks/host`
- `POST /api/v1/dataplane/blocks/flow`

Temporary blocks and connection revocations live in the persistent nftables
table `inet <enforceTable>` (default `inet containd`; sets `block_hosts`,
`block_flows`, `revoke4`, `revoke6`, `revoke_service4` and `revoke_service6`).
They act before the policy table's rules, including on established connections,
and they persist across commits until their timeouts expire. Revocations skip
traffic to the management listeners on the management interfaces and to the
reserved management listener, so they cannot lock administrators out.

See [API Reference](api-reference.md) for request fields. A decision or block
request is not proof of delivery prevention; inspect verdict/apply errors and
[evidence limits](logging-evidence.md).

## Experimental eBPF code

`pkg/dp/ebpf` contains experimental XDP/TC pass-through programs. The engine does
not load them; they provide no enforcement, early drops, counters, or event
streaming in the appliance. nftables has no automatic eBPF acceleration path.
