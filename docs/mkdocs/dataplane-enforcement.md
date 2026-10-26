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

nftables cannot evaluate identity or schedule predicates. On a rule it decides,
an `ALLOW` with either predicate is not installed, and a `DENY` drops without
the predicate's condition. See
[Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).

## Capture is not inline enforcement

- **AF_PACKET** observes packet copies. Later dynamic blocks can affect subsequent
  traffic, but cannot prevent delivery of a packet already observed.
- **NFQUEUE** holds selected packets for userspace verdicts. Set the candidate
  dataplane's `nfqueueGroup` to a nonzero queue (for example 101), preserve the
  rest of the dataplane settings, and commit. The queue and rules must be active
  on the routed packet path. Generic DPI can cache per-flow verdicts; IEC 104
  retains session-level inspection.

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

## Actions and temporary blocks

Firewall policy actions are `ALLOW` and `DENY`. The generic dynamic updater
implements temporary host and flow blocks; enum names such as rate-limit or tag
do not establish an implemented enforcement action. Native IDS matches produce
alerts, not automatic IPS action.

Administrators can request temporary blocks through:

- `POST /api/v1/dataplane/blocks/host`
- `POST /api/v1/dataplane/blocks/flow`

See [API Reference](api-reference.md) for request fields. A decision or block
request is not proof of delivery prevention; inspect verdict/apply errors and
[evidence limits](logging-evidence.md).

## Experimental eBPF code

`pkg/dp/ebpf` contains experimental XDP/TC pass-through programs. The engine does
not load them; they provide no enforcement, early drops, counters, or event
streaming in the appliance. nftables has no automatic eBPF acceleration path.
