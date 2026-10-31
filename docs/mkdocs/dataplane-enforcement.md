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
through `GET /api/v1/dataplane/ruleset` and check for apply errors. Any
authenticated user can read the installed ruleset's status, without the ruleset
text, through `GET /api/v1/dataplane/ruleset/status`: `error` and `failedAt` for
a failed apply, `schedulePlanner`, applied `warnings`, and `installed`, which is
false before the first successful apply and while enforcement is disabled.

The engine owns only its own nftables tables, named after `dataplane.enforceTable`
(default `containd`). Each apply replaces the policy table
`inet <enforceTable>_policy` in one transaction and keeps the persistent table
`inet <enforceTable>` (temporary blocks and revocations, below). Other tables in
the namespace, such as Docker's embedded DNS rules or the DHCP redirect table
`inet containd_dhcp`, are left untouched. Everything else in
`inet <enforceTable>`, such as the policy chains and sets an older containd
version kept there, is removed on the next apply; flow blocks from an older
version carry over with their remaining timeout. Disabling enforcement deletes
the tables the running engine installed, and the ruleset status then reports
no installed ruleset. Renaming the table replaces the old
tables with the new ones on the next apply. A table name starts with a letter
or underscore, followed by letters, digits, underscores and hyphens.
Local input and NAT rules match a zone's interfaces through the set
`zone_<hex-encoded zone name>` in the policy table, so every zone gets its own
set even when names differ only in case or punctuation. A zone with interfaces
can therefore have a name of at most 125 bytes. The engine places a flow's
addresses in zones by the networks on each zone's interfaces. It reads them
once and again after every link or address change the kernel reports, so a
changed address takes effect without a commit.

nftables enforces identity and schedule predicates on the rules it handles,
with per-label address sets and absolute-time interval sets in the policy
table, and decides established connections in their scope again before the
conntrack accept. For a conditional ICS `ALLOW` queued to the engine, that
recheck covers the replies and server packets the queue does not see. See
[Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).

Rule addresses are written per address family (`ip` or `ip6`), one line per
family for a rule with both. Interface names are written as quoted nftables
strings; the apply refuses a name that is not a valid Linux interface name
(1–15 bytes, no `/`, `:`, whitespace or control characters, not `.` or `..`)
or that nftables cannot match exactly (`"`, `*`, `\`). A rule line whose zones
have no interfaces, or whose addresses share no family, is left out, and the
rule is reported in the ruleset warnings
([Rules that match nothing](policy-model.md#rules-that-match-nothing)).

## Capture is not inline enforcement

- **AF_PACKET** observes packet copies and cannot prevent delivery of a packet
  already observed. ICS rules in effective enforce mode are therefore rejected
  at validation while `nfqueueGroup` is 0; use monitor mode with AF_PACKET.
- **NFQUEUE** holds selected packets for userspace verdicts. Set the candidate
  dataplane's `nfqueueGroup` to a nonzero queue (for example 101), preserve the
  rest of the dataplane settings, and commit. The queue and rules must be active
  on the routed packet path. A denied command is dropped inline; later packets
  of that TCP incarnation keep dropping even after the verdict cache expires.
  After the drop completes, the engine sends a best-effort RST to each peer
  and deletes exactly that conntrack tuple, including both ports. No DPI deny
  installs a host or service block. A fresh handshake, including one from the
  same source port, is admitted immediately; other sessions are untouched.
  UDP denies drop only the datagram, with no reset or block.
  Generic DPI can cache per-flow verdicts; IEC 104 retains session-level
  inspection.

For verified AF_PACKET observations, ICS policy coordinates match the forward
chain: pre-SNAT client → post-DNAT backend, including the backend service port.
Wire event endpoints, flow IDs, reassembly and RST addresses are unchanged;
verified conntrack deletion uses the kernel's original tuple. Unverified
observations and retained-event rule preview remain wire-based. See
[Transport identity and NAT](ics-dpi.md#transport-identity-and-nat) for resolution
statuses and late-verification behavior.

DPI effective mode is per-rule `ics.mode`, then global `dpiMode`, then `monitor`.
Monitor rules never admit or deny traffic; independent nftables decisions,
enforcing rules and strict enforce scopes still apply. See
[ICS DPI modes](ics-dpi.md#dpi-modes).

IEC 104 enforce rules require DPI enabled, its decoder enabled, NFQUEUE capture,
and no overlapping DPI exclusion. Inside the IEC inspection envelope unmatched,
malformed, unsupported, or broadcast object traffic cannot be allowed by a broad
TCP rule. Enforce-mode tracking exhaustion is fail closed; monitor-mode exhaustion
accepts new connections without inspection. These are protocol-specific limits,
not a universal fail-open/fail-closed guarantee. AV has separate failure settings;
see [Config Format](config-format.md). In an enforce envelope an IEC 104
session starts only at a SYN of a handshake that the kernel's connection
tracking has not seen complete. A SYN sent into an established connection
starts none; a connection the engine did not see from its SYN is dropped and
reset at both endpoints. A client that lost an established session and
reconnects from the same source port recovers as described below for other
ICS protocols. A RST without payload closes a session only at the sequence
number its receiver expects next; any other passes and the session stays
inspected. Before the server's SYN-ACK, only the server's RST refusing the
client's SYN passes (no payload, acknowledging the SYN): the client fails at
once, as with a station that does not listen, and its next SYN opens a new
session. Any other packet before the SYN-ACK, except the client's SYN, is
dropped.
A segment carrying both SYN and RST is never a handshake segment: it
opens, establishes and closes no session, and is dropped within any
session and in an enforce envelope.

With NFQUEUE, a generic ICS connection inside an enforce rule's scope fails
closed when its stream cannot be inspected: a conflicting overlap, a
retransmission that differs from or predates the bytes the engine kept,
malformed framing, reassembly limits, a decoder fault, or a SYN with payload
that does not start the connection's stream (reason `stream_resync`). The
packet is dropped and only that session is reset, like a decoded denial,
without restarting inspection of its old bytes. A tuple tombstone keeps the
denied incarnation dropping independently of verdict-cache expiry for a fixed
10 seconds; duplicates do not refresh it. At most 16,384 tombstones are kept,
with the oldest evicted first. Capacity evictions increment
`containd_dp_denied_tcp_evictions_total`. Ten seconds covers early payload
retransmissions and the challenge-reset window, not every possible delayed
duplicate. Expiry and eviction clear only the guarded tuple's verdicts, flow
state and failed streams: later payload fails closed as a mid-stream pickup
and triggers another reset, while a fresh kernel-tracked handshake can start
inspection immediately. A fresh handshake also retires a still-live tombstone.

Generic resets are **best-effort**, not confirmation that either peer closed.
The engine uses the denied packet's SEQ for its receiver and ACK for its
sender; without an ACK the sender's reset sequence is unavailable. Generic
NFQUEUE rules do not automatically steer reverse traffic, so server-side RFC
5961 challenge ACKs may not be observed. There is no IPv6 reset injector:
IPv6 denies, and TCP denies when the injector is not ready, drop only. An
`ics.session` event per peer records `reset_sent`, `reset_failed`, or
`unavailable`, with `target` set to `client` or `server`. Send failures retain
the existing enforcement health fault. These events are visible in the generic
event list; they do not assert confirmed closure. Manual blocks, AV blocks
and operator connection revocations remain independent.

A connection the engine did not see from its SYN is dropped (reason
`stream_midstream`). This covers connections open across an engine restart or
a data-plane configuration change, connections idle longer than the engine's
5-minute flow timeout, and a connection whose tuple carries the SYN of a new
handshake while the engine still follows the old one. No flow block is
installed. The engine resets the connection at both endpoints and drops its
later packets; after tombstone expiry or eviction, another pickup can trigger
another reset. The client reconnects at once and its next
connection is inspected from its first byte. An endpoint that answers its
reset with a challenge ACK gets it again at that ACK's sequence number, up
to three times within a second, as IEC 104 sessions do. Without the reset
injector, or for IPv6, the connection is only dropped. A reset that fails
makes the `iec104Enforcement` health object unhealthy while such a rule is
loaded, even without an IEC 104 envelope (`active` stays false); the
`enforce_unhealthy` session event still describes IEC 104 envelopes only.
Monitor rules and observations without an inline verdict do not change delivery;
other enforcing rules, defaults and strict scopes can still block.

Inspection starts only at a SYN of a handshake that the kernel's connection
tracking has not seen complete. A SYN without payload sent into an
established connection passes, but inspection does not restart at it, so its
sender cannot choose where framing starts. This is how a client that lost its
connection without closing it, for example by restarting, reconnects from the
same source port: the server answers its SYN with a challenge ACK, the
client's reset closes the old connection, and the client's next SYN starts a
new, inspected one.

## ICS rule coverage

Every firewall rule that names an ICS protocol reports its coverage: whether a
prohibited command is actually stopped, not only which mode is configured.

| State | Meaning |
| --- | --- |
| `monitoring` | The effective mode is monitor: the rule observes by design. |
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

Exclusion reasons name the exclusion in `value`. Reasons that only the running
engine can know (`queue-unavailable`) carry `runtime: true`; every other reason
also appears in a static evaluation of the same rules and settings, so the
candidate and the applied coverage differ in configuration only when they
differ without runtime reasons and match counts. A monitor rule keeps
`monitoring` and lists the reasons that limit what it observes. Unrelated
exclusions never lower a rule. Coverage appears in:

- `GET /api/v1/dataplane/ruleset`: `icsCoverage` for the candidate, from its
  settings alone, and `engineStatus.icsCoverage` for the applied rules under the
  running engine's settings and state. Applied exclusion reasons carry
  `matches`, the connections that exclusion has exempted from inspection since
  the rules were last applied. Applied coverage always describes the rules in
  force: a failed apply leaves the previous rules installed, so after one
  `engineStatus.error` is set while `engineStatus.icsCoverage` still describes
  the previous rules (and is empty if no apply has succeeded yet).
- `GET /api/v1/dataplane/ics-coverage`, readable by any authenticated user and
  without the ruleset: `candidate` (or `candidateError` when the candidate does
  not validate), `applied` with `appliedAt` and `applyError` (or
  `engineStatusError` when the engine cannot be read). Each side is reported
  even when the other fails; the admin-only ruleset preview keeps refusing an
  invalid candidate with HTTP 400.
- `POST /api/v1/firewall/rules/preview`: `icsCoverage` for the previewed rule
  under the running engine.
- `GET /api/v1/health`: `icsEnforcement`, counts only (see
  [API Reference](api-reference.md)).

Generic decoders still pass a packet whose payload they cannot parse; only
IEC 104 fails closed on malformed traffic.

## Actions and rule order

Any matching `ALLOW` wins; otherwise the first matching `DENY` or `RESET` by
rule ID decides; otherwise the default (see
[Actions and precedence](policy-model.md#actions-and-precedence)). The engine
decides inspected ICS messages the same way, so an ICS `DENY` that overlaps an
`ALLOW` is shadowed. The forward chain of the policy table runs in this order:

1. `RATE_LIMIT` meters, by rule ID: every packet of a matching flow, established
   or not and in both directions, is counted against its directional 5-tuple's
   bucket and dropped over the limit. Tracked packets match by their
   connection's original tuple (`ct original`, `ct reply`), packets without
   usable connection tracking state by their header.
2. IEC 104 envelope steering and the NFQUEUE lines of ICS rules. Envelope
   steering jumps to the `iec104_envelope` chain and the NFQUEUE lines of the
   other ICS rules to the `ics_queue` chain. Both chains mark the packets of
   connections whose handshake connection tracking has not seen complete.
3. The established/related accept and the DNAT accepts.
4. `TAG` lines, by rule ID, which count matching connection openers and
   continue.
5. Every `ALLOW` line, by rule ID.
6. Every `DENY` and `RESET` line, by rule ID. `RESET` lines end in
   `reject with tcp reset` for TCP and `reject with icmpx admin-prohibited`
   otherwise.
7. The chain policy, the default action.

Every line updates its rule's named counter, read through
`GET /api/v1/firewall/counters`; a `RATE_LIMIT` rule has a second counter for
its excess drops. Counters live in the policy table, so each apply restarts
them. `TAG` has no kernel mark: NFQUEUE steering owns mark mask `0x0f000000`
(bit `0x01000000` for IEC 104 envelope traffic, bit `0x02000000` for a
connection whose handshake connection tracking has not seen complete), and a
tag has no enforcement effect.

## Temporary blocks

The generic dynamic updater implements temporary host and flow blocks. Native
IDS matches produce alerts, not automatic IPS action.

Administrators can request temporary blocks through:

- `POST /api/v1/dataplane/blocks/host`
- `POST /api/v1/dataplane/blocks/flow`

Temporary blocks and connection revocations live in the persistent nftables
table `inet <enforceTable>` (default `inet containd`; sets `block_hosts`,
`block_flows`, `revoke4`, `revoke6`, `revoke_service4`, `revoke_service6`,
`revoke_icmp4` and `revoke_icmp6`).
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
