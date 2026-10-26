# Policy Model

Policy separates the configuration you are editing from the configuration the
engine runs:

- **Candidate** holds staged changes. Saving a rule or applying a template does
  not activate it.
- **Running** is the committed configuration. Commit validates candidate state
  and applies it; rollback restores a prior revision. Commit-confirmed requires
  confirmation within its timeout. See [Config Format](config-format.md).

## Firewall and DPI

Zone firewall rules use the Linux nftables backend. Rules match zones,
CIDRs/assets, transport/port ranges, and optional identity, schedule, and ICS
predicates. Generic evaluation uses the firewall default action when nothing
decides. The default action is `ALLOW` or `DENY`; an omitted or empty default
action means `DENY`.

### Actions and precedence

Rule order in the configuration does not decide anything. A packet or ICS
message is decided in three steps, in nftables and in the engine alike:

1. If any matching `ALLOW` rule exists, it is allowed.
2. Otherwise, if a `DENY` or `RESET` rule matches, the first of them by rule ID
   decides.
3. Otherwise the default action applies.

The rule a decision reports, in events and logs, is the first match in that
order: `ALLOW` rules by rule ID, then `DENY` and `RESET` rules by rule ID. A
`DENY` or `RESET` rule that overlaps an `ALLOW` is shadowed where they overlap.
This holds for ICS rules too: an ICS `DENY` overlapping any `ALLOW`, including
a plain L3/L4 `ALLOW`, is shadowed. IEC 104 objects are the one exception to
the L4 part of this: they are decided among IEC 104 rules only, so a broad
`ALLOW` on TCP 2404 does not admit them (see
[IEC 104 fields and matching](ics-dpi.md#iec-104-fields-and-matching)).

The ruleset warnings (below) name a `DENY` or `RESET` rule when one `ALLOW`
rule matches all of its traffic (`shadowedBy`). The check is conservative: a
rule covered only by several `ALLOW` rules together is not reported, and IEC
104 rules are left out.

| Action | Decides | Effect |
| --- | --- | --- |
| `ALLOW` | yes | Accepts the packet. |
| `DENY` | yes | Drops the packet. |
| `RESET` | yes, as `DENY` | Rejects back to the sender: a TCP reset for TCP, ICMP or ICMPv6 destination unreachable (administratively prohibited) otherwise. |
| `RATE_LIMIT` | no | Drops the packets over `rateLimit` for each directional 5-tuple; a packet under the limit continues to the decision. |
| `TAG` | no | Labels matching flows and their events with `tag`; no kernel effect. |

`RESET`, `RATE_LIMIT` and `TAG` act on a rule's L3/L4 scope and take no ICS
protocol: IEC 104 keeps sole ownership of session resets, and an ICS rate or
label is not defined. `RESET` cannot be the default action. Inside NFQUEUE
inspection the engine cannot reject a queued packet, so a `RESET` rule that
decides an inspected ICS message drops it like `DENY` and blocks the flow.

`RATE_LIMIT` is a kernel packet policer, keyed by source and destination
address, layer-4 protocol and, for TCP and UDP, both ports; on IPv4 and IPv6.
`packetsPerSecond` is 1 to 1,000,000; `burst` is the bucket depth in packets, 0
to 1,000,000, where 0 means `packetsPerSecond`. It meters every packet of a
flow, established ones included, before NFQUEUE and IEC 104 steering. It never
admits traffic. Each rule's meter tracks up to 65,536 tuples per address family
and key; a tuple expires once idle long enough to refill its bucket, and while
a meter is full, new tuples pass unmetered until entries expire. A rule with
sources or destinations meters IPv4 only, because nftables matches rule
addresses as IPv4.

`TAG` labels are lower-case, 1 to 32 characters (`a-z`, `0-9`, `_`, `.`, `-`,
starting with a letter or digit); a configuration uses at most 32 distinct
labels. A flow's labels are those of every `TAG` rule matching its tuple when
it opens (opener, server, protocol, server port), so a `TAG` rule takes no
schedule. They appear as a `tags` attribute on the flow's events and on the
connection list (`GET /api/v1/conntrack`), which derives them the same way
from the running ruleset.

Every rule has an nftables counter. `GET /api/v1/firewall/counters` reports
each rule's packets and bytes, and each `RATE_LIMIT` rule's excess drops, for
the applied ruleset; logging need not be on. Every apply restarts the counters
at zero, and the response says when (`since`).

### Identity and schedule predicates

A rule's `identities` and `schedule` are conditions that change without a new
connection: an identity binding is removed, or a window opens or ends.

**Identities** are admin-set tags on source addresses,
`firewall.identityBindings` (see [Config Format](config-format.md)). They are
part of the configuration: staged in the candidate, applied on commit, and
backed up, exported and rolled back with it. A rule with `identities` matches a
connection whose opener address is bound to any listed label, compared exactly
and case-sensitively. An opener without a matching binding matches no identity
rule, `ALLOW` or `DENY`.

**Schedules** are recurring windows in the rule's `timezone`, UTC when blank:

- A window opens on each listed day, or every day when `daysOfWeek` is empty,
  at `startTime` and closes at `endTime`. The end is exclusive: a 09:00–17:00
  window does not match at 17:00.
- A window whose end is not after its start is overnight and ends on the next
  day. It belongs to its start day: a Monday 22:00–02:00 window matches Monday
  night and early Tuesday, not early Monday.
- A blank `startTime` is 00:00 and a blank `endTime` is the end of the day.
  Equal start and end times are invalid.
- On a daylight-saving change, a skipped local time is the moment the gap
  ends, and a repeated local time is its first occurrence.

nftables evaluates both predicates on every rule it handles, `RATE_LIMIT` and
`TAG` included: a `RATE_LIMIT` rule with identities meters, in both
directions, only connections a bound address opened, and a `TAG` rule with
identities labels only those connections. Identity bindings
become per-label address sets. Schedules become sets of absolute times that the
kernel opens and closes itself. The engine plans 24 hours of windows ahead and
refills them as they run out, and again after a wall-clock step. If the engine
stops planning, the windows fail closed when the plan runs out: a scheduled
`ALLOW` stops matching and a scheduled `DENY` applies at all times. For ICS
rules that NFQUEUE steers to the engine, the engine evaluates both predicates on
each message.

The conditions also apply to established connections, in both directions.
When a binding is removed or a window ends, a connection that only a
conditional `ALLOW` admitted stops passing. A connection that an unconditional
`ALLOW` also admits keeps passing. When a scheduled `DENY` window opens, it
stops the established connections it covers. The current policy decides those
connections again by their original tuple, and connections outside the scope of
any conditional rule keep the established fast path.

A rule whose identities no bound address satisfies matches nothing. It is
reported as a warning with its rule ID, the predicate `identity`, the action
and the effect, in:

- The firewall page's nftables ruleset preview, which lists the candidate's
  warnings.
- `GET /api/v1/dataplane/ruleset`: `warnings` for the candidate and
  `engineStatus.warnings` for the last applied ruleset.
- The rule editor's **Preview impact**, and `warnings` in the
  `POST /api/v1/firewall/rules/preview` response, for the previewed rule.

The rule impact preview evaluates a schedule at each event's time. It takes
identities from the running bindings, so it shows what the rule would match if
today's bindings had applied to the retained events.

DPI mode resolves per-rule `ics.mode` > global `dpiMode` > `learn`. Learn is not a
global bypass: enforce-mode rules and independent kernel decisions can still
block traffic. IEC 104 uses a dedicated inspection envelope with default-deny
object evaluation, even if the generic firewall default is allow. See
[ICS predicates and modes](ics-dpi.md#ics-firewall-rule-predicates) and
[Enforcement](dataplane-enforcement.md).

Native [IDS rules](ids-rules.md) evaluate decoded events and generate alerts;
these are distinct from firewall decisions. Learned allowlist rules require
review, candidate staging, and commit.

## Templates and preview

The seven templates at `GET /api/v1/templates/ics` comprise two Modbus variants
and DNP3, S7comm, CIP, BACnet, and OPC UA examples, not one per supported protocol.
`POST /api/v1/templates/ics/apply` stages their rules. Purdue and maintenance
window templates belong to the general `/api/v1/templates` registry and its
`/apply` endpoint. The maintenance window template stages scheduled L4 `ALLOW`
rules that open Operations (L3) access to the L1, L0 and L2 zones on Saturdays
and Sundays from 02:00 to 06:00 America/New_York (see
[Identity and schedule predicates](#identity-and-schedule-predicates)).

Applying a template with `mode: "enforce"` is refused while
`dataplane.nfqueueGroup` is 0, as for any ICS rule in enforce mode.

Use `POST /api/v1/firewall/rules/preview` to inspect matches before committing;
preview is not a live packet-delivery test. For a rule with an ICS protocol it
also reports the rule's coverage (see
[ICS rule coverage](dataplane-enforcement.md#ics-rule-coverage)).

The admin-only `GET /api/v1/dataplane/ruleset` previews the candidate nftables
ruleset through the live engine, without applying it. It uses the candidate's
table, NFQUEUE and NFLOG settings and the engine's reserved management access.
The response and firewall page explain the IEC 104 envelope decision sampled
from current queue ownership. A later queue bind or loss can change steering
before commit. If the engine cannot compile, preview reports an error rather
than guessing with compiler defaults.
Preview does not enable enforcement or prove that a kernel apply will succeed.
When candidate enforcement is disabled, preview returns no nftables ruleset and
states plainly that enforcement is disabled and nothing would be applied.
