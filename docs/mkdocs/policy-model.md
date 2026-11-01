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
CIDRs, transport/port ranges, and optional identity, schedule, and ICS
predicates. Sources and destinations may be IPv4 or IPv6 CIDRs, mixed in one
rule: each address family matches its own addresses, so a rule whose sources
are all IPv4 and destinations all IPv6 (or the reverse) matches nothing. A zone
matches the interfaces assigned to it; a rule whose source or destination zones
have no interfaces matches nothing. Generic evaluation uses the firewall default action when nothing
decides. The default action is `ALLOW` or `DENY`; an omitted or empty default
action means `DENY`.

### Actions and precedence

The first matching enforcing terminal rule in configured order wins; otherwise
firewall.defaultAction applies. Monitor rules never decide.

Configurations below schema 0.1.10 migrate legacy rule precedence and
port-forward permissions on upgrade. Review
[ordered policy upgrades](config-format.md#ordered-policy-upgrades), including
the warnings for forwards whose permissions cannot be generated safely.

Terminals are `ALLOW`, `DENY` and `RESET`; rule IDs do not set precedence.
Logged enforcing matches name the deciding rule. Put exceptions before broader
rules: an earlier `DENY` can shadow a later `ALLOW`, just as an earlier
`ALLOW` can shadow a later `DENY`. This holds for ICS rules too. IEC 104
objects are decided among IEC 104 rules only, so a broad
`ALLOW` on TCP 2404 does not admit them (see
[IEC 104 fields and matching](ics-dpi.md#iec-104-fields-and-matching)).

The ruleset warnings (below) name a terminal rule when an earlier unconditional
terminal matches all of its traffic (`shadowedBy`). Effects and monitor rules
cannot shadow decisions. The check is conservative: coverage by several rules
together is not reported, and IEC 104 rules are checked only against earlier
IEC 104 rules.

The firewall table displays configured order, with ↑/↓ controls beside each
position number for admins. The arrows are disabled at the ends and during a
move. Keyboard focus follows the moved rule; at an end it switches to the
remaining enabled direction. **Move to…** also supports top, bottom, before
or after another rule. Moves stage changes; commit to apply them.

A read-only **Default** row stays last, even with no configured rules. It applies
to any zone and protocol when no enforcing `ALLOW`, `DENY` or `RESET` rule
decides. Matching `TAG`, under-limit `RATE_LIMIT` and Monitor rules can fall
through to this default. Its action comes from the
same candidate revision as the listed rules: an empty or omitted action means
`DENY`, `ALLOW` carries an unmatched-traffic warning, and an unreadable or
revision-mismatched default is shown as **unknown**, never assumed to deny.
This row has no edit, delete or move controls.

New rules default to the bottom; creation can instead select top, bottom,
before or after another rule. Editing keeps a rule's slot. Templates append
their ordered rules and can report a warning when an earlier terminal shadows
an addition. CLI syntax is in [CLI](cli.md).

The rule editor preserves all saved source zones, destination zones and
protocols, including when only the description or logging changes. Its simple
controls edit the first entry in each list; additional entries remain unchanged
and can be inspected under **All saved matching values**. For multi-valued
lists, the removal option explicitly removes only the first entry and retains
the others; it does not change the match to any zone or protocol. To edit entire lists,
use the **Staged** JSON editor in Configuration and review the diff before commit.
An empty protocol list continues to mean any protocol.

| Action | Decides | Effect |
| --- | --- | --- |
| `ALLOW` | yes | Accepts the packet. |
| `DENY` | yes | Drops the packet. |
| `RESET` | yes, as `DENY` | Rejects back to the sender: a TCP reset for TCP, ICMP or ICMPv6 destination unreachable (administratively prohibited) otherwise. |
| `RATE_LIMIT` | no | Drops the packets over `rateLimit` for each directional 5-tuple; a packet under the limit continues to the decision. |
| `TAG` | no | Labels matching flows and their events with `tag`; no kernel effect. |

`RESET`, `RATE_LIMIT` and `TAG` act on a rule's L3/L4 scope and take no ICS
protocol: the engine owns the resets of inspected ICS connections (aborted IEC
104 sessions and connections picked up mid-stream), and an ICS rate or label
is not defined. `RESET` cannot be the default action. Inside NFQUEUE
inspection the engine cannot reject a queued packet, so a `RESET` rule that
decides an inspected ICS message drops it like `DENY`. TCP denials use the
session-only reset and tombstone path described in
[Enforcement](dataplane-enforcement.md#capture-is-not-inline-enforcement);
they do not install a host or service block.

`RATE_LIMIT` is a kernel packet policer, keyed by source and destination
address, layer-4 protocol and, for TCP and UDP, both ports; on IPv4 and IPv6.
`packetsPerSecond` is 1 to 1,000,000; `burst` is the bucket depth in packets, 0
to 1,000,000, where 0 means `packetsPerSecond`. It meters every packet of a
flow, established ones and replies included, before NFQUEUE and IEC 104
steering: a flow is matched by its connection's original tuple, as its first
packet was, and each direction has its own bucket. A packet without usable
connection tracking state is matched as a connection's first packet. It never
admits traffic. Each rule's meter tracks up to 65,536 tuples per address family
and key; a tuple expires once idle long enough to refill its bucket, and while
a meter is full, new tuples pass unmetered until entries expire. A rule with
sources or destinations meters the address families they name.

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
at zero, and the response says when (`since`). These are rule-path counters,
not total connection traffic: established packets can use the admission fast
path without incrementing an `ALLOW` counter, and ICS counters measure steering.

### Established connections and policy changes

A stateful firewall remembers admitted connections so established traffic can
take a fast path. That state is not a permanent permission: mainstream stateful
firewalls also re-match existing sessions when policy changes.

When a commit changes the policy, the next packet of each established
connection is evaluated again against the new first-match policy, using the
connection's original tuple. If the new policy no longer admits it, the packet
is dropped; unmatched traffic follows `firewall.defaultAction`, which is
`DENY` unless configured otherwise. Reordering or removing an `ALLOW`, or adding
an earlier `DENY`, can therefore stop traffic without waiting for a new
connection.

Re-evaluation does not delete the kernel conntrack entry. The Sessions page and
`GET /api/v1/conntrack` can still show the tuple until the kernel times it out;
an entry's presence does not prove that traffic is passing.

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
each client message, and nftables on the rest of the connection: replies and
the server's own packets.

The conditions also apply to established connections, in both directions.
When a binding is removed or a window ends, a connection that only a
conditional `ALLOW` admitted stops passing. A connection that an unconditional
`ALLOW` decides under the current ordered policy keeps passing. When a scheduled
`DENY` window opens, it stops established connections for which it is the first
matching enforcing terminal. The current policy decides those
connections again by their original tuple, and connections outside the scope of
any conditional rule keep the established fast path. This includes ICS
connections steered to the engine: once a conditional ICS `ALLOW` no longer
admits a connection, its replies and server packets stop too.

### Rules that match nothing

A rule matches nothing when no bound address satisfies its identities, when
none of its source or destination zones has an interface, or when its sources
and destinations share no address family. A `viaForwards` rule also matches
nothing if none of its referenced candidate forwards can match. It is reported
as a warning with its rule ID, the predicate (`identity`, `zone` with the
`zones` concerned, `addressFamily`, or `forward`), the action and the effect, in:

- The firewall page's **Generated firewall configuration (nftables)** preview,
  which lists the candidate's warnings. Expand **Generated ruleset** for the
  full low-level configuration; **Technical details** retains runtime reasons
  and queue-ownership caveats.
- `GET /api/v1/dataplane/ruleset`: `warnings` for the candidate and
  `engineStatus.warnings` for the last applied ruleset; any authenticated user
  reads the applied `warnings` through `GET /api/v1/dataplane/ruleset/status`.
- The rule editor's **Preview impact**, and `warnings` in the
  `POST /api/v1/firewall/rules/preview` response, for the previewed rule.

The rule impact preview evaluates a schedule at each event's time. It takes
identities from the running bindings, so it shows what the rule would match if
today's bindings had applied to the retained events.

DPI mode resolves per-rule `ics.mode` > global `dpiMode` > `monitor`. Monitor
rules never admit or block; enforcing rules, strict scopes and independent kernel
decisions can still block traffic. See [DPI modes](ics-dpi.md#dpi-modes) for shadow
evidence, counter lifetime and upgrade behavior. IEC 104 uses a dedicated
inspection envelope with default-deny
object evaluation, even if the generic firewall default is allow. See
[ICS predicates and modes](ics-dpi.md#ics-firewall-rule-predicates) and
[Enforcement](dataplane-enforcement.md).

Native [IDS rules](ids-rules.md) evaluate decoded events and generate alerts;
these are distinct from firewall decisions. Learned allowlist rules require
review, candidate staging, and commit.

## Port-forward publication and deletion

A port forward translates traffic; it never admits it by itself. Firewall
policy still decides delivery. Rules can restrict matching to connections
translated by specific forwards with `viaForwards`; other selectors use the
original client and translated backend service, not the public listen port.

The NAT page, wizard and CLI publish through the admin-only
`POST /api/v1/firewall/port-forwards` endpoint:
`{"forward": {...}, "allowRule": true}`. The forward and any generated allow
rule are staged in one atomic candidate mutation. `allowRule` defaults to true.
The response contains `forward` and a `placement` explaining the decision:

- `generated`: no enforcing ICS scope overlaps. A matching `viaForwards`
  `ALLOW` rule is inserted before existing terminals, retaining stable
  forward-ID order among leading grants. The response includes the rule and
  its zero-based `index`; UI and CLI positions are one-based.
- `inside`: an enforcing ICS rule's transport scope fully covers the forward.
  No allow rule is generated and no warning is needed; `ruleIds` identify
  governing ICS rules. Their semantic predicates and ordered policy still
  decide delivery, so this is not a promise of admission.
- `partial`: overlap is partial or cannot be proved safe. Permission generation
  fails closed: **no allow rule is generated for any of the forward's traffic**,
  including traffic outside the inspected subset. `warning` explains the
  affected sources, ingress, backend zones and service. Existing inspection
  rules and defaults stay unchanged; current policy decides delivery. Review
  that policy explicitly rather than assuming the forward opens a path.

Set `allowRule: false`, uncheck **Create matching allow rule**, or use CLI
`no-allow` to publish translation only. The response then omits `placement`.
Review the result and commit to activate it.

The admin-only `DELETE /api/v1/firewall/port-forwards/{id}` atomically removes
the forward and removes its ID from every rule's `viaForwards`. A rule whose
list becomes empty is deleted, regardless of action, rather than becoming an
unrestricted rule. Rules retaining other forward IDs are edited. The response
lists `deletedRuleIds` and `editedRuleIds`; the UI confirms those effects before
deletion. Deletion is staged and also needs a commit.

`POST /api/v1/firewall/nat` remains a pure replacement, not a publication or
cascading deletion operation. A replacement leaving dangling `viaForwards`
references is rejected.

## Templates and preview

The four templates at `GET /api/v1/templates/ics` comprise two Modbus variants,
one DNP3 example, and one CIP example. There is no IEC 104 template.
`POST /api/v1/templates/ics/apply` stages their rules. Purdue and maintenance
window templates belong to the general `/api/v1/templates` registry and its
`/apply` endpoint. The maintenance window template stages scheduled L4 `ALLOW`
rules that open Operations (L3) access to the L1, L0 and L2 zones on Saturdays
and Sundays from 02:00 to 06:00 America/New_York (see
[Identity and schedule predicates](#identity-and-schedule-predicates)).

Applying a template with `mode: "enforce"` is refused while
`dataplane.nfqueueGroup` is 0, as for any ICS rule in enforce mode.

Use `POST /api/v1/firewall/rules/preview` to inspect matches before committing;
preview counts this one rule in isolation, not its position among other rules,
and is not a live packet-delivery test. Forward warnings use the candidate's
forwards, while zones and identities use the engine's running inputs. For a rule
limited by `viaForwards`, historical match counting is unavailable: retained
events do not record which connections containd translated. The response
explains this in `unavailable`; the UI hides counts and samples. Warnings and
ICS coverage remain available. For a rule with an ICS protocol it
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
