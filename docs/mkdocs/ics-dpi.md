# ICS/OT Deep Packet Inspection

containd has **12 native Go protocol decoders: 4 ICS + 8 IT**. Live capture and
PCAP analysis share `DefaultDecoders()`. ICS marker and port detector are two
additional utility registrations, not protocol decoders. Decoding a field does
not make it an enforceable firewall predicate.

## DPI Modes

DPI mode resolves **per-rule `ics.mode` > global `dataplane.dpiMode` > `monitor`**.
Both fields accept `monitor`, `enforce` or empty. Empty means inherit; a mode
without an ICS protocol is invalid. Editors show **Inherit (effective mode)**,
**Monitor (safe)** and **Enforce**. Staging a change does not apply it: commit
candidate configuration to activate it. You can enforce directly; monitoring
and learning are optional, not prerequisites.

- **Monitor (safe)** observes every matching rule independently. A monitor rule
  never admits, drops, holds or resets traffic, including an `ALLOW` rule. It
  opens no fail-closed envelope. Other enforcing rules, firewall defaults and
  strict enforce scopes can still deny that traffic.
- **Enforce** applies policy inline. ICS rules resolving to enforce require a
  nonzero `dataplane.nfqueueGroup`; AF_PACKET capture only observes copies and
  cannot stop the first command. Candidate save, import and commit validate this.
  A global enforce setting with no enforcing ICS rules needs no queue.

Monitor-only traffic needs DPI, its decoder and capture:

- With `dataplane.nfqueueGroup: 0`, AF_PACKET observes packet copies passively.
  Monitor rules add no packet steering.
- With a nonzero queue group, monitor-only ICS traffic still passes through the
  engine's single NFQUEUE capture source. The engine feeds the decoder once,
  then immediately releases the packet back to the ruleset without a monitor
  hold. An observation mark prevents repeat queueing through any ICS queue rule.
  Later L4 rules, established-connection handling and the default policy decide
  its outcome as if no ICS rules applied. Monitoring therefore adds engine
  traversal and processing latency, but does not change that outcome. No queue
  bypass is enabled: engine-down queue behavior is unchanged, and monitoring
  does not guarantee forwarding when the engine is unavailable.

When an enforcing ICS rule or scope also applies at L3/L4, its enforcing policy
still decides the packet; monitor matches remain independent observations.
Disabled DPI/decoders, exclusions and capture loss limit observations. Enforce
mode alone does not prove protection either:
see [ICS rule coverage](dataplane-enforcement.md#ics-rule-coverage).

### Shadow evidence and applied-policy counters

Each matching monitor rule emits `ics.decision` with `decision: would_allow` or
`would_drop`, `mode: monitor`, `ruleId`, configured `action` and `reason: rule`,
even when rule logging is off. These are **rule-local matches, not predictions
of the full policy**: monitor ALLOW cannot mask an enforcing DENY, and monitor
DENY does not override an enforcing ALLOW. Enforcing decisions keep their usual
logging behavior. Events use bounded retention, not an all-hit durable journal.

Strict nonconformance is decided on the enforcing scope/envelope before rule
arbitration. A scope drop has reason `nonconformant`, `scopeId` and `findingCode`,
not a monitor rule's ID or configured action. A matching monitor rule additionally
records its own shadow decision. A monitor-only strict scope never drops or resets.

Firewall and ICS tables show shadow matches, would-allow and would-deny for the
**applied policy**, with a start timestamp and links to
`/events/?kind=ics.decision&ruleId=<id>&mode=monitor`. Authenticated viewers can
read `GET /api/v1/firewall/shadow-counters` independently of nftables counters:

```json
{"available":true,"snapshotVersion":"policy-id","since":"2026-10-30T12:00:00Z","unit":"messages","rules":[{"ruleId":"trial","shadowMatches":12,"wouldAllow":10,"wouldDeny":2}]}
```

One hit is **one matching monitor rule × one decoded message**, not one object
in a multi-object message. Every effective-monitor ICS rule in the installed
snapshot is listed, including zero counts; enforce rules are omitted. A
candidate monitor rule absent from that list is **not applied yet**, not zero.
Editing predicates under an existing rule ID leaves its applied counts unchanged
until installation. Counters reset on successful snapshot installation, remain
on failed apply, and are lost on engine restart. The snapshot ID and `since`
identify the applied counter lifetime. Before first apply or when the engine is
unreachable the endpoint returns HTTP 200 with
`{"available":false,"reason":"..."}`; unavailable never means zero.

### Upgrade and downgrade

Schema 0.1.9 rewrites exact legacy `learn` modes to `monitor` in running,
candidate and previous banks; meaningless protocol-less modes are cleared.
Upgrade records one durable `config.rule_modes.migrated` audit record per bank,
with `changes[]` entries containing `path`, `ruleId`, `action`, `old` and `new`.
Repeated boots do not create duplicate records. Legacy versionless input is
upgraded before validation; new rule writes and configurations stamped 0.1.9 or
newer reject `learn` rather than accepting an alias.

**Traffic behavior changes:** a former learn ALLOW inside an enforce envelope
could admit at L7 and mask an enforce DENY under the legacy evaluator. As monitor
it does neither: that traffic is now denied (and reset where the envelope resets).
A former learn DENY no longer drops at L4 without a queue. Audit existing rules
and arrange separate enforcing/L4 allowances where observation needs traffic.
The current schema is 0.1.10, which also migrates rule order and port-forward
permissions to first-match policy; see
[ordered policy upgrades](config-format.md#ordered-policy-upgrades).
Back up before upgrading: 0.1.36 and earlier cannot read schema 0.1.10; restore
a pre-upgrade backup to downgrade.

Monitoring is observation, **not learning**. It never starts evidence collection.
See [Learning](#learning) for the separate explicit workflow.

If the AF_PACKET NAT resolver loses a packet to queue or byte pressure, passive
DPI and identification decoding stop for that connection incarnation, including
retransmissions and the reverse direction. Forwarding and existing verdicts do
not change. A `dpi.coverage.loss` event and the fixed-label
`containd_dpi_coverage_losses_total` counter report lost coverage. Decoding resumes
only at the existing new-SYN/conntrack-generation boundary, not after an idle
decoder reset. If a loss cannot be indexed at capacity, already-started
unindexed streams conservatively stop at their next worker packet too.

## Configuration and protocol toggles

Use the Firewall page's DPI configuration UI or the authenticated management API.
Read `GET /api/v1/dataplane`, edit the returned object, then post the **complete
replacement object** to `POST /api/v1/dataplane`. Preserve capture, queue, and
other settings: this endpoint replaces candidate dataplane configuration, not a
partial patch. Commit with `POST /api/v1/config/commit` to activate changes.
See [Config Format](config-format.md) for the lifecycle and wire schema.

The following is a field excerpt to merge into that object, not a complete
replacement request:

```json
{
  "dpiEnabled": true,
  "dpiMode": "monitor",
  "dpiIcsProtocols": {
    "modbus": true,
    "dnp3": true,
    "iec104": true,
    "cip": false
  }
}
```

The four supported industrial decoders are Modbus/TCP, DNP3, IEC 60870-5-104
and CIP/EtherNet/IP. CIP is optional and can be disabled. An omitted protocol
toggle leaves its decoder enabled. `dpiProtocols` controls the IT decoders
separately. Enabling a decoder does not create a policy rule. For saved
configurations affected by removed protocol support, see
[upgrade recovery](config-format.md#unsupported-protocols-during-upgrade).

## Parsing modes

`dataplane.dpiIcsParsing` sets parsing independently for `modbus`, `dnp3`,
`cip` and `iec104`. Each value is `tolerant` (the default) or `strict`.
An omitted map, omitted key or empty value means tolerant. Unknown protocol
names and other values are rejected. Existing configurations become tolerant
without migration. Stage settings in **Firewall → Deep Packet Inspection →
ICS Protocol Decoders → Configure**, or POST the full candidate dataplane
document to `/api/v1/dataplane`, then commit to apply.

For example, this fragment selects strict IEC 104 parsing and leaves the other
protocols tolerant (merge it into the full dataplane document before posting;
the endpoint replaces, rather than patches, that document):

```json
{"dpiIcsParsing": {"iec104": "strict"}}
```

Parsing governs nonconformant content **inside a frame whose length is known**,
such as a nonzero Modbus protocol ID, bad DNP3 data-block CRC, reserved bits,
truncated PDU or unknown CIP command. Decoded fields remain available to policy;
unreadable fields stay absent. A rule never matches a function code or object
class that was not decoded. When the addresses a message touches cannot be
bounded, an `ALLOW` with an address range does not match it, but a `DENY` or
`RESET` with an address range does.

Some framed content is not inspected at all and is reported separately in the
event's `undecoded` codes (`<proto>.<reason>`), not as a conformance violation.
Policy handles these findings like conformance findings: tolerant parsing
leaves delivery to normal rule and default-action evaluation; the finding itself
does not cause a drop. Strict parsing in an enforce scope drops and resets the
message, while strict monitor scope records a would-drop decision without
affecting delivery. Either finding type raises a medium-severity IDS alert
(`ics-conformance` or `ics-undecoded`), deduplicated per connection and code. If
an event has both keys, it can produce both alerts, while policy still decides
delivery once. Events with either finding are excluded from actionable learner
suggestions.

| Effective rule mode | Tolerant parsing | Strict parsing |
| --- | --- | --- |
| Enforce scope | Evaluate decoded fields as usual; pass unless policy denies | Drop the packet and reset the session; decision reason `nonconformant` |
| Monitor scope | Rules observe; no on-wire effect | Report `would_drop`; no on-wire effect |

Strict nonconformance in an enforcing scope preempts rule decisions and is attributed to that scope. Tolerant is not a policy bypass:
under an allowlist, an unreadable field cannot satisfy an ALLOW that names that
field, so the message falls to the default action. A broader ALLOW using only
readable fields can still match.
TCP resets are best effort and connection-scoped; UDP denials drop only the
datagram, without a session reset.

Conformance findings carry sorted, unique `conformance` codes such as
`iec104.unsupported_type`; uninspected content uses `undecoded` instead.
Both modes raise an `ids` / `alert` with rule ID
`ics-conformance` or `ics-undecoded`, respectively, severity `medium`,
flow identity, codes and the action taken
(`passed`, `dropped and reset` or `would drop`). Alerts are bounded to one per
connection per code; repeats only count. Events with findings never produce
actionable learner suggestions, but inventory and telemetry still record them.

**Both modes fail closed in enforce scope** when a frame boundary is lost:
Modbus length outside 2–254, bad DNP3 start or header CRC, invalid IEC 104 start
or length, or oversized CIP encapsulation. They also fail closed on integrity
faults: midstream pickup, retransmission with different bytes, decoder panic,
queue unavailability, buffer or out-of-order overflow, a missing decoder, and
IEC 104 hold timeout. These faults reset the session, not a host/service block;
tolerant does not scan for a new frame boundary or recover that session.

IEC 104 malformed/profile-violating content with a known APDU length reaches
the rules with decoded fields and an alert in tolerant mode; strict drops and
resets it. Reserved APCI control bits with a readable length are conformance
findings. An unsupported Type ID is still a decoded type byte: tolerant rules
decide it, with an `iec104.unsupported_type` finding. Changing parsing applies
to new decisions after the config push, not by resetting existing sessions
solely because their parsing mode changed.

## Transport identity and NAT

Live AF_PACKET DPI events and their derived alerts carry an optional
`transportConnectionId`. It identifies a locally tracked TCP/UDP connection
incarnation across the original and reply conntrack tuples, including source
port remapping. It is separate from the directional `flowId`, IEC 104
`session_id` and CIP's numeric `connection_id`. Published IDs are never renamed.
Events retain their observed wire addresses and ports; `/flows` remains
directional and includes the shared transport ID rather than regrouping it.
Existing IEC 104 `session_id` grouping is unchanged.
If one directional rollup contains differing evidence or incarnations,
`correlationStatus` is `mixed`, and differing transport IDs are omitted.

`correlationStatus` describes identity evidence: `resolved`, `wire`,
`zone_unverified`, `unsupported_zone`, `unsupported_tuple`, `not_found`,
`lookup_error`, `lookup_timeout`, `ambiguous`, `admission_timeout`,
`cache_capacity` or `queue_overflow`. Authority or lookup failures downgrade
status without removing an issued ID or changing the incarnation's pairing
key. A history without a public ID can adopt verified identity, including its
pending requests; previously published events are not rewritten. PCAP and
NFQUEUE report `wire`: they retain wire-connection pairing without claiming
live conntrack evidence or querying it.
With `correlationStatus: resolved`, ICS policy uses the pre-SNAT client
(`Original.Source`) and post-DNAT backend (`Reply.Source`), including their
ports. Zones, identities, TAG labels and DPI exclusions use these same
coordinates, matching nftables forward-chain rules after DNAT and before SNAT.
For example, a rule for client → backend TCP/502 governs both observed legs
of public TCP/1502 → backend TCP/502, and verified service ports select Modbus.
Inventory and learning use that same client/backend authority.

Without verified evidence, policy and legacy decoder selection use the wire
coordinates. This includes PCAP, NFQUEUE and unresolved or downgraded live
connections; inspect the event's `correlationStatus` above. A NAT egress leg
that exposes a supported service port can decode and reach rule/default
policy in wire coordinates before verification. An unverified public TCP/1502
leg does not select the legacy Modbus decoder. Passive protocol identification
is independent of that port selection.

Newly verified evidence can select a decoder on a flow that has not selected
one yet. An already selected decoder/stream is not switched midstream; policy
uses the evidence available for the current packet, but previously emitted
events and decisions are not rewritten. A new connection starts selection
afresh. Retained-event rule preview remains wire-based because retained events
do not carry the kernel evidence used for live policy.

RST injection always uses the observed packet-space addresses and ports.
When verified evidence is available, conntrack deletion uses the kernel's
`Original` tuple, not the translated egress tuple. Without verification it
uses the packet tuple as before. Only the default conntrack zone is supported.

Modbus pending requests are keyed by connection incarnation, request
direction, transaction ID and unit ID. Coverage requires observing the
incarnation's opening SYN being admitted to inspection and correlation, not
merely tracked as a wire packet or seen as a request. Excluded openers do not
grant coverage. Deliberately bypassed packets extend the recovery timeout on an
already-correlated incarnation, without broadening inspection or changing
wire-based exclusions. An unknown reply with verified
identity and complete coverage raises a protocol violation. Known pairs still
match when capture began midstream or evidence is unavailable.
Missing identity or capture coverage instead raises an
`ids` anomaly with `anomaly_type: correlation_unavailable` and a
`correlation_status` reason. These reasons also include `capture_incomplete`,
`pending_capacity`, `pending_incomplete`, `wire_identity_missing` and
`tuple_mismatch`. Pending state is capped at 4,096 connections and 256
transactions per connection, expires transactions after two minutes, and is
cleared on connection close or reuse. Correlation-unavailable anomalies are
emitted at most once per incarnation, while unavailable observations continue
to be counted. After an actual observation loss, unmatched
claims re-arm only after a full two-minute quiet pairing timeout since the
latest gap, and only if the opening SYN was captured. Thus transactions that
could predate a gap cannot cause unmatched claims; detection is not disabled
permanently. An AF_PACKET resolver queue or byte overflow is different: it
stops decoding for the rest of that connection incarnation (see
[DPI Modes](#dpi-modes)), so pairing resumes only on a new incarnation, not
after the quiet timeout.

Only default conntrack zone zero is supported. The resolver reads
`nft -j list ruleset` at startup, after containd's ruleset applications and
reconciliations, and every five seconds. It includes all tables and families,
including other applications' rules. Any `ct zone` assignment or xt `CT`
target prevents zone-zero authority; read errors leave it unverified. Each
read has a 500 ms deadline and runs in a separate goroutine, never blocking
packet processing. Ruleset apply invalidates authority immediately and requests
an asynchronous recheck after completion; each packet uses an immutable
evidence snapshot. Routine successful reads preserve authority and cached
identities while in flight. Errors or detected zone setters revoke authority.
An evidence downgrade gates unmatched claims until evidence is verified again,
but does not itself count as packet loss or start a recovery timeout.
This is periodic namespace observation, not
synchronization with external ruleset writers; an external change can take
until the next check to be detected. Conntrack zones are not firewall
interface policy zones.

Only traffic selected for industrial DPI enters correlation admission; other
traffic follows normal packet processing without a CT lookup.
Capture admission never performs network I/O or waits for a lookup. One
worker owns exact GETs, O/R aliases and correlation processing. Its 25 ms
timestamp reorder window lets an earlier request from another capture
interface precede a reply, including requests queued during a lookup.
Admission holds at most 512 packets and 4 MiB of payload. Overflow loses an
observation, not a forwarded packet. Every drop increments `queue_overflow`,
but emits at most one `dpi.correlation.unavailable` event per second. This
kind carries `correlationStatus: queue_overflow`, the matching
`correlation_status` attribute, wire endpoints, directional `flowId` and
protocol/transport hints when known, and an already-known transport ID.
It does not claim payload decoding. Loss is scoped to the affected tuple and
incarnation, not unrelated connections. A new-ISN SYN reserves its own loss
history immediately at admission, including while it waits in the reorder
window; retransmissions retain that history. Backlogged
packets older than 500 ms degrade to unavailable evidence. The alias cache
holds at most 16,384 aliases, revalidates positive entries after one second
(or the shorter kernel timeout), and prunes negative entries at their 100 ms
expiry. Each miss sends one direction-agnostic exact GET with a 100 ms native
deadline, within a 200 ms resolver budget; confirmation waits for a later
packet, never a worker retry sleep. No table dump or per-packet lookup occurs
on cache hits. A separate bounded 16,384-tuple loss index survives lookup TTL
expiry and reclaims a connection's aliases directly on close or expiry, without
scanning the index on capture admission. Dropped-only, unbound histories become
evictable once two minutes have passed since their latest loss. The existing
activity-driven flow sweep, triggered by packet processing when 30 seconds have
elapsed since its last run, removes them. It never removes a queued/in-flight
token or a live connection's history.
`coverage_index_reclaimed` counts those expired unbound entries removed.

While the index is full, affected connections cannot claim complete coverage;
`coverage_capacity` counts unindexed observations. After capacity is reclaimed,
an already-started connection must regain indexing and wait a full two-minute
pairing timeout, with no further loss or inspection bypass, before unmatched
replies can alert again. This still requires an inspected, admitted opening SYN;
midstream-only captures do not acquire complete coverage by waiting. A new
connection with a fully inspected opening SYN after capacity returns can claim
coverage immediately. No worker restart is needed after a stopped flood.

The engine ruleset status includes `transportIdentity` for live AF_PACKET
capture. `zoneStatus` is `verified`, `zone_unverified` or `unsupported_zone`;
`zoneCheckedAt`, `zoneError` and `zoneSetters` describe the last read.
Sparse cumulative `counters` include:

- Authority: `zone_checks`, `zone_read_errors`, `zone_setter_checks`.
- Resolution: `lookups`, `cache_hits`, `resolved`, `not_found`,
  `lookup_error`, `lookup_timeout`, `ambiguous`, `unsupported_zone`,
  `unsupported_tuple`, `zone_unverified`.
- Admission and correlation: `queue_overflow`, `admission_timeout`,
  `cache_capacity`, `coverage_capacity`, `coverage_index_reclaimed`, `canceled`,
  `correlation_unavailable`.

The `modbus` object reports `matched`, `unmatched`, `unavailable`, `capacity`
and `expired` totals plus current `pendingConnections` and
`pendingTransactions`. `unavailable` counts observations, while
`correlation_unavailable` counts emitted anomalies; `queue_overflow` counts
every dropped observation regardless of event rate limiting.
Missing sparse counters mean zero. These are
observation-health signals, not inline enforcement readiness.

## DPI exclusions

`dataplane.dpiExclusions` accepts `ip`, `cidr`, and `domain` entries. Each
entry has a `type` and `value`; commit the candidate to activate changes.
IP and CIDR exclusions match either endpoint.

Domain values are exact DNS names such as `updates.example.com`, or suffix
wildcards such as `*.example.com`. Matching ignores case and one trailing dot.
A wildcard matches subdomains, **not the apex**: add `example.com` separately.
Use ASCII DNS labels (punycode for internationalized names); URLs, ports,
embedded wildcards, spaces and IP literals are not domain values.

The engine decides a connection once, at its **first client payload-bearing
packet**:

- If that packet contains a complete TLS ClientHello with visible SNI, only
  that SNI decides. A nonmatching SNI keeps inspection enabled even when DNS
  associated the destination IP with an excluded name.
- Otherwise, a live observed DNS association for the destination IP decides.
  An A or AAAA answer can associate the queried name and CNAME targets within
  that response. The minimum TTL along each CNAME path is clamped to 30 seconds
  through one hour.

Handshake-only packets use normal inspection selection. Later DNS answers,
later SNI, or DNS expiry do not reverse a cached decision; the decision applies
to both directions. Packets inspected before the decision remain inspected.
Decisions live with the engine's tracked flows; association-cache eviction
does not reverse them. The association cache holds at most 16,384 IP/name pairs
and evicts the least recently used pair at capacity. Reconfiguration clears
domain associations and flow decisions.

**Shared IP warning:** without a deciding SNI, every new connection to an
associated IP can skip DPI, including non-TLS traffic for other names on that IP.
TLS SNI provides precision only when present in the deciding packet. Observation
is packet-local: split TLS ClientHellos or TCP DNS messages are not reassembled
for exclusion decisions. A split ClientHello therefore uses DNS at its first
payload and cannot be corrected by later SNI.

The engine observes ordinary DNS responses from port 53 and TLS ClientHellos
on any TCP port whenever a domain exclusion is configured, even if DNS/TLS
event decoders are disabled. Encrypted DNS (DoH/DoT) does not expose DNS answers;
ECH does not reveal the encrypted server name. These mechanisms do not provide
associations for hidden names. This is passive, unauthenticated DNS observation,
not a hostname-authentication boundary.

Domain exclusions **never bypass IEC 104 inspection or its enforcement
envelopes**. Existing IP/CIDR overlap validation remains in force for IEC 104
enforce rules. For other protocols exclusions stay allowed: an IP or CIDR
exclusion that meets a rule's addresses, and any domain exclusion, make the
rule report partial coverage (see
[ICS rule coverage](dataplane-enforcement.md#ics-rule-coverage)).

The existing DPI protocol statistics expose flow-hit totals in `eventCount`
under `dpi_exclusion_sni` and `dpi_exclusion_dns`, and capacity-eviction totals
under `dpi_domain_cache_eviction`. These are reason counters, not decoded
protocols or packet counts. Debug logging names the matched exclusion value
and selection reason.

## Protocol decoders

| ICS protocol | Usual port | Decoder package |
| --- | --- | --- |
| Modbus/TCP | TCP 502 | `pkg/dp/ics/modbus` |
| DNP3 | TCP 20000 | `pkg/dp/ics/dnp3` |
| IEC 60870-5-104 | TCP 2404 | `pkg/dp/ics/iec104` |
| CIP/EtherNet/IP | TCP 44818, UDP 2222 and 44818 | `pkg/dp/ics/cip` |

The eight IT decoders live in `pkg/dp/itdpi`: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP,
and RDP. Protocol events carry `proto`, `kind`, `flowId`, timestamp, and a decoder-
specific attribute map. Inspect emitted events before authoring attribute-based
[IDS conditions](ids-rules.md).

### Decoded event fields

`GET /api/v1/events` returns decoded events with IDs encoded as decimal JSON
strings. A Modbus read of ten holding registers looks like this:

```json
{
  "id": "1",
  "flowId": "192.168.10.20|192.168.20.5|49152|502|006|0",
  "proto": "modbus",
  "kind": "request",
  "attributes": {
    "address": 0,
    "function_code": 3,
    "ics": true,
    "is_write": false,
    "quantity": 10,
    "raw_hex": "00010000000601030000000a",
    "transaction_id": 1,
    "unit_id": 1
  },
  "timestamp": "2026-10-26T09:14:02.123Z",
  "srcIp": "192.168.10.20",
  "dstIp": "192.168.20.5",
  "srcPort": 49152,
  "dstPort": 502,
  "transport": "tcp"
}
```

Live ICS events also carry `ics: true`. Where present, `raw_hex` holds at most
the first 512 payload bytes (IEC 104: the APDU). An attribute is present only
when the decoder found its value. The tables list what each ICS decoder emits;
the value in brackets is the event's `proto`.

`coverage_incomplete: true` marks a DNP3 fragment or CIP operation whose
contained objects or operations were not fully inspected. The attribute is
omitted on fully covered messages; it is separate from `conformance` and
`undecoded` findings. See [Incomplete inspection](#incomplete-inspection).

| Protocol | `kind` values | Attributes |
| --- | --- | --- |
| Modbus/TCP (`modbus`) | `request`, `response`, `exception`, `malformed` | `transaction_id`, `unit_id`, `function_code`, `is_write`, `raw_hex`; data-access fields per function code (see [ICS Firewall Rule Predicates](#ics-firewall-rule-predicates)): requests `address` with `quantity` (1–4, 15, 16; plus `byte_count` for 15, 16), `value` (5, 6), `and_mask`, `or_mask` (22), or `read_address`, `read_quantity`, `write_address`, `write_quantity`, `byte_count` (23); read responses `byte_count` and, for registers, `register_count`; write responses the fields they echo; `sub_function`, `sub_function_name` (code 8; sub-functions 1, 3, 4, 10 and 20 are writes; supported names cover 0–4, 10–18 and 20); invalid per-sub-function layout is `modbus.pdu_layout`; unknown sub-functions are reported as undecoded `modbus.diagnostics_subfunction`; `mei_type` (code 43), `mei_type_name` (MEI type 14); `exception_code`, `exception_description` (exceptions, with `function_code` set to the base code); `error` (malformed) |
| DNP3 (`dnp3`) | `request`, `response`, `restart` (codes 13, 14), `control` (codes 18, 19), `malformed` | `function_code`, `function_name`, `is_write`, `is_control`, `source_address`, `destination_address`, `direction` (`master` or `outstation`, from the link DIR bit), `iin_flags`, `object_groups`, `qualifier`, `object_count`, `objects` with point records that may include an `index` and decoded `crob`, `link_ranges`, `transport_segments`, `application_fragment`, `application_complete`, `raw_hex`; `error` (malformed), `conformance` and `undecoded` codes (listed below) |
| IEC 104 (`iec104`) | `apci`, `request`, `response`, `malformed`, `unsupported` | See below |
| CIP/EtherNet/IP (`cip`) | `request`, `response`, `session` (EtherNet/IP commands without a CIP message) | See below |

The DNP3 decoder reassembles transport segments and tracks multi-fragment
application responses. Events for a completed transport fragment ride on its
finishing link frame; `link_ranges` identifies the constituent physical link
frames, while `raw_hex` remains the finishing physical frame rather than a
synthesized application payload. Application fragments are decoded
independently: earlier TCP packets are not held back and whole-response
prevention is not atomic. Point records preserve indices only when present
(absence is not index zero); group 12 variation 1 CROBs expose their encoded
control, operation, trip/close, queue/clear, count, on/off times and status.
The fragment event carries `coverage_incomplete: true` when the object walk
stops at an unknown, unsupported, size-prefixed, free-format or truncated
layout, a reserved range code or an inspection budget. Readable headers and
partial point lists remain in `objects`, including each header's `covered`
byte count; a partial point list also marks coverage incomplete.

DNP3 conformance codes are `dnp3.data_crc`, `dnp3.application_header`,
`dnp3.object_walk`, `dnp3.crob_value`, `dnp3.link_duplicate`,
`dnp3.link_retry_conflict`, `dnp3.transport_duplicate`,
`dnp3.transport_conflict`, `dnp3.transport_orphan`, `dnp3.transport_sequence`,
`dnp3.transport_restart`, `dnp3.application_control`,
`dnp3.application_duplicate`, `dnp3.application_sequence` and
`dnp3.application_restart`. Header CRC failures instead fail frame parsing.
Undecoded codes are `dnp3.link_payload`, `dnp3.transport_incomplete`,
`dnp3.application_incomplete`, `dnp3.assembly_limit`, `dnp3.assembly_budget`,
`dnp3.object_limit`, `dnp3.object_qualifier`, `dnp3.object_truncated` and
`dnp3.object_unsupported`. Inspection bounds are 64 KiB application bytes,
1024 link segments per fragment, 1024 application fragments per response,
4096 station contexts, 16 MiB retained storage (including payload, duplicate
bytes, provenance and context charges), 1024 object headers per fragment and
8192 point records total. Incomplete transport/application assemblies expire
after 30 seconds idle or 60 seconds absolute.

IEC 104 events carry `direction` (`request` from the client, `response` from
the server), `session_id`, `apdu_id`, `apci_type` (`I`, `S` or `U`) and
`raw_hex`. Further attributes depend on the frame:

| Frame | Attributes |
| --- | --- |
| S-format | `class: system`, `is_write: false`, `receive_sequence` |
| U-format | `class: system`, `is_write: false`, `u_function` (`startdt_act`, `startdt_con`, `stopdt_act`, `stopdt_con`, `testfr_act`, `testfr_con`) |
| I-format | `send_sequence`, `receive_sequence`, `type_id`, `class`, `vsq`, `object_count`, `sq`, `cause`, `cot_negative`, `cot_test`, `originator`, `ca`, `is_write` |
| Information object | `ioa`, `object_index`, and by type `value`, `quality`, `qualifier`, `select`, `transient`, `value_invalid`, `source_time`, `time_valid`, `time_summer` |
| Malformed or unsupported | `error` and `conformance`, with the identity attributes the decoder could read |

An I-format APDU emits one event per information object. Types outside the
supported set emit `unsupported` with a conformance finding; parsing mode and
rules determine the verdict, not the event kind alone.
When a role-violating ASDU's layout decodes, it still emits every object,
each as `malformed` with the role finding and its own IOA and object index.
The existing APDU-length and object-count limits bound this emission.

CIP events report each EtherNet/IP layer as attributes. The protocol name `cip` covers the whole EtherNet/IP stack: one decoder toggle
and one protocol match. The name `enip` is rejected at rule, signature, Sigma
and toggle boundaries with: `EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`.

TCP CIP on port 44818 is reassembled and framed per EtherNet/IP encapsulation,
including split headers and bodies and multiple encapsulations in one segment.
UDP is packet-only, without stream reassembly. CIP inspection on port 2222 is
UDP-only; TCP/2222 is containd's default SSH service port, not CIP. UDP port
2222 carries implicit I/O
datagrams: a bare Common Packet Format with a sequenced address item and a
connected data item, decoded as one `session` event with `connection_id`,
`sequence`, `data_length` and `cpf_item_types`, never a service code. A
datagram whose item list cannot be read carries the `cip.cpf_layout` finding.
UDP port 44818 carries encapsulation commands such as ListIdentity, decoded like TCP.

| CIP event layer | Attributes |
| --- | --- |
| Encapsulation | `enip_command` (name), `enip_command_code`, `enip_session_handle`, `enip_status`, `enip_sender_context`, `enip_options` |
| Implicit I/O (UDP 2222) | `connection_id`, `sequence`, `data_length` (whole connected data item), `cpf_item_types` |
| Common Packet Format (CPF) | `cpf_item_count` (declared item count); `cpf_item_types` (item types in packet order as one comma-joined lowercase hex string with no spaces); plus selected item `cpf_item_index`, `cpf_data_item_type`, and, when available, `connection_id`, `connected_sequence` |
| CIP | `service_code`, `service_name`, `function_code`, `is_write`, `is_control`, `cip_path`, `cip_target` (requests: `logical`, `symbolic` or `unknown`), `cip_symbol` (symbolic targets only, an array of symbol-name segments), `object_class`, `object_class_name`, `instance_id`, `attribute_id`, `address`; responses retain `response_reserved`, `general_status`, `additional_status_count` and `additional_status` when present; MSP parents carry `multi_service_count` and `multi_service_decoded_count`; each child carries `msp: true`, `msp_index` and `msp_index_path`; incomplete wrappers and roots with uninspected extra CPF data items carry `coverage_incomplete: true` |

Every CIP request operation, including MSP children, carries `cip_target`. Supported logical paths name a class, optionally an instance,
then at most one attribute, member or connection point, using 8/16-bit segments.
Symbolic paths contain one or more ANSI `0x91` symbols with optional 8/16-bit
element segments; `cip_symbol` preserves the symbol segments in order, without
element indexes. Repeated logical segments, mixed logical/symbolic paths,
32-bit segments and other unsupported paths are `unknown`, never truncated to
a supported target. Partial logical fields can remain as telemetry but do not
make an unknown target known. Responses have no wire target and carry no `cip_target`, so object
selectors (class, instance, attribute, tag) never match a response.

CIP access classification uses the request's own complete, supported EPATH,
not the service number alone. `is_write: false` identifies a supported read;
writes and controls carry `is_write: true`, with controls also carrying
`is_control: true`. Unknown operations, structural wrappers and uncorrelated
responses carry neither flag. They match neither `readOnly` nor `writeOnly`.
Protocol statistics count them as events but not reads or writes; event totals
need not equal the sum of reads, writes and alerts. Learning retains CIP
observations but offers no actionable CIP suggestions.

Common reads `0x01`, `0x0E` and `0x18` require empty bodies. `0x03` requires
a nonempty, exact-length list of attribute IDs. `0x0D` is Apply Attributes
(write), `0x19` is Set Member (write), and `0x15` is Restore (write).
Reserved codes and `0x14` as an EtherNet/IP request are unknown; `0x11`
Find Next Object Instance is named but its body is not supported.

Object-specific codes depend on class. The supported Logix profile recognizes
ANSI-symbolic paths consisting only of nonempty `0x91` segments and optional
8/16-bit member segments, or Symbol class `0x6B` instance addressing.
`0x4C` Read Tag requires exactly a nonzero 16-bit element count; `0x52`
Read Tag Fragmented requires that count plus a 32-bit byte offset.
Symbol `0x55` requires a nonempty, exact-length attribute-ID list.
Template class `0x6C` instance `0x4C` requires a 32-bit offset and 16-bit
byte count, not a tag-read body. Symbolic `0x4E` is Read Modify Write
(write); Connection Manager class `0x06`, instance 1, `0x4E` is Forward
Close (control). Class `0x06` `0x5B` is Large Forward Open (control), not a
read. `0x4C` on File `0x37`, Connection Configuration `0xF3`, TCP/IP `0xF5`,
Ethernet Link `0xF6` and Device Level Ring `0x47` is a write or control.

Incomplete, ambiguous, unsupported or mixed symbolic/logical paths never
classify as reads. Logical IDs wider than 16 bits and program-scoped browse
prefixes are unsupported. Unconnected Send bodies, CM query bodies
(`0x56`, `0x57`, `0x5A`), Modbus bridge reads/passthrough, PCCC commands,
File upload transfers without file association, and Connection Configuration
Get Status remain unknown. MSP (`0x0A`) is structural; children have their own
categories. Per-child classification is not whole-message authorization or
proof that a rule covers every route, child, attribute or element range.
Responses require separate reply policy because request correlation is absent.

MSP sub-events retain encapsulation and CPF/response metadata; inspection is
bounded to 32 children total and nesting depth 8. CIP wire violations carry
`conformance` codes: `cip.unknown_command`, `cip.encapsulation_length`,
`cip.cpf_layout`, `cip.item_truncated`, `cip.message_short`,
`cip.epath_truncated`, `cip.msp_layout`, `cip.response_reserved` and
`cip.msp_response_mismatch`. Protocol structure the decoder did not walk
carries `undecoded` codes: `cip.msp_limit`, `cip.msp_nesting`,
`cip.epath_unsupported`, `cip.extra_data_item`, `cip.cpf_item_unsupported`
(unknown CPF item types only) and `cip.encapsulation_payload_unsupported`
(bodies of unknown encapsulation commands). Attribute values, service
parameters and reply data, known command bodies and known CPF metadata items
are data of a decoded operation and carry no undecoded code. Non-CPF commands such as
RegisterSession have no `cpf_item_types`. The encapsulation fields replace
`command`, `command_code` and `session_handle`; CIP events do not emit aliases.

For a `cip` IDS rule, this condition matches a connected-data CPF item using
`contains "0x00b1"`:

```json
{"field": "attr.cpf_item_types", "op": "contains", "value": "0x00b1"}
```

The TLS decoder emits a `client_hello` event with `sni`, `alpn`,
`tls_version`, `cipher_suites`, `extensions`, `ja3`, `ja3_hash`, `src_port`,
`dst_port` and `transport`. `ja3` follows the JA3 layout but is **not
reference JA3**: it holds the ClientHello version, at most 50 cipher suites and
the extension types. GREASE values are not removed, and the elliptic-curve and
point-format fields are always empty. `ja3_hash` is the MD5 of that string. Do
not compare it with JA3 values from other tools. `tls_version` is the
ClientHello version field, so TLS 1.3 clients usually show `TLS1.2`.

## ICS Firewall Rule Predicates

Firewall rules contain an `ics` object. Generic predicates for protocols other
than IEC 104 are:

| JSON field | Meaning and limits |
| --- | --- |
| `protocol` | `modbus`, `dnp3`, or `cip` |
| `functionCode` | Array of numeric function/service codes, 0–255; evaluated from `function_code` |
| `unitId` | Optional Modbus unit ID, 0–255; evaluated from `unit_id` |
| `addresses` | Modbus register/coil or DNP3 point-index array of entries, each one value or an inclusive `low-high` range (see below); evaluated against the addresses the message touches |
| `masters`, `outstations` | DNP3 station addresses, 0–65519; reserved 65520–65535 are rejected |
| `groups`, `variations` | DNP3 object-header groups and variations, 0–255 |
| `objectClasses`, `instances`, `attributes` | CIP logical target selectors, 0–65535 |
| `tags` | CIP symbolic tag-path list; cannot combine with logical target selectors |
| `readOnly`, `writeOnly` | Read/write class from an explicitly present `is_write`; not both true |
| `direction` | `request` or `response`; omit for both |
| `mode` | `monitor` or `enforce`; omit to inherit global mode |

Modbus and DNP3 access classification uses explicit known operations. Unknown
operations omit `is_write` and `is_control`, so they match neither `readOnly`
nor `writeOnly`. These attributes describe function semantics, not successful
execution or whole-message conformance.

| Protocol | Read (`is_write: false`) | Write/control (`is_write: true`) |
| --- | --- | --- |
| Modbus | FC 1–4, 7, 11, 12, 17, 20, 24; FC 8 sub-functions 0, 2, 11–18; FC 43 MEI type 14 (Read Device Identification) | FC 5, 6, 15, 16, 21, 22, 23; FC 8 sub-functions 1, 3, 4, 10, 20 |
| DNP3 | FC 0 (Confirm), 1 (Read), 23 (Delay Measure); known responses 129–131 retain their non-write classification | FC 2 (Write); FC 3–22 and 24–33 are controls, also carrying `is_control: true` |

Other function codes, private/vendor extensions such as Modbus FC 90, unknown
FC 8 sub-functions, and FC 43 MEI types other than 14 are unknown, not reads.
MEI 13 (CANopen General Reference) is not inherently read-only. Modbus replies
use their own function/subtype; exceptions use the base function but have no
diagnostic or MEI subtype, so FC 8/43 exceptions remain unknown. DNP3 response
codes outside 129–131 remain unknown even though their high bit identifies a
response-form header. Response access is not inferred from request correlation.
DNP3 `restart` events identify FC 13/14; kind `control` identifies only FC 18/19.
Other control operations retain kind `request` while carrying `is_control: true`.

Each `addresses` entry is one value (`256`, `0x0100`) or an inclusive range
`low-high` (`100-511`, `0x0100-0x01FF`). Values are unsigned decimal or hex with
a `0x` prefix, may mix within a range, and may have spaces around them. A range
needs low <= high. Modbus addresses are 0–65535 (`0xFFFF`).
Validation refuses any other entry, such as
`0x01G0`, `-5` or `0x200-0x100`, and names the rule and the entry. A stored
configuration with such an entry starts in management recovery until a valid
configuration is committed.

DNP3 `addresses` selects **point indexes**, not station addresses, and requires
nonempty `groups`. Its closed ranges use the same syntax, with endpoints
0–4294967295. CIP rejects `addresses`; use logical target selectors or tags.
DNP3 and CIP reject `unitId`: neither decoder emits a Modbus unit identifier.
Stored invalid predicates remain visible in management recovery until explicitly
repaired and a valid configuration committed. IEC 104 uses `ca` and `ioa` instead.

A message touches a set of address spans. A Modbus request touches the span
from its starting address for its quantity: function codes 1–4, 15 and 16 name
a start and a quantity, 5, 6 and 22 one address, and 23 a read span and a write
span. On an `ALLOW`, `addresses` holds a message only when every span it touches
lies inside the listed entries, which may together cover a span. A read of
address 11 count 8 therefore matches neither `10-11` nor `11`, but matches
`10-20` or `10-11` plus `12-19`. On a `DENY`, `addresses` holds a message when
any span it touches shares an address with an entry. A message with no address
(Modbus diagnostics, device identification, other function codes that address
no data) matches no `addresses` predicate. A Modbus request whose span cannot be
bounded matches every `DENY` with `addresses` and no `ALLOW` with `addresses`:
an unknown or unlisted function code (including file record and FIFO access), a
PDU whose length does not fit its function code, a quantity outside the
protocol's limits (1–2000 bits, 1–125 registers read, 1–1968 coils or 1–123
registers written, 1–121 registers written by function code 23), a byte count
that disagrees with the quantity, or a span past 65535. So is a message from the
connection's opener that the decoder does not decode as a request. Modbus replies
carry no request address: a read reply touches no address, and a write reply
touches only the address and quantity it echoes.

DNP3 indexes come from each object header: start/stop qualifiers name a span,
and index-prefix qualifiers name individual points. Virtual, all-objects and
count-only qualifiers have unknown point indexes; an address-qualified ALLOW
fails and an address-qualified DENY matches those unknown indexes.

Modbus events carry only fields present on the wire: requests have `address`
with `quantity` (function codes 1–4, 15, 16, plus `byte_count` for 15 and 16),
`value` (5, 6), `and_mask` and `or_mask` (22), or `read_address`,
`read_quantity`, `write_address`, `write_quantity` and `byte_count` (23).
Requests for function codes 15, 16 and 23 also carry a `values` array when all
declared write values are available: coil bits for 15, register words for 16
and 23. Read replies have `byte_count` and, for registers, `register_count`;
write replies have the fields they echo.

Example: a monitor rule observing Modbus reads of holding registers 0–99
(function code 3) on unit 1, over TCP 502 from the `lan` zone to the `dmz` zone.
Its `ALLOW` action records would-allow matches, not admission:

```json
{
  "id": "modbus-read-setpoints",
  "sourceZones": ["lan"],
  "destZones": ["dmz"],
  "protocols": [{"name": "tcp", "port": "502"}],
  "ics": {
    "protocol": "modbus",
    "functionCode": [3],
    "unitId": 1,
    "addresses": ["0-99"],
    "direction": "request",
    "mode": "monitor"
  },
  "action": "ALLOW"
}
```

With `mode: "enforce"` the rule needs a nonzero `dataplane.nfqueueGroup` (see
[DPI Modes](#dpi-modes)).

### Object, station and target matching

Fields are ANDed; members within each list are ORed. An omitted selector means
ANY. A selector whose value is absent does not match either ALLOW or DENY,
except for the explicitly unknown cases below. Each DNP3 object header and each
CIP operation is evaluated independently through firewall
[precedence](policy-model.md#actions-and-precedence): the first matching
enforcing terminal in configured order wins, otherwise the default action
applies. Monitor rules never decide. **Any denied object denies the
message**; different ALLOW rules may cover different objects. Modbus retains
whole-PDU span containment in a single rule. A complete CIP Multiple Service
Packet wrapper is a container, not an operation; only its children are judged.
An earlier broad L3/L4 ALLOW can therefore shadow a later generic ICS DENY;
ruleset warnings identify full coverage by an earlier unconditional terminal.
IEC 104 retains its separate inspection envelope below.

DNP3 masters/outstations apply only to application messages, never link-only
frames. Link DIR identifies the master (source when DIR=1, destination when
DIR=0). Groups and variations come from **every** object header, not only the
first. Omitted variations mean ANY. Wire variation 0 satisfies ALLOW only if 0
is listed; any constrained DENY matches wire variation 0. Selector 0 does not
match concrete nonzero variations.

CIP logical targets support 8- and 16-bit class/instance/attribute segments;
32-bit segments and unsupported or mixed paths are unknown, never truncated.
Instance-enumerating services (0x11 and class 0x6B service 0x55) have unknown
instances. Attributes are known only for single-attribute services 0x0E/0x10 and
member services 0x18/0x19. Unknown instance/attribute selectors fail ALLOW and
match DENY. Object facts and unknown-object flags apply only to CIP service
operations. Non-operation encapsulation events and implicit I/O retain message
facts but have no object facts or unknown flags, so a rule with an object
selector matches neither ALLOW nor DENY. If a SendRRData/SendUnitData data item
exists but its CIP operation cannot be decoded, or an unknown encapsulation
command carries a payload, coverage is unknown: object-selector DENYs match
and ALLOWs do not. Read-only requires positive read evidence; controls are
writes, never reads, and structural/unknown services satisfy neither access
constraint.

Tag paths are dot-separated names (`Motor.Speed`, `Program:Main.Motor`): each
name matches `[A-Za-z_][A-Za-z0-9_]*`, at most 40 characters; only the first
segment may have `Program:`. Brackets are not accepted in selectors. Comparison
is case-insensitive by segment; target element indexes are ignored (all elements
and subtrees are selected). ALLOW requires the selector to be a prefix of the
target. DENY matches either prefix direction, so denying `A.B` also overlaps an
operation on aggregate `A`. **Logical targets never match a tag selector**, even
instance-addressed Symbol class 0x6B access. A tag DENY does not protect that
access; prefer tag ALLOW lists with default deny.

### Incomplete inspection

A message not fully inspected adds an **unknown-object context**, with only
message-wide facts (L3/L4, protocol, direction, DNP3 stations). DNP3 retains its
fragment-wide function code and access category; CIP MSP coverage contexts have
neither, because inner services are unknown. This includes incomplete/unsupported
DNP3 object walks, partial point lists and reserved qualifiers, incomplete CIP
nested MSP decoding or uninspected CPF data items. Decoder events mark
`coverage_incomplete: true`, omitted otherwise. Each incomplete MSP wrapper
carries the marker, including ancestors of an incomplete nested wrapper:
declared/decoded count mismatches, service/depth budget exhaustion and
`cip.msp_layout` all mark incomplete coverage. Uninspected extra CPF data items
mark the root operation, not its already inspected children.
An ALLOW with any object selector fails this context; a DENY with any object
selector matches it. Function, access, station, direction and L3/L4 constraints
still apply: this is not an unconditional denial. An ALLOW must omit object
selectors; for CIP MSP coverage it must also omit function and access constraints.
Unknown-object handling overrides only the object-selector conjunction, not
other fields.
IEC 104 retains each decoded object, including role-violating ASDUs.

Create/replace rejects explicit `null` or `[]` for the new selector fields;
omit them for ANY. The general `/firewall/rules/{id}` merge PATCH uses `null`
to clear any known ICS key (including old IEC fields), omission to retain it.
The `/firewall/ics-rules/{id}` PATCH replaces the whole rule: omitted selectors
become ANY. Editors preview the full effective predicate, not the null-bearing
PATCH delta.

Strict nonconformance is rejected before ALLOW matching as described in
[Parsing modes](#parsing-modes). `RESET`,
`RATE_LIMIT` and `TAG` rules take no ICS protocol.

### IEC 104 fields and matching

With `protocol: "iec104"`, use these fields instead of the generic selectors:

| JSON field | Meaning and limits |
| --- | --- |
| `typeIds` | Numeric array, 1–255; enforce `ALLOW` accepts only descriptor-backed types |
| `classes` | Array drawn from `monitor`, `control`, `system`, `unknown`; enforce `ALLOW` cannot include `unknown` |
| `ca` | Common-address array, 0–65534; broadcast 65535 cannot be named |
| `ioa` | Inclusive ranges such as `[{"start": 0, "end": 100}]`, endpoints 0–16777215, no overlaps |
| `cot` | Cause-of-transmission list, 1–63 |
| `originators` | Originator address list, 0–255 |
| `negative`, `test` | Exact P/N and T flags; `false` is a restriction, not omission |
| `commandStates` | SCS 0–1 for Type IDs 45/58, or DCS/RCS 1–2 for 46/47/59/60; requires explicit Type IDs in one domain group |
| `commandQualifiers` | QU 0–31 (bits 2–6); requires explicit Type IDs contained in 45/46/47/58/59/60 |
| `selectExecute` | `select` or `execute`; Type IDs must be omitted or contained in 45–50, 58–63 (51/64 have no S/E) |
| `readOnly` | Restrict to the decoder's safe-read set; false means no read constraint, not writes-only |
| `direction`, `mode` | Same spellings and mode inheritance as above |

Command state/qualifier fields exist only on I-frame objects of the six
command types. Constrained rules never match objects missing these fields,
for any action. Duplicate list values are permitted, as for `cot`.

Omit a list to match any value. Present IEC lists reject `null`, empty arrays,
and null members. IOA entries require exactly `start` and `end`. Predicate keys
are case-sensitive; unknown or duplicate keys are rejected. IEC 104 rejects
`functionCode`, `unitId`, `addresses`, `objectClasses`, and `writeOnly` by presence,
even with a zero/false value. All protocol-specific fields are rejected on other
protocols. COT, originator,
P/N, T and S/E selectors require their ASDU values; S/U frames do not carry them.

Supported descriptor Type IDs are 1, 3, 5, 7, 9, 11, 13, 15, 21; 30–37;
45–51; 58–64; 70, 100, 101, 102, 103, 105, and 107. Other types decode as
unsupported with a conformance finding: tolerant evaluates the decoded fields,
including the Type ID, against the rules; strict drops and resets in enforce
scope. Unsupported does not mean implicitly allowed.

IEC 104 conformance codes: `iec104.apci_length`, `iec104.body_length`,
`iec104.element`, `iec104.ioa_range`, `iec104.profile_sq`,
`iec104.reserved_bits`, `iec104.role`, `iec104.short_asdu`, `iec104.time`,
`iec104.u_function`, `iec104.unsupported_type`, `iec104.zero_objects`.
Nonconformant content is never safe-read, so a `readOnly` ALLOW does not admit
it. A malformed event without a code is a lost frame boundary or stream fault
and is denied in enforce scopes; monitor-only scopes remain observational.

Safe-read includes S/U frames, response-direction monitoring, general
interrogation (100), request-direction read (102), and end of initialization (70).
It excludes control commands/confirmations, counter interrogation, clock sync,
reset process, timed test, malformed/unsupported events, and broadcast CA.

Enforcing IEC 104 rules define an L3/L4 inspection envelope. Monitor-only rules
open no fail-closed envelope. Inside an enforce envelope, object decisions use
only enforcing IEC 104 rules in configured order. The first matching terminal
decides; an object with no match is denied. Matching monitor rules additionally
record shadow evidence without changing this decision. A broad TCP/2404 allow rule
or a generic allow default cannot bypass it. In tolerant mode, malformed or
profile-violating content with a known length can match an `ALLOW` on fields
that were decoded; absent fields never satisfy a predicate. Strict rejects
nonconformance before ALLOW matching. Broadcast objects cannot match an
`ALLOW`. ASDU predicates, identity, and schedules do not narrow the envelope itself.

## Learning

Learning records observations and offers certified suggestions; it never changes
running policy. The **PCAP Analysis** page (`/pcap`) is the single review surface
for imported captures and explicit live watches. Monitoring alone does not start
collection. Observation is not authorization, even when the traffic was delivered.

### Collect, generate, review, stage

1. Import a classic PCAP with **Analyze**, or start a **Live watch** after configuring
   capture/DPI. Analyze returns a dataset, not generated rules. Live watch defaults
   to one hour, is capped at 24 hours, and allows only one active watch. **Stop**
   seals its dataset; engine restart stops collection and never resumes a watch.
2. Open the dataset. Inspect source, capture hash, decoder/profile/snapshot
   fingerprints, record/byte counts, expiry and gaps. Both sources use the same
   engine-owned evidence store. **Inspect service authority** shows service
   endpoints, direction, wire/logical coordinates, role certainty and coverage.
3. For a sealed dataset, explicitly **Generate suggestions**. Review the proposed
   endpoint/service and protocol selectors, withheld-reason counts, limitations,
   and **Certified evidence (frozen)**: positive replay, negative boundary tests,
   evidence digest and evaluator/generator versions. A rule's **Preview live recent
   evidence** is a separate isolated impact check against recent retained events;
   it does not recertify the frozen suggestion or simulate the whole policy.
4. IEC 104 requires an explicit authenticated administrator **Review** before
   selection. Wire-coordinate PCAP suggestions also require acknowledgement that
   the captured pre-NAT addresses and service match the intended deployment.
   Review records approval of the exact revision; it does not select or stage it.
   Selection starts empty and is never approval. Viewers can inspect evidence but
   cannot import, collect, generate, review, select or stage.
5. **Stage selected** sends one `POST /api/v1/learn/apply` containing a request ID
   and selected suggestion IDs/revisions, not editable rule payloads. The server
   reloads certified content and stages the entire bundle atomically. Stale,
   expired, conflicting, uncertified or unreviewed selections are refused; a
   `409` rejects the whole batch, displays the server reason and refreshes the
   suggestions. The maximum is 128 suggestions and 128 total rules per request.
   If completion is uncertain after a network/engine error, retry the **same
   request ID and ordered selections**: the candidate may already be staged.
   Retries use the resolved snapshot for seven days from resolution, even after dataset deletion, eviction or expiry; after that, the request ID is unknown.
   Completion failures after candidate persistence return a retryable `503`
   naming the request ID, not a rejection.
6. Reviewed suggestions stage as explicit `ics.mode: "monitor"` ALLOW rules,
   including IEC 104. Review the candidate diff and use the normal **Commit** or
   **Commit-confirmed** bar to apply them. Committed monitor rules do not authorize
   traffic. Enforcing a learned rule requires a deliberate candidate mode edit
   and another commit; a global mode change cannot override explicit monitor.
   The staged receipt is not evidence that the rule is active.

Existing `learned-*` rules may overlap a suggestion. Warnings are heuristic only:
the learner never deletes or replaces policy by an ID prefix. Review and remove
unwanted legacy rules yourself, through candidate edits and commit.

### Exactness and limits

Exact means exact within the supported selector relations, not byte-for-byte
transaction equality. Generation retains correlated endpoint/service, direction,
unit/station, operation and span/object constraints. The certifier evaluates
referenced parents and negative boundary mutations against the shared rule
evaluator, without transmitting packets. Large repeated relations are split into
proofs of at most 512 positive parents, keeping each frozen suggestion within
storage and replay budgets while retaining normalized evidence and the same
selectors. Relations requiring aggregate closed-domain coverage carry their
selector witnesses into every fragment; oversized witness sets are withheld for
budget limits, never split into unjustified rules.
Every positive is replayed; equivalent negative boundary inputs are replayed once
per proof. Capture time remains part of boundary identity for scheduled rules.
Finite replay is evidence, not a proof of universal protocol correctness. Malformed, incomplete, undecoded,
nonconformant or authority-less parents cannot yield actionable suggestions.

- **Modbus:** supported bounded request spans keep their unit and function code.
  FC23 read/write roles, unbound diagnostic subtypes and unexpressible write
  values/masks are withheld rather than broadened.
- **DNP3:** supported master/outstation, function, group/variation and bounded
  point relations are certified together as needed. All-objects, count-only,
  wildcard variation, indexless controls and unexpressible values are withheld.
- **IEC 104:** supported commands only, always admin-reviewed and staged as
  monitor. Single, double and regulating-step commands (45/46/47/58/59/60)
  bind each observed state and QU qualifier alongside IOA and select/execute;
  even a partial observation can certify without admitting unobserved tuples.
  Setpoint values/QL, bitstrings and select-before-operate sequences remain
  withheld. Monitoring ASDUs, APCI/startup behavior and broadcast CAs
  do not become command ALLOWs. Use deliberate policy/templates for startup.
- **CIP:** observations are retained, but no actionable CIP rules are offered.
  Content identified on nonstandard service ports remains observation-only.

Evidence persists in the engine's sibling SQLite store (`/data/evidence.db`,
override with `CONTAIND_EVIDENCE_DB`) across restarts and expires after seven days
by the store clock. Ceilings are 32 datasets, 100,000 records and 128 MiB of
normalized evidence; each parent is limited to 256 KiB and 4,096 objects. Loss,
rejection, eviction, expiry and withheld reasons are exposed, not silently
interpreted as complete coverage. Recorded collection or admission loss excludes
every connection it could have touched from generation and direct certification.
Known-connection loss excludes that incarnation; coordinate-scoped loss excludes
matching wire tuples or host pairs across every incarnation, in either direction.
Live observations retain both verified original/reply NAT aliases, so loss on
the opposite wire face still excludes request-only or response-only evidence.
Identity and scope are additive. Parents and losses retain `captureHook`
(`nfqueue` or `afpacket`) when known. NFQUEUE's forward hook observes one
post-DNAT/pre-SNAT face in both directions, so NFQUEUE parents and losses use
wire-only matching even without conntrack verification. An unrelated malformed
frame no longer erases the watch's suggestions; same-tuple loss still excludes
every matching incarnation, and missing ports widen to host pair/transport.
Unverified AF_PACKET parents still cannot prove that their unknown opposite
NAT face escaped a same-transport loss. Missing capture authority remains
conservative unless a complete verified alias pair proves disjointness.
PCAP retains only its observed wire authority.
Retained message times do not prove lifecycle bounds. Legacy timestamp-only loss
and missing scope exclude the dataset. Excluded retained parents count toward
the durable `collection_loss` withheld reason. Connections
fully outside localized loss remain eligible. Restart and policy-change loss
exclude the dataset: store-clock lease bounds cannot safely delimit packet times.
Loss localization is capped at 1,024 entries per dataset; exhaustion collapses to
one dataset-wide loss. Live collection batches parent rows in bounded SQLite
statements and uses a 256-batch queue with a 64 MiB decoded-copy budget to absorb
flush bursts without blocking packet verdicts. Deletion or eviction invalidates
dependent proofs for new stage requests.
Resolved staging snapshots and completed receipts count toward the storage
budget and are purged when their retry window expires. Dataset review shows the
last generation's per-dataset withheld counts; store-wide counters are durable totals.

`GET /api/v1/learn/datasets`, `/learn/watches`, `/learn/suggestions` and dataset
`/observations` reads use bounded pages (`items`, `nextCursor`, maximum `limit`
200). The UI offers **Load more** rather than implying the first page is complete.
Delete a dataset with `DELETE /api/v1/learn/datasets/{id}` when it is no longer
needed. The removed profile/bulk workflow (`GET /learn/profiles`,
`DELETE /learn`, and the old generate/apply bodies) is not supported. See [API Reference](api-reference.md#learner-evidence-and-staging)
and [CLI](cli.md#learner-evidence) for the replacement requests and commands.

IEC 104 tracking shares a **4,096-entry session table** across monitor and enforce
envelopes, including retained closed sessions and abort tombstones. At capacity,
new monitor-mode connections are accepted **without stream inspection**. Each
untracked SYN emits `ics.session` with `outcome: untracked`, `mode: monitor`,
`reason: bound`, and `limit: 4096`, on the client/server tuple without a session
or APDU ID. Midstream traffic stays untracked; existing sessions remain inspected.
New SYNs can be tracked when entries expire. Enforce envelopes remain fail closed
at capacity.

In an enforce envelope a session starts only at a SYN of a handshake that
connection tracking has not seen complete. A SYN sent into an established
connection starts no session. A connection the engine did not see from its SYN
is dropped and reset at both endpoints, so the client reconnects at once.

## Live IEC 104 APCI anomalies

Tracked IEC 104 sessions produce observational `ids` / `anomaly` events in
both monitor and enforce mode:

| `anomaly_type` | Observation |
| --- | --- |
| `iec104_data_while_stopped` | I-frame before STARTDT con or after STOPDT con |
| `iec104_send_sequence` | N(S) gap or backwards step |
| `iec104_ack_sequence` | N(R) outside [last acknowledged, next unsent], modulo 32768 |
| `iec104_test_timeout` | TESTFR act without an opposite-direction TESTFR con within t1 (15 seconds) |

STOPDT act alone does not stop data observation: I-frames remain valid until
STOPDT con. Data-while-stopped alerts occur only on the first offending I-frame
per stopped period; STARTDT con re-arms the alert for the next stopped period.
Sequence checks use the ordered, TCP-deduplicated APDU stream, not
individual packets or information objects. Each alert carries `session_id`,
`direction`, and protocol evidence; frame-triggered alerts also carry `apdu_id`.
Timers run without incoming packets. State is bounded by the session table,
discarded when observation ends, and fresh for each reconnect. These alerts
never change firewall decisions, enforcement health, or learned rules.

## Protocol anomaly detection

The anomaly detector checks every decoded ICS event. Each finding is stored in
the detector and recorded as an `ids` / `anomaly` event with `anomaly_type`,
`protocol`, `severity`, `message`, `source_ip` and `dest_ip`. Findings are
observations only: they never block traffic or change firewall decisions.
Detectors have no tuning controls.

| `type` | Severity | Finding |
| --- | --- | --- |
| `malformed_frame` | medium | An ICS event with an `error` attribute: malformed Modbus, DNP3 or IEC 104 data, an unsupported IEC 104 type, or an IEC 104 role violation |
| `protocol_violation` | high | Modbus write to broadcast unit ID 0 |
| `protocol_violation` | medium | Modbus response whose transaction ID matches no earlier request in the opposite direction |
| `protocol_violation` | critical | DNP3 cold or warm restart (function code 13 or 14) from an outstation |
| `protocol_violation` | high | Every DNP3 unsolicited response (function code 130) |
| `protocol_violation` | high | DNP3 request with an undefined function code (34–127) |
| `protocol_violation` | critical | CIP message with service code 0x07 (Stop), request or reply |
| `protocol_violation` | high | CIP message with service code 0x06 (Start), request or reply |
| `protocol_violation` | high | IEC 104 role violation: a monitor type (1–44) from the client, or a control or system activation/deactivation from the server |
| `rate_anomaly` | high | More than 1,000 ICS events from one source to one destination address in the current and previous clock minute |
| `rate_anomaly` | critical | More than 100 write events (`is_write: true`) in the same window |

These checks use the source and destination IP addresses, not ports. While a
pair is above a rate limit, each further event raises another finding.
IEC 104 rate counts use one event per APDU. The `ids` /
`anomaly` event of a finding
from an IEC 104 event also copies that event's identity attributes, such as
`session_id`, `apdu_id`, `type_id`, `ca` and `ioa`.

`GET /api/v1/anomalies` lists stored findings, newest first. `limit` defaults
to 200; values outside 1–5000 use the default. Each entry has `type`,
`protocol`, `severity`, `message`, `source_ip`, `dest_ip`, `attributes` and
`timestamp`. The detector keeps the 4,096 newest findings. Admins clear the
findings and the detector's tracking state with `DELETE /api/v1/anomalies`.
An engine restart, or a committed change to the `dataplane` settings, also
clears them. The [IEC 104 APCI anomalies](#live-iec-104-apci-anomalies) appear
only as events, not in this list.

## Signatures

The signature engine compares every decoded event with the loaded signatures.
It loads **20 built-in signatures**: 13 for Modbus, DNP3, CIP and ICS write
storms, and 7 for IEC 104. A match is recorded as an `ids` /
`signature_match` event with `signature_id`, `name`, `severity` and
`description`, plus the identity attributes of a matched IEC 104 event.
Matches are observations only and never block traffic.

The built-in `ICS-WRITE-STORM` signature alerts after 20 initiator write
commands on one connection within 10 seconds. Replies and exceptions do not
count, and an IEC 104 APDU with multiple object events counts once.

| Request | Purpose |
| --- | --- |
| `GET /api/v1/signatures` | List the loaded signatures, built-in and custom |
| `POST /api/v1/signatures` | Add a custom signature (admin) |
| `DELETE /api/v1/signatures/{id}` | Remove a loaded signature, built-in or custom (admin) |
| `GET /api/v1/signatures/matches` | List recent matches, newest first; `limit` defaults to 100 |

A custom signature has a unique `id` and at least one condition. `name`,
`description`, `severity`, `protocol` and `references` are optional. An empty
`protocol` matches every protocol; otherwise it must equal the event's `proto`,
in any letter case. All conditions must match. Each condition names a `field`
(`proto`, `kind`, `flow_id` or an attribute name from
[Decoded event fields](#decoded-event-fields)), an `op` and a `value`:

| `op` | Matches when the field |
| --- | --- |
| `equals` (`eq`) | equals the value; numbers compare by value |
| `in` | equals one member of the value array |
| `gt`, `gte`, `lt`, `lte` | compares as stated; both sides must be numbers |
| `contains` | contains the value as text |
| `has_token` | is a comma-separated list or a string list that contains the value as a whole token |
| `regex` | matches the regular expression (Go RE2 syntax) |

Validation does not check `op`; a condition with another `op` never matches.
An optional `threshold` of `count` (at least 2) and `windowSeconds` (at least 1)
alerts once per flow ID when that many events match in one window. The window
starts at the first matching event. The signature does not alert again for that
flow ID until the window has passed.

Two optional threshold fields change what counts:

- `scope`: `flow` (the default) counts each direction of a connection
  separately. `connection` counts both directions of one connection together.
  Events whose flow ID is not a connection tuple keep their own counter.
- `dedupAttr`: an event attribute. Matching events with the same nonempty value
  count once in a window. The built-in write storm uses `apdu_id`. A window
  retains at most 256 values; past that, new values still count but are not
  remembered.

```json
{
  "id": "SITE-MODBUS-WRITE-BURST",
  "name": "Modbus register write burst to unit 1",
  "severity": "high",
  "protocol": "modbus",
  "conditions": [
    {"field": "function_code", "op": "in", "value": [6, 16]},
    {"field": "unit_id", "op": "equals", "value": 1}
  ],
  "threshold": {"count": 10, "windowSeconds": 60}
}
```

`POST` returns `200` with the signature, `400` for an invalid one and `409`
when a loaded signature already has that ID. `DELETE` returns `204`, or `404`
for an unknown ID. Additions and removals are audited as `signatures.add` and
`signatures.delete`.

**Signature changes are live and temporary.** They are not part of the
candidate or running configuration, and export does not include them. An
engine restart, or a committed change to the `dataplane` settings, rebuilds
the signature engine with the built-in signatures. This removes custom
signatures, restores deleted built-in signatures and clears the match list.
The engine keeps the 4,096 newest matches. Each match has `signature`,
`timestamp` and the matched `event`, whose keys are `FlowID`, `Proto`, `Kind`,
`Attributes` and `Timestamp`.

## PCAP Offline Analysis

`POST /api/v1/pcap/analyze` (multipart `file`) and
`POST /api/v1/pcap/analyze/{name}` import normalized evidence through the engine.
They return `{dataset, stats}`; neither endpoint returns profiles or rules.
Only classic PCAP is supported, with a 64 MiB upload ceiling; PCAPng is rejected.

`stats` contains bounded events, flows, content identifications, protocol/count
statistics and capture duration. `stats.truncated` identifies partial,
snap-length-cut or IP-length-truncated records. `stats.displayTruncated` means the display sample was
capped, not that normalized evidence was sampled. Inspect dataset gaps separately:
collection and admission loss exclude every connection they could have touched.
Known loss excludes the authoritative incarnation, or every matching wire
five-tuple incarnation when ports are captured. Without ports, host-pair and
transport scope excludes all matching connections in either direction. First
and last retained messages are not connection lifecycle bounds; timestamp-only
historical loss and missing coordinates exclude the dataset. A short IP/TCP
header therefore cannot leave an earlier parent eligible for certification.
A cut non-IP record with readable EtherType (including VLAN tags), or a known
non-TCP/UDP IP protocol, records non-excluding `capture_unrelated` loss. Opaque
IPv6 extension chains are not proof of unrelated traffic; their IP family comes
from the decoded header, never IPv4-mapped address spelling. A cut opaque chain
(including MLD-style traffic) still excludes the dataset. Ordinary unrelated
ARP/LLDP/ICMP truncation does not erase workshop suggestions. A header-less final
record remains dataset-wide.

Live `capture_loss` is retained at transport admission, before worker processing,
and delivered through AF_PACKET and NFQUEUE even with incomplete TCP headers.
Stop, deadline and policy-change cleanup close parent admission before detaching
loss callbacks and fence those callbacks before sealing;
failed automatic stops retry the retained lease. `watch_collection_loss` and
`budget_exceeded` retain known rejected connections; `watch_restart`,
`policy_changed` and storage/import failures are dataset-wide. Dropped
decision/delivery annotations (`outcome_loss`) are counted but do not exclude
certification inputs. See the
[loss-code scope table](api-reference.md#content-identification-results) for fallbacks.

The internal engine `/internal/pcap/analyze` endpoints use the same import
contract, not a second policy generator. Imports do not update live inventory,
stage candidate rules or commit policy. Use the dataset's explicit **Generate**
and review workflow above. Raw PCAP replay transmits packets and is never used
for certification. See [API Reference](api-reference.md#learner-evidence-and-staging).

## Events and templates

Live telemetry includes inventory, anomalies, signatures, and protocol statistics.
The passive IEC 104 inventory is separate from the learner. Native IDS rules and
the [signature engine](#signatures) are separate consumers; see also
[Protocol anomaly detection](#protocol-anomaly-detection) and
[Decoded event fields](#decoded-event-fields). See
[Logging and Evidence](logging-evidence.md) for bounded retention, queries, and
syslog forwarding.

Four ICS API templates provide two Modbus variants, one DNP3 example, and one
CIP example. There is no IEC 104 template. Purdue and maintenance-window
templates belong to the general registry, not this four-template set. Applying
templates stages candidate changes. The CIP monitor template uses `readOnly`
for its ALLOW and `writeOnly` for its DENY, including control operations.
Unknown and structural operations need separate policy; this template is not a
catch-all DENY. Existing saved template rules are not migrated at startup.
The general template registry skips existing rule IDs; remove old CIP template
rules before reapplying there. The ICS template API stages replacements for
matching IDs. Review the saved rules, default action and reply policy before
enforcing. See
[Policy Model](policy-model.md#templates-and-preview).

The Modbus read-only template allows FC 1–4 and denies listed write functions,
including FC 21 (Write File Record); use default deny to exclude all other
functions. The `dnp3-secure-operations` template is **not read-only**: it allows
FC 0 (Confirm), 1 (Read), 20/21 (Enable/Disable Unsolicited), 23 (Delay
Measure) and 24 (Record Current Time), allows FC 2 (Write) only for groups 50
(time) and 80 (internal indications), and denies FC 13/14 (Restart), 18 (Stop
Application) and 19 (Save Configuration). Review these allowances before
applying it.

## IEC 104 Holdback Diagnostics

The Diagnostics page shows current IEC 104 held packets, held payload bytes,
oldest pending age and active sessions beside the fixed limits. The engine holds
incomplete APDUs until every byte is framed and allowed. Held bytes include
retransmissions. An empty hold queue has zero packets, bytes and age.

Limits are 256 held packets globally, 32 packets and 65,536 payload bytes per
session, a one-second pending timeout, and 4,096 tracked tuple slots. Closed
sessions and abort tombstones occupy slots; replacement handshakes reuse their
slot. Capture shutdown makes active sessions zero, but retained tuple slots can
remain until expiry or rebuild. The shared reset/block worker has 256 queue slots.
There are no tuning controls.

Totals distinguish denied-command aborts from timeouts, saturation, midstream
traffic, stream/framing/transport errors, policy changes and queue closure.
Fail-closed steering rejections and injector-unavailable admission rejections are
also counted per occurrence, not as unique commands. Reset-worker rejections,
inline verdict failures and failed reset-injection attempts are separate totals.
Verdict failures cover the shared inline pipeline as well as rejected IEC
holdback settlement requests; intentional queue-closure completions are excluded.
Totals survive configuration rebuilds and reset only when the engine process
restarts. These diagnostics do not change
packet decisions or the `iec104Enforcement` health object.

Authenticated clients read `GET /api/v1/diagnostics/iec104`. An unavailable engine
returns HTTP 503, not an empty or zero snapshot.

In the default `containd all` deployment (including Compose), engine and
management run in one process and share the Prometheus registry. Scrape the
management listener's `/metrics` for `containd_dp_iec104_*` gauges and counters;
the engine API stays on `127.0.0.1:8081` by default. With separate `engine` and
`mgmt` processes, scrape the engine listener's `/metrics` for dataplane pressure;
the management process has its own registry. Non-loopback engine metrics require
mutual TLS. Export credentials with `containd enginecredentials DIRECTORY` and
configure Prometheus `ca_file`, `cert_file`, `key_file` and
`server_name: containd-engine` as shown in the
[Compose guide](docker-compose.md#diagnostics-and-metrics-credentials). Keep the
network private and the exported client key secret: it authorizes every engine
route until rotation. Metric registration
happens once per process, not once per listener. The series have no
station/session/IP/CA/IOA labels; only the abort counter has a fixed `reason` label.


## Passive IEC 104 inventory

The **Assets** page has a read-only IEC 104 section, separate from configured
assets and learner evidence datasets. It groups controlling stations (clients)
with controlled stations (servers, normally port 2404). Expand a pair to see observed
common addresses (CAs), then expand a CA to see each (IOA, type ID) point and its
first/last observation times. Pair and CA command counters distinguish decoded
client command attempts from accepted commands. Accepted means the IEC decision
allowed the APDU **and every packet carrying its bytes completed an Accept
verdict without error**; an allow decision alone is not delivery evidence.
Acceptance is recorded only in inline enforce envelopes. Monitor and
non-inline capture record attempts and points, but never claim delivery.
Server echoes and monitoring ASDUs do not count as command attempts.

The live feed observes ordered, TCP-deduplicated ASDUs in sessions tracked from
their SYN within IEC 104 envelopes. Untracked, midstream and uninspected traffic
does not populate it. Retransmissions are not new attempts; retransmissions
received while delivery is pending also need successful Accept verdicts.
Acceptance is not a station acknowledgement or proof of physical execution.
Inventory summaries never generate ALLOW rules or enforcement decisions.
During an explicit live watch, the delivery ledger also reports accepted
APDUs to learner evidence; inventory counters are not its input.
Engine unavailability displays an explicit
unavailable state, not an empty inventory or zero counters; **Refresh** retries.

Memory is bounded to 128 endpoint pairs, 32 CAs per pair and 256 (IOA, type ID)
points per CA. The least recently observed entry is evicted at each cap; idle
entries expire after 24 hours on the next observation or read. Reads do not
extend retention. The legacy Modbus/DNP3/CIP inventory is bounded to 1,024 assets,
128 peers and 256 station addresses per asset, with the same asset LRU/expiry.
Overflow counters show capacity evictions, truncated metadata observations and
late command outcomes whose observation has expired or been evicted. Input calls
never wait for the inventory lock: observations or outcomes dropped on contention
have visible overflow counters. Per-session delivery evidence is capped at 128
commands and 128 carrying packet tokens. Ledger overflow records a not-accepted
outcome and increments **Lost outcomes**. Pending evidence expires after one
second, and is freed on session end, abort, queue close, policy removal,
reconfiguration or stop; incomplete evidence never credits acceptance. Counts
are therefore conservative when evidence is unavailable. Oversized
ASDU input is truncated to 127 IOAs and counted as point overflow. Expiry is not
overflow. Counts are retained-history totals, not lifetime traffic or unique
missing-device counts. Clearing inventory or restarting the engine resets data
and overflow totals. See [API Reference](api-reference.md#passive-inventory).

## Content identification

AF_PACKET capture (when DPI is enabled) and offline PCAP analysis identify
Modbus/TCP, DNP3/TCP, IEC 104 and EtherNet/IP encapsulation (CIP) by content,
including on alternate service ports. Disabled ICS protocols are not probed.
Live discovery respects DPI address and domain exclusions. NFQUEUE does not
run content identification. UDP/2222 implicit I/O remains port-selected.

Identification **never changes a verdict or the meaning of rule ports**. The
existing port-selected decoder runs immediately. A confirmed protocol gets a
separate passive decoder only when the legacy path does not already decode
that protocol. These events carry `observation_only: true` and
`binding_source: observation`; they do not enforce rules or generate automatic
ALLOW suggestions. The learner withholds suggestions for nonstandard service-port
observations. Observation-bound connections are excluded from offline and live
policy suggestions, including legacy events emitted before confirmation. A
confirmed content/port mismatch excludes the entire connection incarnation, not
just the passive decoder's events. Generate reports `observation_binding` withheld
counts, and suggestion limitations state this exclusion.

Historical datasets whose adapter discarded binding authority are withheld as
`missing_authority`. Reimporting the same capture after an adapter-normalization
change creates a separate dataset using the current normalization; it does not
rewrite the old, still-readable dataset. With unchanged normalization and
decoding authorities, reimports reuse the existing dataset without extending
retention. Previously certified suggestions require regeneration under the
current generator.

Flows show the bound application, whether identification is by **content** or
only **port**, and a **Mismatch** badge when content differs from a registry
port expectation. Mismatch preserves the original port-selected decoder and
can add passive decoding of the confirmed protocol. **Outside rule ports**
means at least one ICS rule names that protocol but none covers the observed
service transport and port. This checks a single rule snapshot, not source,
destination or other rule predicates; it is not a hypothetical rule hit. A
rule without explicit transport/ports covers only that protocol's registry
ports. PCAP analysis without a rule snapshot reports scope as `unknown`.

Evidence is bounded to 1 KiB per direction, 16 arrivals and 5 seconds per
connection (with bounded entries and total bytes). Only passive decoding
waits for confirmation. The 5-second evidence window is activity-driven:
idle evidence finalizes on the next arrival, sweep, close or PCAP EOF, not on
a promised timer deadline. PCAP deadlines use a nondecreasing capture-time
watermark, so out-of-order timestamps do not rewind the evidence clock. Ambiguous evidence can resolve with later bytes;
exhaustion or EOF yields an incomplete result with candidates retained.
TCP identification requires SYN coverage: midstream capture does not confirm
or start a passive decoder. Truncation, missing bytes, conflicting evidence
and budget exhaustion can leave an identification incomplete. There is no
fallback scan or midstream replay. Identification results and observation-decoded events
retain the capture timestamps. PCAP analysis never increments live metrics.
