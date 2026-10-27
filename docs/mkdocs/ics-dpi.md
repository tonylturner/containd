# ICS/OT Deep Packet Inspection

containd has **12 native Go protocol decoders: 4 ICS + 8 IT**. Live capture and
PCAP analysis share `DefaultDecoders()`. ICS marker and port detector are two
additional utility registrations, not protocol decoders. Decoding a field does
not make it an enforceable firewall predicate.

## DPI Modes

DPI mode resolves **per-rule `ics.mode` > global `dpiMode` > `learn`**. Both
fields accept only `learn`, `enforce` or empty.

- **Learn** records would-deny decisions without applying that DPI denial.
- **Enforce** drops a prohibited command inline, before it reaches the device.
  That needs NFQUEUE: AF_PACKET capture only observes copies and cannot stop
  the first command. Validation therefore rejects a rule that names an ICS
  protocol and resolves to enforce while `dataplane.nfqueueGroup` is 0, at
  candidate save, import and commit; set a nonzero queue or put the rule in
  learn mode. A global `dpiMode: "enforce"` without such rules, and `mode` on a
  rule without an ICS protocol, need no queue.

Enforce mode alone does not prove protection: DPI switched off, a disabled
decoder, nftables enforcement off or an overlapping exclusion each leave a rule
unprotected or partly protected. Each ICS rule reports its actual coverage; see
[ICS rule coverage](dataplane-enforcement.md#ics-rule-coverage).

Global learn mode is **not a no-block switch**: explicit enforce-mode rules and
independent nftables firewall decisions can still block traffic. Automatic
profile collection additionally requires at least one committed firewall entry
with explicit `ics.mode: "learn"`; setting the global mode alone is insufficient.
This gate does not limit collection to only events matching that entry.

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
  "dpiMode": "learn",
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
| CIP/EtherNet/IP | TCP 44818, UDP 2222 | `pkg/dp/ics/cip` |

The eight IT decoders live in `pkg/dp/itdpi`: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP,
and RDP. Protocol events carry `proto`, `kind`, `flowId`, timestamp, and a decoder-
specific attribute map. Inspect emitted events before authoring attribute-based
[IDS conditions](ids-rules.md).

The protocol name `cip` covers the whole EtherNet/IP stack: one decoder toggle
and one protocol match. The name `enip` is rejected at rule, signature, Sigma
and toggle boundaries with: `EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`.

| CIP event layer | Attributes |
| --- | --- |
| Encapsulation | `enip_command` (name), `enip_command_code`, `enip_session_handle` |
| Common Packet Format (CPF) | `cpf_item_types`: all item types in packet order as lowercase hex strings, such as `["0x0000", "0x00b2"]`, on SendRRData/SendUnitData with a valid item list |
| CIP | `service_code`, `service_name`, `function_code`, `is_write`, `is_control`, `cip_path`, `object_class`, `object_class_name`, `instance_id`, `attribute_id`, `address`; MSP parents also carry `multi_service_count`, sub-events carry `msp` |

MSP sub-events retain the encapsulation and CPF fields. Non-CPF commands such as
RegisterSession have no `cpf_item_types`. The encapsulation fields replace
`command`, `command_code` and `session_handle`; CIP events do not emit aliases.

## ICS Firewall Rule Predicates

Firewall rules contain an `ics` object. Generic predicates for protocols other
than IEC 104 are:

| JSON field | Meaning and limits |
| --- | --- |
| `protocol` | `modbus`, `dnp3`, or `cip` |
| `functionCode` | Array of numeric function/service codes, 0–255; evaluated from `function_code` |
| `unitId` | Optional Modbus unit ID, 0–255; evaluated from `unit_id` |
| `addresses` | Array of address entries, each one value or an inclusive `low-high` range (see below); evaluated from `address` |
| `objectClasses` | CIP object-class IDs, 0–65535; evaluated from `object_class`; CIP only |
| `readOnly`, `writeOnly` | Read/write class from an explicitly present `is_write`; not both true |
| `direction` | `request` or `response`; omit for both |
| `mode` | `learn` or `enforce`; omit to inherit global mode |

Each `addresses` entry is one value (`256`, `0x0100`) or an inclusive range
`low-high` (`100-511`, `0x0100-0x01FF`). Values are unsigned decimal or hex with
a `0x` prefix, may mix within a range, and may have spaces around them. A range
needs low <= high. Modbus addresses are 0–65535 (`0xFFFF`); the other protocols
accept 0–4294967295 (`0xFFFFFFFF`). Validation refuses any other entry, such as
`0x01G0`, `-5` or `0x200-0x100`, and names the rule and the entry. A stored
configuration with such an entry starts in management recovery until a valid
configuration is committed.

Only metadata actually emitted by the decoder can satisfy these conditions.
There are no firewall selectors for DNP3 station addresses/object headers, CIP
instance/attribute/EPATH/MSP. Decoder telemetry and IDS attributes are not
additional firewall selector fields.

ICS messages follow the firewall's precedence (see
[Actions and precedence](policy-model.md#actions-and-precedence)): any matching
`ALLOW` admits the message, whatever its position; otherwise the first matching
`DENY` or `RESET` by rule ID denies it. An ICS `DENY` that overlaps any `ALLOW`,
including a plain L3/L4 `ALLOW` on the same port, is therefore shadowed and
never denies anything there; the ruleset warnings name such rules. `RESET`,
`RATE_LIMIT` and `TAG` rules take no ICS protocol.

### IEC 104 fields and matching

With `protocol: "iec104"`, use these fields instead of the generic selectors:

| JSON field | Meaning and limits |
| --- | --- |
| `typeIds` | Numeric array, 1–255; enforce `ALLOW` accepts only descriptor-backed types |
| `classes` | Array drawn from `monitor`, `control`, `system`, `unknown`; enforce `ALLOW` cannot include `unknown` |
| `ca` | Common-address array, 0–65534; broadcast 65535 cannot be named |
| `ioa` | Inclusive ranges such as `[{"start": 0, "end": 100}]`, endpoints 0–16777215, no overlaps |
| `readOnly` | Restrict to the decoder's safe-read set; false means no read constraint, not writes-only |
| `direction`, `mode` | Same spellings and mode inheritance as above |

Omit a list to match any value. Present IEC lists reject `null`, empty arrays,
and null members. IOA entries require exactly `start` and `end`. Predicate keys
are case-sensitive; unknown or duplicate keys are rejected. IEC 104 rejects
`functionCode`, `unitId`, `addresses`, `objectClasses`, and `writeOnly` by presence,
even with a zero/false value. IEC-only list fields are rejected on other protocols.

Supported descriptor Type IDs are 1, 3, 5, 7, 9, 11, 13, 15, 21; 30–37;
45–51; 58–64; 70, 100, 101, 102, 103, 105, and 107. Other types decode as
unsupported, not as implicitly allowed commands.

Safe-read includes S/U frames, response-direction monitoring, general
interrogation (100), request-direction read (102), and end of initialization (70).
It excludes control commands/confirmations, counter interrogation, clock sync,
reset process, timed test, malformed/unsupported events, and broadcast CA.

IEC 104 rules define an L3/L4 inspection envelope. Any matching enforce-mode rule
makes the envelope enforce-mode. Object evaluation uses only IEC 104 rules: any
matching IEC 104 `ALLOW` admits the object, otherwise the first matching IEC 104
`DENY` by rule ID denies it, and no match is denied. A broad TCP/2404 allow rule
or a generic allow default cannot bypass it. `ALLOW` cannot match malformed or
broadcast objects. ASDU predicates, identity, and schedules do not narrow the envelope itself.

## Learn Mode

The generic learner records non-IEC-104 ICS profiles; IEC 104 is excluded from
both automatic learning and asset discovery. Review learned rules before use:
observation is not authorization.

1. Commit an explicit learn-mode firewall entry and configure capture/DPI.
2. Inspect `GET /api/v1/learn/profiles`.
3. Use `POST /api/v1/learn/generate` to return proposed rules for review.
4. `POST /api/v1/learn/apply` stages generated rules in candidate configuration
   (`status: staged`); it does not activate them. Generated rules leave
   `ics.mode` empty, so they inherit the global `dpiMode`: they enforce only
   when the global mode is `enforce`, and staging them is then refused while
   `dataplane.nfqueueGroup` is 0. Set a per-rule mode in candidate to override.
5. Review scope and per-rule modes in candidate, then commit with
   `POST /api/v1/config/commit`. Rule order does not matter: a learned `ALLOW`
   admits its traffic even past a `DENY` listed before it, and any `DENY` it
   overlaps is shadowed (see
   [Actions and precedence](policy-model.md#actions-and-precedence)). Changing
   only global mode does not override an explicit per-rule learn mode.
6. `DELETE /api/v1/learn` clears the profiles when no longer needed.

IEC 104 tracking shares a **4,096-entry session table** across learn and enforce
envelopes, including retained closed sessions and abort tombstones. At capacity,
new learn-mode connections are accepted **without stream inspection**. Each
untracked SYN emits `ics.session` with `outcome: untracked`, `mode: learn`,
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
both learn and enforce mode:

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

## PCAP Offline Analysis

The public management endpoints `POST /api/v1/pcap/analyze` (multipart `file`) and
`POST /api/v1/pcap/analyze/:name` call `AnalyzeForPolicy`. They return analysis
statistics, event summaries, profiles, and generated rules for review. IEC 104
is summarized but never generates permissive learned rules. Results **do not
update live inventory, stage candidate rules, or commit policy**.

The engine's separate `/internal/pcap/analyze` endpoints call `Analyze`, returning
only events, flows, protocol/count statistics, and duration. These internal
endpoints are not the public policy-generation interface. See
[API Reference](api-reference.md) for public requests.

## Events and templates

Live telemetry includes inventory, anomalies, signatures, and protocol statistics.
The passive IEC 104 inventory is separate from the learner. Native IDS rules and the built-in signature engine
are separate consumers. See [Logging and Evidence](logging-evidence.md) for
bounded retention, queries, and syslog forwarding.

Four ICS API templates provide two Modbus variants, one DNP3 example, and one
CIP example. There is no IEC 104 template. Purdue and maintenance-window
templates belong to the general registry, not this four-template set. Applying
templates stages candidate changes; see
[Policy Model](policy-model.md#templates-and-preview).

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
the management process has its own registry. The engine API is unauthenticated:
keep any split-mode listener on a trusted private network. Metric registration
happens once per process, not once per listener. The series have no
station/session/IP/CA/IOA labels; only the abort counter has a fixed `reason` label.


## Passive IEC 104 inventory

The **Assets** page has a read-only IEC 104 section, separate from configured
assets and learned profiles. It groups controlling stations (clients) with
controlled stations (servers, normally port 2404). Expand a pair to see observed
common addresses (CAs), then expand a CA to see each (IOA, type ID) point and its
first/last observation times. Pair and CA command counters distinguish decoded
client command attempts from accepted commands. Accepted means the IEC decision
allowed the APDU **and every packet carrying its bytes completed an Accept
verdict without error**; an allow decision alone is not delivery evidence.
Acceptance is recorded only in inline enforce envelopes. Learn/monitor and
non-inline capture record attempts and points, but never claim delivery.
Server echoes and monitoring ASDUs do not count as command attempts.

The live feed observes ordered, TCP-deduplicated ASDUs in sessions tracked from
their SYN within IEC 104 envelopes. Untracked, midstream and uninspected traffic
does not populate it. Retransmissions are not new attempts; retransmissions
received while delivery is pending also need successful Accept verdicts.
Acceptance is not a station acknowledgement or proof of physical execution.
Inventory never feeds the learner,
auto-ALLOW, or enforcement decisions. Engine unavailability displays an explicit
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
