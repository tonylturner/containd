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

### Decoded event fields

`GET /api/v1/events` returns decoded events. A Modbus read of ten holding
registers looks like this:

```json
{
  "id": 1,
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

| Protocol | `kind` values | Attributes |
| --- | --- | --- |
| Modbus/TCP (`modbus`) | `request`, `response`, `exception`, `malformed` | `transaction_id`, `unit_id`, `function_code`, `is_write`, `raw_hex`; data-access fields per function code (see [ICS Firewall Rule Predicates](#ics-firewall-rule-predicates)): requests `address` with `quantity` (1–4, 15, 16; plus `byte_count` for 15, 16), `value` (5, 6), `and_mask`, `or_mask` (22), or `read_address`, `read_quantity`, `write_address`, `write_quantity`, `byte_count` (23); read responses `byte_count` and, for registers, `register_count`; write responses the fields they echo; `sub_function`, `sub_function_name` (code 8); `mei_type` (code 43), `mei_type_name` (MEI type 14); `exception_code`, `exception_description` (exceptions, with `function_code` set to the base code); `error` (malformed) |
| DNP3 (`dnp3`) | `request`, `response`, `restart` (codes 13, 14), `control` (codes 18, 19), `malformed` | `function_code`, `function_name`, `is_write`, `is_control`, `source_address`, `destination_address`, `direction` (`master` or `outstation`, from the link DIR bit), `iin_flags`, `object_groups` (comma-separated), `qualifier`, `object_count` (first object header), `raw_hex`; `error` (malformed) |
| IEC 104 (`iec104`) | `apci`, `request`, `response`, `malformed`, `unsupported` | See below |
| CIP/EtherNet/IP (`cip`) | `request`, `response`, `session` (EtherNet/IP commands without a CIP message) | See below |

The DNP3 decoder emits one event per link frame that starts an application
fragment. It does not reassemble fragments that span several link frames.

IEC 104 events carry `direction` (`request` from the client, `response` from
the server), `session_id`, `apdu_id`, `apci_type` (`I`, `S` or `U`) and
`raw_hex`. Further attributes depend on the frame:

| Frame | Attributes |
| --- | --- |
| S-format | `class: system`, `is_write: false`, `receive_sequence` |
| U-format | `class: system`, `is_write: false`, `u_function` (`startdt_act`, `startdt_con`, `stopdt_act`, `stopdt_con`, `testfr_act`, `testfr_con`) |
| I-format | `send_sequence`, `receive_sequence`, `type_id`, `class`, `vsq`, `object_count`, `sq`, `cause`, `cot_negative`, `cot_test`, `originator`, `ca`, `is_write` |
| Information object | `ioa`, `object_index`, and by type `value`, `quality`, `qualifier`, `select`, `transient`, `value_invalid`, `source_time`, `time_valid`, `time_summer` |
| Malformed or unsupported | `error`, with the identity attributes the decoder could read |

An I-format APDU emits one event per information object. Types outside the
supported set emit `unsupported`.

CIP events report each EtherNet/IP layer as attributes. The protocol name `cip` covers the whole EtherNet/IP stack: one decoder toggle
and one protocol match. The name `enip` is rejected at rule, signature, Sigma
and toggle boundaries with: `EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`.

| CIP event layer | Attributes |
| --- | --- |
| Encapsulation | `enip_command` (name), `enip_command_code`, `enip_session_handle` |
| Common Packet Format (CPF) | `cpf_item_types`: all item types in packet order as one comma-joined lowercase hex string with no spaces, such as `"0x0000,0x00b2"`, on SendRRData/SendUnitData with a valid item list |
| CIP | `service_code`, `service_name`, `function_code`, `is_write`, `is_control`, `cip_path`, `object_class`, `object_class_name`, `instance_id`, `attribute_id`, `address`; MSP parents also carry `multi_service_count`, sub-events carry `msp` |

MSP sub-events retain the encapsulation and CPF fields. Non-CPF commands such as
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
| `addresses` | Array of address entries, each one value or an inclusive `low-high` range (see below); evaluated against the addresses the message touches |
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
touches only the address and quantity it echoes. For the other protocols a
message touches the one numeric `address` its decoder emits, or none.

Modbus events carry only fields present on the wire: requests have `address`
with `quantity` (function codes 1–4, 15, 16, plus `byte_count` for 15 and 16),
`value` (5, 6), `and_mask` and `or_mask` (22), or `read_address`,
`read_quantity`, `write_address`, `write_quantity` and `byte_count` (23). Read
replies have `byte_count` and, for registers, `register_count`; write replies
have the fields they echo.

Example: a firewall rule that allows Modbus reads of holding registers 0–99
(function code 3) on unit 1, over TCP 502 from the `lan` zone to the `dmz` zone:

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
    "mode": "learn"
  },
  "action": "ALLOW"
}
```

With `mode: "enforce"` the rule needs a nonzero `dataplane.nfqueueGroup` (see
[DPI Modes](#dpi-modes)).

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
2. Inspect `GET /api/v1/learn/profiles`. A Modbus profile lists each observed
   address span (`10-11`, `100`), so its learned rule admits the whole spans it
   saw.
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
| `protocol_violation` | high | More than one ICS protocol from one source to one destination address |
| `rate_anomaly` | high | More than 1,000 ICS events from one source to one destination address in the current and previous clock minute |
| `rate_anomaly` | critical | More than 100 write events (`is_write: true`) in the same window |

These checks use the source and destination IP addresses, not ports. While a
pair is above a rate limit, each further event raises another finding. After a
pair shows a second protocol, each further ICS event of that pair raises that
finding again. IEC 104 rate counts use one event per APDU. The `ids` /
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
the signature engine with the 23 built-in signatures. This removes custom
signatures, restores deleted built-in signatures and clears the match list.
The engine keeps the 4,096 newest matches. Each match has `signature`,
`timestamp` and the matched `event`, whose keys are `FlowID`, `Proto`, `Kind`,
`Attributes` and `Timestamp`.

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
The passive IEC 104 inventory is separate from the learner. Native IDS rules and
the [signature engine](#signatures) are separate consumers; see also
[Protocol anomaly detection](#protocol-anomaly-detection) and
[Decoded event fields](#decoded-event-fields). See
[Logging and Evidence](logging-evidence.md) for bounded retention, queries, and
syslog forwarding.

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
