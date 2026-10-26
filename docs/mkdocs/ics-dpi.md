# ICS/OT Deep Packet Inspection

containd has **16 native Go protocol decoders: 8 ICS + 8 IT**. Live capture and
PCAP analysis share `DefaultDecoders()`. ICS marker and port detector are two
additional utility registrations, not protocol decoders. Decoding a field does
not make it an enforceable firewall predicate.

## DPI Modes

DPI mode resolves **per-rule `ics.mode` > global `dpiMode` > `learn`**.

- **Learn** records would-deny decisions without applying that DPI denial.
- **Enforce** applies DPI policy decisions when the enforcement/capture path is
  configured. AF_PACKET cannot drop the packet it observes; inline prevention
  requires NFQUEUE. See [Enforcement](dataplane-enforcement.md).

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
    "cip": false,
    "s7comm": false,
    "mms": true,
    "bacnet": false,
    "opcua": false
  }
}
```

An omitted protocol toggle leaves its decoder enabled. `dpiProtocols` controls
the IT decoders separately. Enabling a decoder does not create a policy rule.

## Protocol decoders

| ICS protocol | Usual port | Decoder package |
| --- | --- | --- |
| Modbus/TCP | TCP 502 | `pkg/dp/ics/modbus` |
| DNP3 | TCP 20000 | `pkg/dp/ics/dnp3` |
| IEC 60870-5-104 | TCP 2404 | `pkg/dp/ics/iec104` |
| CIP/EtherNet/IP | TCP 44818 | `pkg/dp/ics/cip` |
| S7comm | TCP 102 | `pkg/dp/ics/s7comm` |
| IEC 61850 MMS | TCP 102 | `pkg/dp/ics/iec61850` |
| BACnet | UDP 47808 | `pkg/dp/ics/bacnet` |
| OPC UA | TCP 4840 | `pkg/dp/ics/opcua` |

The eight IT decoders live in `pkg/dp/itdpi`: DNS, TLS, HTTP, SSH, SMB, NTP, SNMP,
and RDP. Protocol events carry `proto`, `kind`, `flowId`, timestamp, and a decoder-
specific attribute map. Inspect emitted events before authoring attribute-based
[IDS conditions](ids-rules.md).

## ICS Firewall Rule Predicates

Firewall rules contain an `ics` object. Generic predicates for protocols other
than IEC 104 are:

| JSON field | Meaning and limits |
| --- | --- |
| `protocol` | `modbus`, `dnp3`, `cip`, `s7comm`, `mms`, `bacnet`, or `opcua` |
| `functionCode` | Array of numeric function/service codes, 0–255; evaluated from `function_code` |
| `unitId` | Optional Modbus unit ID, 0–255; evaluated from `unit_id` |
| `addresses` | Register/address strings or ranges; evaluated from `address` |
| `objectClasses` | CIP object-class IDs, 0–65535; evaluated from `object_class`; CIP only |
| `readOnly`, `writeOnly` | Read/write class from an explicitly present `is_write`; not both true |
| `direction` | `request` or `response`; omit for both |
| `mode` | `learn` or `enforce`; omit to inherit global mode |

Only metadata actually emitted by the decoder can satisfy these conditions.
There are no firewall selectors for DNP3 station addresses/object headers, CIP
instance/attribute/EPATH/MSP, S7 DB numbers, MMS named variables/domains, BACnet
objects/properties, or OPC UA message/service/Node ID patterns. Decoder telemetry
and IDS attributes are not additional firewall selector fields.

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
makes the envelope enforce-mode. Object evaluation uses only IEC 104 rules in
order, defaults to deny, and cannot be bypassed by a broad TCP/2404 allow rule or
a generic allow default. `ALLOW` cannot match malformed or broadcast objects.
ASDU predicates, identity, and schedules do not narrow the envelope itself.

## Learn Mode

The generic learner records non-IEC-104 ICS profiles; IEC 104 is excluded from
both automatic learning and asset discovery. Review learned rules before use:
observation is not authorization.

1. Commit an explicit learn-mode firewall entry and configure capture/DPI.
2. Inspect `GET /api/v1/learn/profiles`.
3. Use `POST /api/v1/learn/generate` to return proposed rules for review.
4. `POST /api/v1/learn/apply` stages generated rules in candidate configuration
   (`status: staged`); it does not activate them. Generated rules use explicit
   `ics.mode: "enforce"`, so review them even if global mode is learn.
5. Review ordering, scope, and per-rule modes in candidate, then commit with
   `POST /api/v1/config/commit`. Changing only global mode does not override an
   explicit per-rule learn mode.
6. `DELETE /api/v1/learn` clears the profiles when no longer needed.

IEC 104 tracking shares a **4,096-entry session table** across learn and enforce
envelopes, including retained closed sessions and abort tombstones. At capacity,
new learn-mode connections are accepted **without stream inspection**. Each
untracked SYN emits `ics.session` with `outcome: untracked`, `mode: learn`,
`reason: bound`, and `limit: 4096`, on the client/server tuple without a session
or APDU ID. Midstream traffic stays untracked; existing sessions remain inspected.
New SYNs can be tracked when entries expire. Enforce envelopes remain fail closed
at capacity.

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
STOPDT con. Sequence checks use the ordered, TCP-deduplicated APDU stream, not
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
Inventory excludes IEC 104. Native IDS rules and the built-in signature engine
are separate consumers. See [Logging and Evidence](logging-evidence.md) for
bounded retention, queries, and the distinction between working syslog sinks and
the unwired SIEM export configuration.

Seven ICS API templates provide two Modbus variants and DNP3, S7comm, CIP,
BACnet, and OPC UA examples. Purdue and maintenance-window templates belong to
the general registry, not this seven-template set. Applying templates stages
candidate changes; see [Policy Model](policy-model.md#templates-and-preview).
