# containd milestone B: command-aware IEC 60870-5-104

Handoff spec for the agents that work on the containd `iec104` branch.
It is self-contained. It states what RangerDanger needs from containd
for its European (EU) IEC104 workshop, the decisions already made, and
the contracts between the two projects.

**Status:** corrected on 2026-10-09 after validation against containd
`8ebc4229`. This file is the binding version on `iec104`. It replaces
the RangerDanger draft. §0 lists every change from that draft. The
frozen Go contracts are in `docs/iec104/contracts.md`.

## 0. Changes from the RangerDanger draft

**Release rule (Tony, 2026-10-09).** Milestone B stays unreleased on
`iec104`. Nothing from this branch goes to `main` or `:latest` before
the US course on 2026-10-22. D11 then holds it until the US and EU
gates pass (about 2026-11-02). `.github/workflows/release.yml:9-11,53-80`
publishes `:latest` for **any** `v*` tag, prereleases included, so a
candidate never gets a `v*` tag.

**Decisions (Tony, 2026-10-09).**

| ID | Decision |
|---|---|
| E1 | Candidates: the orchestrator builds linux/amd64 + linux/arm64 locally from `iec104` and tags `ghcr.io/tonylturner/containd:iec104-<sha>`. Tony pushes that tag. |
| E2 | All US-visible changes in §4.1 (the corrected list) are accepted. Release notes list them. RangerDanger re-checks its events gate. |
| E3 | IEC enforce that cannot activate: static causes (DPI off, iec104 decoder off, capture not NFQUEUE, queue 0, DPI exclusion overlapping the envelope) are validation errors. Commit, candidate and import reject them before save. A runtime queue-bind or injector failure keeps the config, fails closed on IEC traffic, and health shows unhealthy. |
| E4 | `GET /api/v1/flows` stays the event-ring rollup. It hides flow groups of aborted IEC incarnations; their events stay in `/events`. |
| E5 | Nothing is sent to RangerDanger from this side. This file is the corrected spec. |

**Corrections (evidence: containd file:line at `8ebc4229`).**

| # | Draft said | Correct |
|---|---|---|
| W1 | `/api/v1/flows` is the engine flow table | It is a rollup of the bounded event ring (`api/http/runtime_telemetry_handlers.go:102-123`, `pkg/dp/events/store.go:350-402`). See E4. |
| W2 | US parse error: "malformed event (today's behaviour)" | Modbus and DNP3 swallow parse errors today (`pkg/dp/ics/modbus/decoder.go:41-44`, `pkg/dp/ics/dnp3/decoder.go:42-45`). Malformed events are new. |
| W3 | §4.1 is the complete list | Five more US-visible changes. §4.1 now lists them. |
| W4 | Export, synth and templates read inventory/learner, so they need no change | They do not. Offline PCAP-to-policy builds its own learner (`api/http/pcap_handlers.go:297,324`, `pkg/dp/pcap/analyze.go:221-239`). It must not emit IEC rules either. |
| W5 | CP56Time2a year = 2000 + 7-bit year | The year field is 0..99. 100..127 is malformed. +2000 is a B profile assumption. |
| W6 | Role and SQ rules are wire errors | The standard allows reverse-direction operation and SQ=1 for more types. B rejects them as **B profile restrictions**. |
| W7 | readOnly includes "confirmations" of read (102) | A read is answered with monitor data (COT 5). Type 102 comes back only with COT 44-47 (errors). |
| W8 | Run `smoke-dpi.sh` for US first-actuation | It never sets `nfqueueGroup`, so it cannot test prevention. Both smoke scripts died on `((x++))` under `set -e` on Linux Bash 5 and exited 0 even when a test failed. Fixed on `iec104`: both scripts exit non-zero on a shortfall, and `smoke-dpi.sh` gains an NFQUEUE variant (`SMOKE_DPI_CAPTURE=nfqueue`) that tests first-write prevention. |

**Gap defaults** (from the validation report §3) are folded into §4,
§6, §8, §11 and §12 below: strict ICS decoding everywhere with
`SchemaVersionCurrent` bumped to 0.1.7 (0.1.x configs still upgrade);
PATCH strict-decodes the raw `ics` object and a protocol change replaces
it; HTTP preview uses the compiler mapping; `dropped` evidence means
"verdict submitted without error"; capture hands undecodable packets to
the engine; policy apply gains a generation with selective IEC abort; a
session-role field separate from `flow.Key.Dir`; contradictions resolve
to §4.2, envelope mode for no-match, and `ics.decision` for every deny
and `would_drop`.

**Checkpoint 1 result (2026-10-09).** On Docker Desktop 29.8.0, kernel
`7.0.12-linuxkit` arm64, `scripts/preflight-iec104.sh` passed every
required scenario twice: deferred ACCEPT and DROP, multiple held
packets, no head-of-line stall, both directions, a 10 KiB stream held
and released intact, two-sided RST with both sockets reset and a clean
reconnect, and fail-closed when the queue is unbound. RFC 5961
challenge ACK was observed, and a retry at its ACK number closed the
socket. Limits: MTU 1500, so no single packet over 2048 bytes was
tested; `SetVerdict` nil means submitted, not kernel-confirmed.

The harness also found a wall that is now fixed. With
`mdlayher/netlink` v1.11.1, `Conn.Receive` holds the connection lock
while it blocks in `recvmsg`. A deferred `SetVerdict` from another
goroutine then waits for the next queued packet: 7.1-7.5 s in every
run. `79668745` bumps netlink to v1.11.2, where Receive has its own
mutex, and go-nfqueue to v2.1.0. After the bump, 3 of 3 runs passed
with no failures. The worst `SetVerdict` time was 2.1 ms over
about 355 verdicts per run, including 62 concurrent releases. Deferred
verdicts need netlink v1.11.2 or later; do not downgrade.

- **Deadline:** the first EU course is **2026-11-07**. Milestone B gates
  that course. There is no alert-only fallback.
- **Owner:** Tony Turner. Agents never push, never merge to containd
  `main`, never publish images.
- **References:** `C:` paths are relative to the containd repository at
  `origin/main` **8ebc4229** (release 0.1.31). `RD:` paths are relative to
  RangerDanger branch `iec104`
  (<https://github.com/tonylturner/rangerdanger/tree/iec104>) at
  **cee4105**. Line numbers are from those commits; re-check them before
  you edit.
- **Evidence level:** facts marked **V** were read from source. Items
  marked **P** are the proposed design. Nothing here was built or run.
  The Linux kernel behaviour (NFQUEUE deferred verdicts, raw RST
  injection on Docker Desktop) is **unproven** and is the first
  checkpoint (§11).

## 1. Why

RangerDanger is a Docker cyber range that teaches OT segmentation.
containd is its firewall (the `firewall` service, image
`ghcr.io/tonylturner/containd:latest`). The current US workshop uses
DNP3 and Modbus. The new EU package adds an IEC104 link:

```text
control-centre SCADA (IEC104 client)   zone lan4, 10.60.60.0/24
        │  TCP/2404, routed through containd
substation RTU (IEC104 server, lib60870-C)   station zone
        │  Modbus TCP southbound
field devices (feeder breaker, OLTC, RMU)
```

Students write containd policy that lets the control centre monitor the
RTU and send only approved commands, and that stops a forbidden command
**before it reaches the RTU**. Port-level rules on TCP/2404 (milestone A)
need no containd change. Milestone B is the command-aware part, and it
is this spec.

## 2. Decisions already made (do not reopen)

| ID | Decision |
|---|---|
| D3 | The RangerDanger IEC104 programs (RTU, control centre, student tool `iec104cmd`) use **lib60870-C** (GPLv3) in separate images. containd's decoder is its **own Go parser**, Apache-2.0. Do not copy, link or port lib60870 code into containd. Captures from lib60870 are test data, not code (§9). |
| D4 | Milestone B (command-aware filtering) **gates the first EU course**. Alert-only does not satisfy it. |
| D5 | Verbatim: "US workshop: Unchanged until EU ships; its upgrade to the new device model is a later change." The plan allows B to change shared dataplane code because "B stays on a containd branch until the US gates pass against it" (`RD:docs/plans/iec104/README.md:237-239`). So: the US workshop keeps its behaviour, the US-visible changes are only those listed in §4.1, and the US gates (§10.4) must pass unchanged. |
| D10 | When policy denies an IEC104 command: **drop it and reset the session** in both directions. The control centre reconnects and re-runs general interrogation (GI). No 10-minute ban, no silent removal of one ASDU from the stream. |
| D11 | RangerDanger tracks containd `:latest` and re-runs the US and EU gates before each course. Therefore milestone B stays off containd `main` and off `:latest` until both gates pass (§10). |
| — | Plain IPv4, TCP/2404, no NAT on the IEC104 path. Field widths are fixed: COT 2 octets, CA 2 octets, IOA 3 octets. |

## 3. Defaults for open owner questions

Tony can override these. Until he does, build to them.

| # | Question | Default |
|---|---|---|
| B1 | Collateral loss on deny | The whole packet that carries a denied APDU is dropped, including other allowed APDUs in it. The session resets. The operator view goes stale and shows quality until GI completes. Recovery budget: new session + GI complete **≤ 5 s** with reconnect delay ≤ 1 s on the course RTU/client. Continuity means recovered telemetry, not zero lost samples. |
| B2 | Unknown, malformed or role-invalid IEC104 | Inside an **enforce** IEC envelope: drop + reset (fail closed). In a **learn** envelope: alert and pass (§6.5). Never resynchronise or pass opaque bytes as allowed. |
| B3 | Addresses | Object-bearing traffic (I-frames) to or from broadcast CA 65535 never matches an ALLOW in B, wildcard rules included; in an enforce envelope it resets. A rule that names CA 65535 is a validation error. The parser still records wire zeros and broadcasts. |
| B4 | Select-before-execute (SBO) | containd classifies select and execute; both are control requests under the same CA/IOA rules. containd does **not** enforce SBO transaction state (expiry, value match, peer match). The RangerDanger RTU application (built on lib60870) owns that and proves it in its own tests; containd tests must not assume it. |
| B5 | Transport | No IPv6, TLS, non-standard ports, NAT or proxying. IEC104 sessions that exist when B enforcement activates are reset once and must reconnect. A session not observed from its SYN gets no preventive guarantee. |
| B7 | Session control | STARTDT, STOPDT and TESTFR (act and con), and S-frames, are read-only: they cannot actuate the plant, and only an L4-authorized peer can send them. A STOPDT still raises an alert signature (§7.4). |
| B8 | Rule orientation | IEC104 semantic rules match the **session** tuple (SYN opener → port 2404), not the packet's wire direction; `direction` selects which half of the session (§6.3). One rule block per session; students do not write reverse rules. |
| B6 | Kernel wall | If NFQUEUE deferred verdicts or raw RST injection do not work on Docker Desktop's Linux VM by the first checkpoint, stop and report to Tony. "Passed with skips" is not acceptance. |

## 4. Shared dataplane fixes (prerequisites)

containd today cannot stop the first forbidden command. These fixes are
shared code. Their US effect is stated per row.

| Fix | V: today | P: change and US effect |
|---|---|---|
| Current-packet verdict | `C:pkg/dp/capture/capture.go:17` Handler returns nothing; `C:pkg/dp/capture/nfqueue_linux.go:172-179` always sets ACCEPT after the handler. A cached denial returns with no verdict (`C:pkg/dp/engine/engine.go:479-506`). `C:pkg/dp/engine/policy_eval.go:99-108` only installs a later nft block. | The handler returns an explicit decision. NFQUEUE applies DROP to the current packet before any nft-updater I/O. A cached denial also returns DROP. An updater failure must not turn DROP into ACCEPT. SetVerdict errors are reported, not ignored. AF_PACKET/NFLOG stay observational. **US:** a complete denied Modbus/DNP3 write is now dropped on its first packet instead of reaching the device. The existing US 10-minute dynamic block stays. |
| TCP metadata | Capture `Packet` has no seq/ack/flags (`C:pkg/dp/capture/capture.go:20-30`); NFQUEUE and AF_PACKET discard them (`C:pkg/dp/capture/decode_ip.go:59-76`, `C:pkg/dp/capture/afpacket_linux.go:189-200`). The engine does not set `ParsedPacket.TCPSeq` (`C:pkg/dp/engine/engine.go:470-475`); offline PCAP analysis does not either (`C:pkg/dp/pcap/analyze.go:134-141`). | Carry seq, ack, flags and a metadata-valid flag from capture through engine to DPI, and in offline PCAP. Seq 0 is a valid value, not "missing". Account for SYN/FIN sequence space, SYN data and ACK-only packets. **US:** retransmissions stop duplicating or stalling parses; split and coalesced messages become visible. |
| All-frame parsing | The DPI manager trims only a `StreamDecoder` (`C:pkg/dp/dpi/dpi.go:147-179`); Modbus and DNP3 parse one frame per call (`C:pkg/dp/ics/modbus/decoder.go:16-44,106-118`, `C:pkg/dp/ics/dnp3/decoder.go:17-45,108-120`). The reassembler drops old bytes on overflow, caps out-of-order at 4 and ignores conflicting overlap (`C:pkg/dp/dpi/reassembly.go:123-158`); its accounting counts retransmitted lengths (`:160-164`). `dpi.StreamDecoder.ConsumedBytes()` (`C:pkg/dp/dpi/reassembly.go:16-26`) is used only by a test mock. | Replace that unused interface with the framed stream API in §5.1. Each decoder consumes every complete frame once and keeps the incomplete tail. Overflow, gaps and conflicting overlaps are explicit errors in inline mode. **US:** a write coalesced behind a read is now inspected. Do not claim full DNP3 application-layer reassembly from a link-frame loop. |
| Direction and lifecycle | `trackFlow` always records DirForward (`C:pkg/dp/engine/engine.go:510-525`) but `servicePort` depends on DirReverse (`C:pkg/dp/engine/policy_eval.go:305-309`). Expired flows are deleted with no stream cleanup (`C:pkg/dp/engine/engine.go:543-550`). | Keep separate per-direction streams bound to one session incarnation. The client is the SYN opener; the server is confirmed on 2404. Clean up streams on FIN, RST, abort, expiry and policy-generation change. IEC104 semantic evaluation uses the session tuple (B8, §6.3). Evaluation of non-IEC traffic keeps today's wire-oriented matching. **US:** no matching change; stream cleanup only. |
| Compiler loses fields | `C:pkg/cp/compile/compile.go:86-94` drops the existing `direction` and `objectClasses` ICS fields. | Copy every predicate field. **US:** policies that set those fields start to be enforced. Call this out in release notes and regression tests; do not preserve the bug. |
| ICS field drift | The anomaly detector also reads Modbus `unit_id` with `.(int)` (`C:pkg/dp/anomaly/detector.go:243`) while Modbus emits `uint8` (`C:pkg/dp/ics/modbus/decoder.go:50`). The DNP3 decoder emits `object_groups` (string) while its signature expects numeric `object_group` (`C:pkg/dp/ics/dnp3/decoder.go:79-98`, `C:pkg/dp/signatures/builtins.go:116-123`). The anomaly detector reads `function_code` with `.(int)` for Modbus, DNP3 and S7 (`C:pkg/dp/anomaly/detector.go:241,364,434`), but Modbus emits `uint8` (`C:pkg/dp/ics/modbus/modbus.go:18`, `C:pkg/dp/ics/modbus/decoder.go:45-52`) and DNP3 emits `uint8` (`C:pkg/dp/ics/dnp3/decoder.go:47-65`), so those checks always see FC 0. | Keep the `object_groups` wire key. Fix the group-70 signature to exact token membership (not substring "7"/"170"). Use the strict numeric accessors from §5.4 everywhere `function_code` is read. Separate maintenance commit, with tests fed by **real decoded events**. **US:** FC-based anomaly events may start to appear in the US range. That is a visible change; report it, and RangerDanger checks it in its events gate (§10.4). |

**Not changed for US:** holdback and session reset (§8) are IEC104-only.
US DENY still uses the existing dynamic block. Extending holdback to US
is a separate product decision.

### 4.1 US-visible changes (the complete list, corrected)

1. A complete denied Modbus/DNP3 message in one packet is dropped on its
   first packet. A message split over packets is still judged when it
   completes, so its last packet is dropped; earlier packets have
   already passed. This is not a universal first-message guarantee.
2. `direction` and `objectClasses` in ICS rules are now compiled and
   enforced.
3. ICS JSON is decoded strictly: unknown keys, duplicate keys and
   semantic fields without `protocol` are rejected. Existing
   `functionCode` input forms, including `null`, stay accepted.
4. FC- and unit-based anomaly events can now fire for Modbus/DNP3, and
   S7 FC anomaly checks start to fire (same `.(int)` bug,
   `pkg/dp/anomaly/detector.go:434`).
5. Modbus and DNP3 parse errors, buffer overflow and conflicting
   overlap now emit `malformed` events (W2).
6. False Modbus broadcast-write alerts disappear: today every decoded
   write reads as unit 0 (`detector.go:243`).
7. Every message on a TCP connection is inspected. Today only the first
   PDU per direction is decoded, and every later packet re-reports it,
   because the engine passes no TCP sequence number
   (`contracts.md` §K8). Event counts, alerts and writeOnly denies
   change for any client that keeps its connection open, and for
   coalesced traffic.
8. DNP3 events gain `direction` from the link-layer DIR bit, so the
   restart check stops flagging every master restart as "non-master".
9. Configs that set `schema_version` 0.1.7 do not load on releases
   before this one.

Release notes list these nine (E2). Anything else that changes US
behaviour is a bug.

### 4.2 US stream errors

US protocols get no holdback, so the shared reassembly errors map to:

| Condition | US (Modbus/DNP3) | IEC104 enforce envelope | IEC104 learn envelope |
|---|---|---|---|
| Gap / out of order | accept the packet; parse when the gap fills | hold (§8.1) | accept; parse when filled |
| Buffer overflow | accept; `malformed` event; drop that stream's buffer | abort + reset | accept; event; stop parsing the session |
| Conflicting overlap | accept; `malformed` event; drop that stream's buffer | abort + reset | accept; event; stop parsing the session |
| Parse error | accept; `malformed` event (new, W2) | abort + reset | accept; event; stop parsing the session |

A gap in a learn envelope is parsed when it fills (this row wins over
the "stop parsing" wording in §6.5, G14a).

## 5. Contracts to freeze first (day 1)

Freeze these before parallel work. The orchestrator commits all of them
in one contract commit with contract tests (exact names:
`docs/iec104/contracts.md`); lanes consume them and never edit them. A
lane that needs a contract change reports it to the orchestrator. The
sketches below fix the semantics.

### 5.1 Framed stream decoder (owner L3; L1 implements it for IEC104, Modbus, DNP3)

- `StreamDecoder` embeds `Decoder` and adds
  `ParseStream(stream StreamView) (StreamResult, error)`. `StreamView`
  carries the session incarnation ID, the direction, the absolute
  offset of its first byte, and the contiguous bytes the DPI manager
  holds for that direction. The manager owns the buffer and its base
  offset; decoders never keep a reference to the bytes after return.
- **Offsets are absolute per direction**: byte 0 is the first payload
  byte after the SYN (ISN + 1). They never reset when the buffer is
  trimmed.
- `StreamResult{Frames []DecodedFrame, Consumed int, NeedMore bool}`.
  `DecodedFrame{Start, End int64 /* [Start,End) absolute */, Events []dpi.Event}`.
  `Consumed` is the length of the complete-frame prefix; the manager
  trims it.
- Incomplete data is `NeedMore`, not malformed. A fatal error is a typed
  `*FrameError{Offset int64, Reason string}`; frames before it are still
  returned and count as complete.
- Contract test: two APDUs split across three packets with a trim
  between them yield the right absolute ranges.
- The DPI `Inspect` path returns this metadata plus the flattened
  events. `OnPacket` stays the event-only entry for non-inline callers
  and uses the same parser. Only the framed decoder consumes the stream;
  port/marker decoders cannot trim it. No shared mutable "last consumed"
  counter.
- Events are emitted once, when a frame completes, never again on
  retransmission.

### 5.2 Inline decision and verdict sink (owner L3)

- `Decision{Action: Accept|Drop|Hold, Reason string, Resolved []{Token, Action}}`
  lives in `pkg/dp/capture`, in L3's fence. (The draft put it next to
  `verdict.Action`, but `pkg/dp/verdict` imports `pkg/dp/rules`, and
  capture must not depend on policy.)
- `Packet` carries an opaque token (queue generation + NFQUEUE packet ID)
  and the TCP metadata from §4. The payload is a copy owned by the
  packet; it stays valid after the callback returns.
- `Hold` returns from the callback **without** SetVerdict. `Resolved`
  may settle tokens from earlier callbacks. Timers and shutdown settle
  through the same sink. Capture owns token lifetime and exactly-once
  submission; the engine owns framing, policy and the session ledger.
- **Completion:** the sink reports each submitted verdict back through a
  callback `OnVerdict(token, action, err)`. A stale queue generation or
  a SetVerdict error is `err != nil`. The engine emits `dropped`
  evidence (§8.4) only from this callback.
- **Ordering:** the callback path never does raw-socket or nft I/O
  while it holds the session lock. DROP verdicts are submitted first;
  reset injection (§8.2) and any nft update run after, on a bounded
  worker.
- Tokens never appear in event JSON.

### 5.3 Policy schema (owner L2) — see §6

### 5.4 Event fields (owner L1) — see §5.5 and §8.4

- New dependency-free package `pkg/dp/ics/eventfields/` owns the key
  constants and strict accessors. Parsers emit concrete integers; JSON
  carries numbers. Accessors accept only exact integral JSON numbers in
  range; they never truncate fractions. Absent is not zero or false.
  Tests check the in-memory form and the marshal/unmarshal form.

### 5.5 IEC104 event shape

`Proto = "iec104"`. One event per information object; objects of one
APDU share `apdu_id`. One event per S-frame, U-frame or error APDU.

| Kind | When |
|---|---|
| `request` | valid I-frame from the client (TCP opener) |
| `response` | valid I-frame from the server (port 2404) |
| `apci` | S- or U-frame (class `system`) |
| `malformed` | framing or layout violation |
| `unsupported` | valid header, Type ID without a B descriptor |

| Attribute | Type and presence |
|---|---|
| `apci_type` | `I` / `S` / `U` |
| `direction` | `request` / `response` (TCP role, not act/con naming; a server may send TESTFR act) |
| `class` | `monitor` / `control` / `system` / `unknown` (from Type ID) |
| `send_sequence`, `receive_sequence` | uint16, only where the APCI carries them |
| `u_function` | string (`startdt_act`, `startdt_con`, `stopdt_act`, `stopdt_con`, `testfr_act`, `testfr_con`), U only |
| `type_id`, `vsq`, `object_count`, `cause`, `originator` | uint8, I only |
| `sq`, `cot_test`, `cot_negative` | bool, I only |
| `is_write` | bool; true only for mutating client requests and dangerous system requests. Never derive read-only as `!is_write`. |
| `ca` | uint16, I only |
| `ioa`, `object_index` | uint32 (24-bit) and uint8, only when the object layout decoded |
| `select` | bool, only for types that have a select bit |
| `qualifier`, `quality` | uint8, where the type has them |
| `value` | typed by descriptor |
| `source_time`, `time_valid`, `time_summer` | timed types only. `source_time` is the CP56Time2a calendar value as ISO 8601 **without** a zone (`2026-11-07T09:15:02.345`), year = 2000 + year field (B profile assumption: the century is not on the wire, and a field value of 100..127 is `malformed`; the minute-octet GEN/RES1 bit is ignored); `time_valid` = not IV; `time_summer` = SU. The course profile runs the RTU clock in UTC; consumers apply the profile, the decoder does not. A calendar value that cannot exist (month 0, day 31 in April) is `malformed`. |
| `apdu_id`, `session_id` | string; `session_id` = incarnation; `apdu_id` = incarnation + direction + absolute start offset |
| `raw_hex` | string, at most 255 bytes of APDU |
| `error` | string, only on `malformed`/`unsupported`/role violation |

Do **not** set `function_code` or generic `address` on IEC104 events.
RangerDanger shows `function_code` for Modbus/DNP3 only.

## 6. Policy schema

### 6.1 Wire shape

Flat IEC fields inside the existing rule `ics` predicate. Existing
`mode` (`learn`/`enforce`) and `direction` (`request`/`response`) keep
their meaning. `classes` is new.

```json
{
  "protocol": "iec104",
  "typeIds": [46],
  "classes": ["control"],
  "direction": "request",
  "ca": [1],
  "ioa": [{"start": 65536, "end": 65567}],
  "readOnly": false,
  "mode": "enforce"
}
```

- `typeIds`: integers 1..255. Serialise as a **numeric array**, never
  Go `[]byte` base64. Allow rules may name only types with a B
  descriptor (§7.2). Unknown types may appear in deny/learn rules only.
- `classes`: any of `monitor`, `control`, `system`, `unknown`. OR within
  the list.
- `ca`: integers 0..65534. Naming 65535 is a validation error in B.
  Broadcast traffic never matches an ALLOW, even a rule without `ca`
  (B3); the evaluator checks this, not the validator.
- `ioa`: closed ranges, integer endpoints 0..16777215, `start ≤ end`.
  Reject duplicates and overlapping ranges.
- OR within each list; AND across fields. A missing field is a
  wildcard. `null` or `[]` on one of the **new** fields (`typeIds`,
  `classes`, `ca`, `ioa`) is a validation error.
- `ca`/`ioa` need an object event. S- and U-frames have neither, so
  session-control rules must not carry `ca`/`ioa`.
- `readOnly: true` matches exactly: monitor-class I-frames in the
  response direction; GI (100) requests and their confirmations; read
  (102) requests (a successful read is answered with monitor data,
  COT 5; a type-102 response carries only COT 44-47 errors and is not
  read-only, W7); end of initialization (70); S-frames; all U-frames
  (STARTDT, STOPDT, TESTFR; B7). It does **not** match counter
  interrogation (101: its QCC can freeze or reset counters, and B does
  not decode integrated totals), clock sync (103), reset process (105),
  test with time (107), control requests, broadcast CA, malformed or
  unsupported traffic. Control confirmations are not read-only; allow
  them with `classes:["control"], direction:"response"`.
- `readOnly: false` means no access constraint. It does not mean
  "writes only". `writeOnly` is rejected for IEC104.
- There is no select predicate in B. If one is needed later, add a new
  versioned field.

### 6.2 Validation

- **V:** `C:pkg/cp/config/ics_json.go:47-83` unmarshals into a struct and
  silently drops unknown keys. `C:pkg/cp/config/validate.go:678-697`
  accepts unknown protocols and returns early for a blank protocol.
- **P:** strict known-key decoding **inside `ICSPredicate`'s own
  `UnmarshalJSON`** (an outer `DisallowUnknownFields` does not reach a
  custom unmarshaller), including the nested IOA objects. Track
  presence so `null`/empty/false-valued fields are seen. Reject
  duplicate JSON keys.
- `ics: {}` stays valid (pure L3/L4 rule). Reject: semantic fields
  without `protocol`, and `mode` counts as a semantic field (today
  `icsPredicateEmpty` ignores `mode`, `C:pkg/dp/rules/eval.go:358-366`,
  so `{"mode":"enforce"}` matches everything); IEC fields on other protocols; `functionCode`,
  `unitId`, `addresses`, `objectClasses` or `writeOnly` on IEC104;
  unknown protocols; contradictory combinations; invalid modes; unknown
  keys.
- Keep every currently accepted US `functionCode` input form,
  including `null` (`C:pkg/cp/config/ics_json.go:74-75`). This is not a
  function-code migration.
- Put IEC validation in sibling files (for example
  `validate_iec104.go`); keep `validate.go` a dispatcher. Files stay
  under 1000 lines.
- **US risk:** strict decoding exposes existing typos that were silently
  ignored. Test both shipped RangerDanger US policies
  (`RD:lab-definitions/firewall/substation-weak.json`,
  `RD:lab-definitions/firewall/substation-improved.json`) and persisted
  appliance exports; they must still load.

### 6.3 Compile and evaluate

- **V:** CP predicate `C:pkg/cp/config/config.go:802-812`; DP predicate
  and context `C:pkg/dp/rules/rules.go:86-97`, `C:pkg/dp/rules/eval.go:30-40`;
  matching `C:pkg/dp/rules/eval.go:267-346,358-366`; first-match order
  `C:pkg/dp/rules/eval.go:189-202`; ICS context built at
  `C:pkg/dp/engine/policy_eval.go:113-143`; rule-evaluable protocols at
  `C:pkg/dp/engine/policy_eval.go:199-205`.
- **Session-tuple matching (B8):** for IEC104 events, the rule's zones,
  CIDRs and port are matched against the session tuple: source = SYN
  opener (client), destination = server, port = 2404, whatever the
  packet's wire direction. `direction` (`request`/`response`) then
  selects the half. So the rule block in §12.4 covers both directions.
  Non-IEC evaluation keeps wire orientation; the US is unchanged.
- Add `ICSContext.IEC104 *IEC104Context` with optional APCI type, Type
  ID, CA, IOA, class, direction and an explicit `SafeRead`. A distinct
  evaluator branch for IEC104; generic function-code/address matching
  never runs on IEC events. Precompile IOA ranges once (also for
  `PreviewMatch`). Compiled snapshots are immutable.
- Every object's decision feeds its APDU; every APDU feeds its packet.
  Any enforce DENY wins. Evaluate all events for evidence even after a
  deny.
- Mode precedence stays: rule override > global DPI mode > learn
  (`C:pkg/dp/engine/runtime_events.go:370-386`). Alert = `DENY` +
  `mode: learn` + `log: true`. Enforce = `DENY` + `mode: enforce`.

### 6.4 Inspection envelope (nft)

- IEC rules compile to a **transport envelope** in nft, not to ASDU
  verdicts. Scoped queue steering in **both directions** must come
  before the conntrack-established accept, normal accepts and
  overlapping L4 ALLOW rules. **V:** today DPI queue entries match dport
  only, so reverse telemetry can fall into established ACCEPT
  (`C:pkg/dp/enforce/enforce.go:145-153,164-187,434-449`).
- Reverse steering does not authorize anything; responses must match a
  semantic rule with `direction: "response"` or `readOnly: true`.
- Reject the config **before it is saved** (validation error on
  commit, candidate and import; E3) if IEC enforce is configured and:
  DPI is off, the IEC104 decoder toggle is off, capture is not
  NFQUEUE, the queue ID is 0, or a DPI exclusion overlaps the
  envelope. A reset injector that is unavailable at runtime, and
  runtime queue-bind or verdict errors, keep the config, fail closed on
  IEC envelope traffic, and make enforcement **unhealthy** (§8.3).
- See §6.5 for what is inside an envelope and how it is decided.
- A policy apply that changes an IEC envelope quiesces affected IEC
  traffic, clears stale state, resets those IEC sessions, then accepts
  new SYNs. No global conntrack flush; US sessions are not disturbed.

### 6.5 IEC envelope and its mode

- **Envelope:** an IEC104 session (opener → 2404) is inside the
  envelope when its tuple matches the L3/L4 part of at least one rule
  with `ics.protocol: "iec104"`. Policies with no IEC rule (milestone A,
  US) have no envelope and behave as today.
- **Envelope mode** is fixed at the SYN: `enforce` if any matching IEC
  rule has effective mode enforce (rule > global DPI mode), else
  `learn`. A policy apply re-evaluates it and resets sessions whose
  envelope changed (§6.4).
- **Evaluation inside the envelope:** each event is matched against the
  IEC rules only, in order. Non-IEC rules (for example a broad `tcp/2404`
  ALLOW) do not take part. No match = DENY, independent of
  `firewall.defaultAction` (L2 implements this in the IEC evaluator
  branch).
- **Enforce envelope:** holdback (§8.1); an enforce DENY, a broadcast
  object, a malformed or unsupported APDU, or a role violation aborts
  the session (§8.2). A learn-mode DENY rule gives `would_drop` and the
  APDU passes.
- **Learn envelope:** no holdback; packets are accepted at once and
  observed. DENY gives `would_drop`. Parse errors, gaps, overflow and
  conflicts emit an event and stop parsing that session; traffic is
  never held or reset.

## 7. Decoder

### 7.1 Placement

- **V:** registration and toggles at `C:pkg/dp/engine/decoders.go:22-41,55-89`;
  default inspection ports at `C:pkg/dp/engine/engine.go:436-452`.
- **P:** new `pkg/dp/ics/iec104/` (`apci.go`, `asdu.go`, `types.go`,
  `decoder.go`, tests, fuzz, testdata). Pure Go, no new runtime
  dependency. `Supports`/`Ports`: TCP with either endpoint on 2404.
  Register the decoder; add the config toggle
  `dataplane.dpiIcsProtocols.iec104` (`C:pkg/cp/config/config.go:465-469`);
  add 2404 to default inspection; add `iec104` to rule-evaluable
  protocols. The port/marker decoders in `pkg/dp/itdpi`
  (`C:pkg/dp/engine/decoders.go:39-40`) need no change.

### 7.2 Wire rules

Verify every rule below against the IEC 60870-5-104 and -101 editions
you use, and against the lib60870 captures (§9), before merging. Record
the edition and clause for each rule in the decoder's doc comment.
Where B rejects something the standard allows, label it a **B profile
restriction**, not malformed wire.

- APDU: start `0x68`, length octet 4..253, total `2 + L` (max 255).
  Validate reserved control bits. No scan-forward resync in inline mode.
- **I-frame:** control octet 1 bit 0 = 0; control octet 3 bit 0 = 0
  (reserved); N(S) and N(R) are 15-bit little-endian, shifted left by
  one. Requires an ASDU, so `L > 4`.
- **S-frame:** octet 1 = `0x01`, octet 2 = 0, octet 3 bit 0 = 0, `L = 4`,
  N(R) as above.
- **U-frame:** `L = 4`, octets 2-4 zero, exactly one function:
  STARTDT act/con `0x07`/`0x0B`, STOPDT act/con `0x13`/`0x23`, TESTFR
  act/con `0x43`/`0x83`.
- **ASDU header:** Type ID (1), VSQ (1: SQ = bit 7, count = low 7 bits),
  COT (2: cause = low 6 bits, P/N = bit 6, T = bit 7; originator = octet
  2), CA (2, little-endian). IOA is 3 octets, held in uint32.
- SQ = 0: each object has its own IOA. SQ = 1: one base IOA, then
  consecutive IOAs; reject 24-bit overflow. Apply the descriptor's
  element size to every object. Reject zero count, extra bytes and bad
  layouts.
- **B profile SQ/count:** SQ = 1 is accepted only for types 3 and 13.
  Control and system types need SQ = 0 and count = 1. Timed monitoring
  (31) needs SQ = 0. Anything else is `malformed` with an `error` that
  says `profile:`. The standard allows SQ = 1 for other monitor types
  (W6); B rejects it on purpose.

| Type IDs | Class | Element after IOA |
|---|---|---|
| 3 `M_DP_NA_1`, 13 `M_ME_NC_1`, 31 `M_DP_TB_1` | monitor | DIQ (1); float32 + QDS (5); DIQ + CP56Time2a (8). Keep value, quality and time validity. |
| 45/46/47, 58/59/60 | control | SCO/DCO/RCO (1); timed adds CP56Time2a (7). Bit 7 = S/E (select); bits 2-6 = QU qualifier. SCO: value = bit 0, bit 1 reserved (must be 0). DCO/RCO: value = bits 0-1; only 1 and 2 are legal commands, 0 and 3 are `malformed`. |
| 48/49/50, 61/62/63 | control | normalized int16 / scaled int16 / float32, + QOS (1); timed adds 7. QOS: bits 0-6 = QL, bit 7 = S/E (select). |
| 51, 64 | control | bitstring32 (4); timed adds 7. **No select bit and no qualifier**: omit `select`. |
| 70, 100, 101, 102 | system | COI (1); QOI (1); QCC (1); read has no element. IOA 0 is parsed, not treated as absent. |
| 103, 105, 107 | system (not safe) | clock sync CP56 (7); reset process QRP (1); test with time TSC (2) + CP56 (7). Decode enough to identify and deny. |
| 104, 106 | unknown | IEC 101 test and delay commands, not used in IEC 104. Header-only `unsupported`. |
| anything else | unknown | Header-only `unsupported` event. Never read-only. |

The first course uses only 3, 13, 31, 100 and 46. The other control
layouts are decoded so that a student cannot bypass the classifier with
a different command type; decoding does not authorize them.

### 7.3 Role and cause

- Class comes from Type ID; direction from TCP role; cause from COT.
  They are independent.
- `direction` = TCP role: every I-frame from the client is a
  `request`, every I-frame from the server a `response`. COT is
  recorded as evidence (`cause`, `cot_negative`, `cot_test`); B does
  not enforce a full COT table.
- **Role violations** (the only COT-based errors in B), reported as
  `malformed` with an `error` that says `profile:`. IEC 104 §9 permits
  reverse-direction operation; these are **B profile restrictions**,
  not wire errors (W6):
  - a monitor-class type (1-44) sent by the client;
  - a control- or system-class I-frame from the server with cause 6
    (activation) or 8 (deactivation), i.e. a command the server
    initiates.
- Everything else is legal role-wise, for example: read (102) with
  COT 5; end of initialization (70) with COT 4; GI data with COT 20-36;
  periodic (1) and background (2) data; status after a command with
  COT 11/12; confirmations with COT 7, 9, 10 and 44-47, with or
  without the P/N bit.
- A type-46 confirmation is `class: control`, `direction: response`; it
  is not a control request. Test and negative flags do not exempt a
  client command.

### 7.4 Consumers

- **Signatures** (`C:pkg/dp/signatures/signature.go:145-173` already
  read scalar attributes): built-ins use `type_id`, `direction`, `ca`,
  `ioa`, `select`. The default command signature alerts on client
  control requests, not confirmations. Add STOPDT, malformed and
  unsupported signatures. Signatures alert; they do not reset.
- Derived alerts keep command identity, CA and IOA
  (`C:pkg/dp/engine/runtime_events.go:124-136` drops them today).
- **Anomaly** (`C:pkg/dp/anomaly/detector.go:154-181` reads `error`):
  add role/COT violations; rate accounting deduplicates by `apdu_id`.
  Spontaneous telemetry is not an unmatched transaction.
- Inventory, learning, export, synth, templates and Suricata
  translation must not auto-learn or render permissive IEC rules from
  IEC events. **V:** the engine already treats `iec104` as ICS
  (`C:pkg/dp/engine/runtime_events.go:293-300`, `C:pkg/dp/itdpi/ics_marker.go:29-43`)
  and feeds inventory and the learner at
  `C:pkg/dp/engine/runtime_events.go:60-79`. **P:** L4 stops IEC104
  events at that feed point. Export, synth and templates do not read
  those stores (W4). The real second path is offline PCAP-to-policy,
  which builds its own learner (`C:api/http/pcap_handlers.go:297,324`,
  `C:pkg/dp/pcap/analyze.go:221-239`); L4 gates it too. Suricata export
  (`C:pkg/cp/ids`) renders an unknown protocol as `ip`; L2 makes it
  skip IEC104 rules instead.

## 8. Enforcement: holdback and session reset (D10)

### 8.1 Holdback ledger (IEC104 only)

A synchronous handler cannot wait for the rest of a split APDU: the
suffix arrives in a later callback. So:

- Map every inspected IEC payload packet to its directional TCP byte
  range. Release (ACCEPT) a packet only when all its bytes belong to
  complete, allowed APDUs. An allowed APDU plus an incomplete tail holds
  the packet. An allowed APDU plus a denied APDU drops the whole packet
  and resets. Never split, rewrite or forge payload, ACKs or sequence
  numbers.
- Out-of-order packets stay held until the gap fills. A retransmit of
  accepted identical bytes is accepted; a retransmit of pending bytes
  follows their decision. Compare overlaps byte for byte; a conflict
  aborts. Keep bounded history of accepted bytes until acknowledged. If
  identity cannot be shown, fail closed and reset.
- Track the handshake from SYN with both ISNs. Never start parsing in
  the middle of a stream. Sessions that exist at activation are reset
  once (B5).
- IP fragments, IPv6, extension headers and truncated packets inside
  the envelope are dropped with evidence. **V:** queued malformed-IP
  handling currently accepts unconditionally
  (`C:pkg/dp/capture/nfqueue_linux.go:156-169`). Copy the full packet
  (up to 65535), not the default 2048-byte snaplen.
- Starting bounds, to benchmark: 32 held packets and 64 KiB per
  session, 256 held globally (under the kernel queue of 1024,
  `C:pkg/dp/capture/nfqueue_linux.go:134-138`), 1 s pending timeout
  (configurable, always below the endpoint's t1). Timers run without
  new packets. Any bound hit aborts the session and drops held packets.
  Queue full or unbound fails closed (no queue bypass).
- Exemptions apply only to **payload-free** segments: do not hold a
  bare SYN or a pure ACK; accept a valid payload-free FIN/RST after
  dropping pending data. A segment with payload is judged on its
  payload first, whatever its flags. SYN with data is dropped (B does
  not support TCP Fast Open). RST with data: drop the data, then treat
  it as an abort.
- **Known limit:** a sender that waits for the ACK of a partial APDU
  before it sends the rest cannot make progress, because a held packet
  is not acknowledged. The pending timeout then resets the session.
  lib60870 and the course tools write whole APDUs; test this at
  checkpoint 1 and document it. Do not forge ACKs to work around it.

### 8.2 Abort transaction

**V:** containd has no TCP RST injector. The updater offers only
`BlockHostTemp`/`BlockFlowTemp` (`C:pkg/dp/enforce/enforce.go:635-676`).
Conntrack delete (`C:pkg/dp/conntrack/delete_linux.go:41-84,118-138`) removes
kernel state only and sends nothing. The IEC104 deny path must not use
the existing DPI block either: its key is src IP, dst IP and dst port,
without source port (`C:pkg/dp/enforce/enforce.go:109-112,662-696`), so
it would also ban the control centre's reconnect for 10 minutes
(`C:pkg/dp/engine/engine.go:31` blockTTL; DENY→BlockFlowTemp at
`C:pkg/dp/engine/policy_eval.go:99-104`). Lowering the TTL is not a fix.

**P:** a small Linux-only `pkg/dp/session` injector (raw IPv4 socket,
`IP_HDRINCL`, IP and TCP checksums, route-selected egress, spoofed peer
addresses, no payload) behind an interface with a fake and an explicit
"unsupported platform" result. **V:** containd already runs as root
with NET_ADMIN + NET_RAW (`C:deploy/docker-compose.yml:62-68`), and so
does RangerDanger's firewall service (`RD:docker-compose.yml:20-22`).
Whether the RSTs are delivered and accepted is unproven (§11
checkpoint 1). A one-sided nft `reject with tcp reset` is not enough: it
answers only the sender.

On an enforce deny:

1. Under the session lock, mark the incarnation aborted **before**
   releasing anything. DROP the packet with the denied APDU, all held
   packets in both directions, and any later payload of the old
   session. DROP does not depend on reset success.
2. Send one RST to each endpoint. The algorithm is the same for both,
   and does not depend on which side sent the denied APDU. For target
   X: `seq` = end of the last byte containd **forwarded** to X (never
   the end of withheld data). If containd forwarded nothing since X's
   last ACK, that equals X's last ACK number. Data lost after
   forwarding makes the RST land above X's RCV.NXT; X then sends a
   challenge ACK (RFC 5961), and containd retries once per challenge
   with `seq` = that ACK number, at most 3 retries within 1 s. A
   successful write is `reset_sent`, not proof that the endpoint
   closed. Golden tests cover a denial in each direction, forwarded
   data lost, a stale ACK and a challenge ACK.
3. Keep an in-memory tombstone for the old incarnation (5-tuple + ISNs
   + generation), bounded globally, at most 10 minutes. It is not
   `block_flows`. Old ACKs/data: DROP + bounded reset retries. A SYN
   from a new source port is a new session. A same-5-tuple SYN with a
   new ISN retires the tombstone after the handshake validates. A
   retransmitted old SYN is not a new session. When the tombstone
   bound is full, evict the oldest; a packet of an evicted, unknown
   mid-stream session is treated as "not observed from SYN": dropped in
   an enforce envelope, never parsed as a new session.
4. Do not add IEC104 denials to nft `block_flows` or any host/service
   ban. New sessions pass ordinary source-pinned L4 rules, then STARTDT
   and GI pass semantic rules. Delete the old conntrack entry only
   after the RSTs, scoped to the 5-tuple.
5. A learn envelope never aborts (§6.5).

### 8.3 Health and failure

- If raw injection is unavailable at start, keep the config, fail
  closed: drop IEC envelope traffic (no session can be reset, so none
  is allowed to start), and report unhealthy (E3). Never downgrade
  silently to learn.
- On a transient reset failure, keep dropping the old session and
  retrying; the connection may time out. Report it as a D10 failure.
- Verdict, queue or reset failures set enforcement health to unhealthy
  and emit `ics.session` `enforce_unhealthy` with `error` (§8.4). Shutdown or queue restart drops outstanding
  packets and clears the ledger.

### 8.4 Decision and outcome events

Three kinds, all `Proto = "iec104"`, all carrying `session_id`. Rule
decisions are separate from what happened on the wire.

| Kind | Cardinality | Attributes |
|---|---|---|
| `ics.decision` | one per object (or per S/U/error APDU) that a rule judged. Emitted for every DENY and `would_drop`; for ALLOW only when the rule has `log: true`. | `decision` (`allow` / `deny` / `would_drop`), `ruleId` (empty for the envelope default or a broadcast/malformed reason), `action`, `mode`, `reason` (`rule`, `default`, `broadcast`, `malformed`, `unsupported`, `role`), plus `apdu_id`, `type_id`, `ca`, `ioa`, `select`, `direction` where present (§5.5) |
| `ics.verdict` | one per aborted session, after the `OnVerdict` callbacks for its dropped packets | `outcome` (`dropped` or `drop_failed`), `apdu_ids` (array: every APDU whose bytes were dropped, including allowed APDUs dropped as collateral), `trigger_apdu_id`, `error` on failure |
| `ics.session` | one per state change | `outcome` (`aborted`, `reset_sent`, `reset_failed`, `reconnected`, `enforce_unhealthy`, `enforce_healthy`), `target` (`client` / `server`) for reset outcomes, `error` on failure |

- `ruleId` and `action` are the keys the engine already emits
  (`C:pkg/dp/engine/runtime_events.go:332-333`).
- An `ics.decision` with `allow` says a rule allowed it, not that it
  was delivered; an APDU is delivered only if no `ics.verdict` lists it.
  A decoded command is an attempt, not an actuation.
- `reconnected` is emitted on the first STARTDT con of a new incarnation
  of the same client/server pair after an abort, so recovery time can be
  measured from `aborted`.

## 9. Test fixtures from RangerDanger

containd does not ask RangerDanger for captures (E5). L1 builds from
documented synthetic fixtures. If RangerDanger's lib60870 spike lane
commits reference captures to `RD:services/iec104/captures/` on branch
`iec104`, they are extra test data, not a dependency. The README will list SHA256, stack versions, configuration
(COT 2, CA 2, IOA 3, k/w, t0-t3), the CA/IOA/type point map, command
values and endpoints, and a regeneration script. The captures will be
Apache-2.0 test data and contain no lib60870 code.

| Capture | Contents |
|---|---|
| `startup-gi-monitor` | handshake; STARTDT act/con; GI act/con/data (COT 20)/term; types 3, 13, 31 with quality and time; spontaneous (COT 3); S-frames; TESTFR act/con |
| `sbo-double-command` | type 46 select/con, execute/con/term; execute without select (negative); select expiry; execute value ≠ select value |
| `session-management` | STOPDT/STARTDT; TESTFR; t1 timeout; FIN; link loss then reconnect + GI |
| `edge-addressing` | IOA 0, 65535, 65536, 16777215; a second CA |

- Derive Go byte fixtures from these captures with checked-in
  extraction metadata. Go unit tests must not need tshark at run time.
- Split/coalesced variants are deterministic transforms of real bytes
  (cut at every byte; coalesce several APDUs; benign→forbidden and
  forbidden→benign; complete + partial tail). Label them as transforms.
- Types the spike does not emit (45, 47-51, 58-64, 103-107, invalid
  frames) use documented synthetic fixtures. Do not label synthetic
  bytes as captured.
- `abort-reconnect` evidence (two-sided RST, reconnect, GI, >10 min
  fresh telemetry, stale retransmit after a new handshake) comes from
  the containd Linux harness (§10), captured on both endpoints.

## 10. Tests and gates

### 10.1 Unit and contract tests (per lane, `-race`)

- **Decoder:** table tests for every descriptor (sizes, endianness,
  flags); split at every byte; multiple APDUs and objects; select
  placement, no select for 51/64; unsupported vs incomplete. Fuzz APCI,
  ASDU and stream parsing with capture seeds; no panic, bounded
  allocation, consumed-prefix invariant, no event from a partial frame.
- **Schema:** literal JSON → strict decode → validate → marshal →
  compile → preview/match. IOA 0 and > 65535, missing vs zero, numeric
  arrays (not base64), unknown/duplicate keys, null/empty/fraction/
  overflow, incompatible fields, enforce rejected when the decoder is
  off, Direction/ObjectClasses propagation, both shipped US policies
  still load.
- **Dataplane:** fake verdict sink proves exactly-once
  DROP/HOLD/ACCEPT; current-packet DROP despite an updater error;
  callback returns while held; earlier-token resolution; payload and
  token lifetime; seq 0, wrap, SYN, FIN; out-of-order, gaps, overlaps,
  retransmits; bounds, idle cleanup, restart, shutdown; injector
  checksums and both RST targets.
- **Engine:** decoded bytes → real predicate → inline decision →
  outcome event; object/frame aggregation; confirmations and
  spontaneous data are not writes; learn alerts without reset; role
  correct; incarnation cleanup; policy cutover; DNP3 drift regressions
  from real decoded events; offline PCAP sequence parity.

### 10.2 Linux truth harness (new, required)

- **V:** `C:scripts/smoke-dpi.sh:4-16,105-110,224-241` runs a Modbus
  Compose harness through a routed engine; it lets the first write
  succeed and checks only the follow-up block (`:260-280`). NFQUEUE
  Linux unit tests use a fake run loop
  (`C:pkg/dp/capture/nfqueue_linux_test.go:25-38,97-110`). CI
  (`C:.github/workflows/ci.yml:24-36,88-105,125-199`) runs Linux
  `go test -race ./...` and a Docker quickstart; it never runs
  `smoke-dpi.sh`. Nothing today proves first-command prevention or a
  two-sided reset.
- **P:** `test/iec104/compose.yml` (two endpoint containers, the
  branch-built firewall between two disposable networks, loopback-only
  management, no host networking) and `scripts/smoke-iec104.sh`. Run
  on Docker Desktop's Linux VM. Do not change Desktop settings and do
  not run nft/conntrack/route on the macOS host. Add a CI Linux job for
  the same harness.
- Endpoints: lib60870 `cs104_server`/`cs104_client` examples (GPLv3,
  built in the test image only; nothing linked into containd) or the
  RangerDanger spike images. A Go test client is allowed for malformed
  and split cases. The RTU side must expose point state, so the harness
  can check that a denied command did not change it.
- Preflight: NFQUEUE bind and verdict delivery, caps, routes, reset
  capability. Missing kernel support is a **blocked** gate (B6).
- Hard assertions:
  - first forbidden select and first forbidden execute are dropped;
    RTU point state unchanged;
  - the right CA + IOA is allowed; each wrong dimension is denied;
  - benign + forbidden in one packet: whole packet dropped;
  - a split forbidden APDU never completes at the RTU;
  - both endpoint sockets are reset (socket state, not only "RST
    seen");
  - the same client reconnects, completes GI within B1's budget, and
    spontaneous telemetry stays fresh for > 10 minutes with **no** IEC
    entry in `block_flows`;
  - monitoring and confirmations pass both ways;
  - malformed/unknown: reset in enforce, alert in learn;
  - an unrelated allowed session survives;
  - same-5-tuple reuse and stale retransmits cannot bypass;
  - a static enforce fault (DPI off, iec104 decoder off, capture not
    NFQUEUE, queue 0, or a DPI exclusion overlapping the envelope) is
    refused before save on commit, candidate and import;
  - a runtime queue-bind, verdict or reset failure keeps the saved
    config, fails closed on IEC envelope traffic, and reports
    enforcement unhealthy.

### 10.3 US non-regression (containd side)

- Modbus FC 3 reads pass. A restricted FC 6/8 write cannot change the
  server on the **first** attempt. DNP3 FC 1 reads pass; FC 5/6 cannot
  actuate on the first complete attempt. Responses and unsolicited data
  pass. Split/coalesced reads still work. The US 10-minute dynamic sets
  still appear.
- Run `bash scripts/smoke-dpi.sh`, `bash scripts/smoke-forward.sh`, the
  new first-actuation assertions, and `bash scripts/dev-verify.sh
  --with-race`. L6 first fixes both smoke scripts for Linux Bash 5
  (`((x++))` under `set -e`) and adds an NFQUEUE variant of
  `smoke-dpi.sh`; today it runs AF_PACKET and cannot test prevention
  (W8). CI vet/race/lint, UI lint and build, Docker quickstart,
  scans, gofmt. linux/amd64 and linux/arm64 images. Do not weaken an
  existing gate to absorb a new failure.

### 10.4 RangerDanger gates (run by the RangerDanger side)

The candidate image runs in RangerDanger branch `iec104`:

- US, configuration unchanged: `scripts/firewall-smoke.sh`,
  `scripts/lab-commands-smoke.sh`, `scripts/events-smoke.sh`,
  `scripts/substation-smoke.sh`, `scripts/test-suite-smoke.sh`. Counts
  and skips must match `RD:docs/plans/iec104/baseline/README.md`
  (firewall 54/54, lab-commands 69 + 1 skipped, events 10/10,
  substation PASS, test-suite 40/40).
- EU: first-command prevention with device state checked, reconnect
  and freshness, using the EU package policies (§12).
- The digest of every candidate run is recorded beside its result.

## 11. Work breakdown

Six lanes with non-overlapping fences. Each owns its package tests. New
logic goes into sibling files; large existing files get only small
assembly edits. An integration owner (Tony's orchestrator) reserves
version, CHANGELOG, `.github/**`, `deploy/**` and final glue. A lane
that needs an edit outside its fence reports it to the integration
owner; it does not make it.

| Lane | Fence | Work | Depends on |
|---|---|---|---|
| C contract commit (orchestrator lane) | the K0–K7 surfaces in `docs/iec104/contracts.md` only | types, stubs, pass-through, test-fixture adaptation; no behaviour change | — |
| L1 wire + fields | `pkg/dp/ics/iec104/**`, `pkg/dp/ics/eventfields/**` (beyond K3), `pkg/dp/ics/modbus/**`, `pkg/dp/ics/dnp3/**` | parser, events, fixtures; framed adapters for Modbus/DNP3 (K2); DNP3 object-header loop fix (separate commit) | C |
| L2 schema + rules | `pkg/cp/config/**`, `pkg/cp/compile/**`, `pkg/cp/ids/**`, `pkg/dp/rules/**`, `api/http/firewall_rule_handlers.go`, `docs/openapi.yaml` | strict schema, validation, E3 static checks, compile, envelope and evaluator, preview, PATCH, Suricata skip (W4), API docs (incl. K6 health) | C |
| L3 inline + reset | `pkg/dp/capture/**`, `pkg/dp/dpi/**`, `pkg/dp/enforce/**`, `pkg/dp/verdict/**`, `pkg/dp/session/**` | K1/K2/K7 behaviour: token lifecycle, settle, source events, snaplen, invalid routing, envelope mark steering, reassembly bounds, raw RST injector | C |
| L4 engine + consumers | `pkg/dp/engine/**`, `pkg/dp/flow/**`, `pkg/dp/signatures/**`, `pkg/dp/anomaly/**`, `pkg/dp/events/**`, `pkg/dp/pcap/**`, `pkg/dp/learn/**`, `pkg/dp/inventory/**`, `pkg/dp/conntrack/**`, `pkg/app/engine/**`, `api/engine/**`, `api/http/**` (except L2's file) | incarnations, holdback, abort, decision/verdict/session events, `/flows` session rollup, learner/inventory gate (§7.4), K6 health, registration, offline metadata, drift readers, signature/exception fixes, `/events` engine-unreachable error (separate commits) | L1 + L2 + L3 |
| L5 UI | `ui/lib/api*.ts`, `ui/app/ics/**`, `ui/app/firewall/**`, `ui/app/wizard/**`, `ui/app/alerts/**`, `ui/app/config/**`, `ui/app/events/**`, `ui/app/sessions/**`, `ui/app/flows/**`, `ui/app/dataplane/**`, `ui/tests/**` | Type ID/class/CA/IOA editor, learn/enforce, decoder toggle (incl. `dpiIcsProtocols` normalisation in `ui/app/config/config-utils.ts`), decision/verdict/reset evidence, health, in existing UI style | C (+ L2 for live API) |
| L6 Linux harness | `test/iec104/**`, `scripts/smoke-iec104.sh`, `scripts/smoke-dpi.sh`, `scripts/smoke-forward.sh`, `scripts/preflight-iec104.sh`, `test/data-smoke/**`, the shellcheck list in `scripts/dev-verify.sh` | §10.2 harness, first-command US assertions, W8 smoke fixes plus NFQUEUE variant; hands the CI job and any `deploy/` change to the integration owner | real gate after L1–L4 |
| Integration (orchestrator) | `AGENTS.md`, `CHANGELOG.md`, `.github/**`, `deploy/**`, `docs/iec104/**`, `go.mod`/`go.sum` | merges, full suites, release notes, candidate build (E1) | all |

- **Drift split:** L1 makes the decoders emit the §5.4 types and adds
  the accessors; L4 changes the readers
  (`C:pkg/dp/anomaly/detector.go:241,243,364,434`,
  `C:pkg/dp/signatures/builtins.go:116-123`). Each is a separate
  maintenance commit with tests fed by real decoded events.
- Import rules: `eventfields` depends on nothing; DPI never imports the
  IEC104 decoder; capture knows nothing of ASDUs or policy; the session
  injector knows TCP tuples, not policy.
- **Critical path:** L3 kernel proof → L4 holdback/abort → L6 real
  prevention + reconnect → US/EU gates.
- **Checkpoints:**

| Date | Checkpoint |
|---|---|
| 2026-10-12 | §5 contracts committed on `iec104` (`docs/iec104/contracts.md`) |
| **2026-10-13** | Two-endpoint deferred verdict + two-sided RST work on Docker Desktop (B6 if not) — **met 2026-10-09** (§0) |
| 2026-10-16 | Parser and schema fixtures pass; first wire slice |
| **2026-10-23** | Integrated first-denied-command + reconnect gate passes |
| 2026-10-30 | Split/out-of-order/failure hardening; US + EU full gates |
| **2026-11-02** | Candidate accepted; digest frozen; Tony merges and publishes |
| 2026-11-03..06 | RangerDanger install, SSD, pre-course retest |

If a bold checkpoint slips, report to Tony with what failed. UI polish
and non-gate consumers may be deferred; D10, first-command prevention
and all-frame inspection may not.

## 12. RangerDanger interface

What the RangerDanger backend sends and reads. Keep these stable;
any change needs a matching RangerDanger change.

### 12.1 Endpoints used

| Call | Use |
|---|---|
| `GET /api/v1/health` | readiness. **V:** today it is hardcoded liveness (`C:api/http/server.go:389-395`), and engine health is hardcoded too (`C:pkg/app/engine/runtime_handlers.go:286-292`). **New (L4):** add an `iec104Enforcement` object `{active: bool, healthy: bool, reason: string}` from the engine; L2 documents it in `docs/openapi.yaml`. `active` = at least one enforce envelope is loaded in the runtime. Inactive with no fault is `{false, true, ""}`. If the engine is unreachable, the status stays 200 and the object is `{false, false, "engine unreachable"}`. |
| `GET /api/v1/events?limit=N` | bare JSON array of events (`C:pkg/dp/events/store.go:21-34`) |
| `GET /api/v1/flows` | a rollup of the event ring, not the engine flow table (W1; `C:api/http/runtime_telemetry_handlers.go:102-123`). After an abort it hides the old IEC incarnation's flow group; the events stay in `/events` (E4). `GET /api/v1/conntrack` (`:278`) is not required. |
| `GET /api/v1/config` | rule summaries; reads `firewall.rules[].ics` |
| `POST /api/v1/config/candidate` then `POST /api/v1/config/commit` | loads and activates a whole policy JSON. `POST /api/v1/config/import` only saves; it does not activate. After import, RangerDanger must commit and then check health (K6). |
| `/api/v1/pcap/*` | student captures |

RangerDanger's client calls `/api/v1/sessions` today, a route containd
never had (`RD:backend/internal/containd/client.go:296`). RangerDanger
moves it to `/api/v1/flows` on its side; containd adds no `/sessions`.

### 12.2 Event JSON

RangerDanger decodes these keys: `id` (string or number), `timestamp`,
`kind`, `srcIp`, `dstIp`, `proto`, `transport`, `srcPort`, `dstPort`,
`attributes`. Attribute keys it reads today: `action`, `ruleId`,
`function_code` (Modbus/DNP3 only), `anomaly_type`, `message`. For
IEC104 it will read the §5.5 and §8.4 keys. Keep `proto` as the wire
key. Numbers are JSON numbers.

### 12.3 Config JSON

RangerDanger reads `firewall.rules[].ics` as `{protocol, functionCode,
readOnly}` today and will add `typeIds`, `classes`, `direction`, `ca`,
`ioa`, `mode`. `GET /api/v1/config` must emit IEC fields as numeric
arrays and IOA ranges as `{start, end}` objects, the same shape that is
accepted on input.

### 12.4 EU policy shape

EU policies use the same top-level keys as
`RD:lab-definitions/firewall/substation-improved.json`
(`schema_version`, `system`, `interfaces`, `zones`, `routing`,
`dataplane`, `pcap`, `firewall`, `ids`, `services`), with:

- `dataplane`: `dpiEnabled: true`, `dpiMode: "enforce"`,
  `nfqueueGroup: 101` (non-zero), `nflogGroup: 100`,
  `dpiIcsProtocols: {"modbus": true, "iec104": true}`.
- A `lan4` interface and zone for the control centre, subnet
  `10.60.60.0/24`, bound by `CONTAIND_AUTO_LAN4_SUBNET`
  (**V:** `C:api/http/interface_autoassign.go:38`). The RTU zone and
  IPs are fixed by RangerDanger in its increment 3; tests must not
  hardcode them.
- Rules in this order (example; IPs illustrative). The point map here
  (type 46 at CA 1 / IOA 2001) is illustrative and differs from the
  RangerDanger spike map (command at IOA 3001, measurement at IOA 2001);
  the decoder and the harness must not hardcode either.

```json
[
  {"id": "cc-rtu-iec104-session", "sourceZones": ["lan4"], "destZones": ["lan1"],
   "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
   "protocols": [{"name": "tcp", "port": "2404"}],
   "ics": {"protocol": "iec104", "readOnly": true, "mode": "enforce"},
   "action": "ALLOW", "log": true},
  {"id": "cc-rtu-breaker-command", "sourceZones": ["lan4"], "destZones": ["lan1"],
   "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
   "protocols": [{"name": "tcp", "port": "2404"}],
   "ics": {"protocol": "iec104", "typeIds": [46], "classes": ["control"],
           "direction": "request", "ca": [1], "ioa": [{"start": 2001, "end": 2001}],
           "mode": "enforce"},
   "action": "ALLOW", "log": true},
  {"id": "rtu-cc-command-confirm", "sourceZones": ["lan4"], "destZones": ["lan1"],
   "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
   "protocols": [{"name": "tcp", "port": "2404"}],
   "ics": {"protocol": "iec104", "classes": ["control"], "direction": "response", "mode": "enforce"},
   "action": "ALLOW", "log": true},
  {"id": "deny-other-iec104", "sourceZones": ["lan4"], "destZones": ["lan1"],
   "protocols": [{"name": "tcp", "port": "2404"}],
   "ics": {"protocol": "iec104", "mode": "enforce"},
   "action": "DENY", "log": true}
]
```

  All rules use the session tuple (client zone → RTU zone, B8),
  including the response rule. The last rule is explicit for the
  student log; an envelope no-match is DENY anyway (§6.5). All other
  sources to 2404 are denied at L4. The first rule also passes STOPDT
  (B7); the STOPDT alert signature makes it visible.
- Milestone A policies (`ics: {}` on 2404) must keep working unchanged.

### 12.5 Candidate images and release

- Build candidates from the containd `iec104` branch as linux/amd64 and
  linux/arm64 images, tagged `ghcr.io/tonylturner/containd:iec104-<sha>`
  (E1). Tony pushes the tag and hands RangerDanger the digest. Never a
  `v*` tag (§0).
- RangerDanger runs §10.4 with that digest. Only after US **and** EU
  gates pass does Tony merge to containd `main` and publish `:latest`.
- Release notes must state all nine §4.1 changes.

## 13. Out of scope for B

Standards-complete ASDU coverage, full APCI session compliance, SBO
transaction enforcement, TLS (IEC 62351), IPv6, NAT, non-standard
ports, transparent telemetry continuity, holdback/reset for US
protocols, IEC-aware inventory/learning/export/Suricata, and
RangerDanger's own changes (policy comparison, validators, UI), which
RangerDanger owns on its side.
