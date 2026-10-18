# Milestone B — frozen contracts

- Base: `iec104` @ 79668745 (main 8ebc4229 + preflight harness + netlink v1.11.2 / go-nfqueue v2.1.0). Implemented by c98e4540; §K8 records the amendments that implementation forced.
- Binding spec: `docs/iec104/milestone-b.md` (corrected; §0 lists decisions E1–E5 and corrections W1–W8). This file is committed as `docs/iec104/contracts.md`.
- Reviewed by two independent critiques (2026-10-09); every blocker is resolved below.
- Lanes consume these contracts and never edit them. A lane that needs a change reports it to the orchestrator.

## K0 Commit rules

- One contract commit on `iec104`. It contains: the types, interfaces, constants, and stub constructors below; contract tests; and the smallest call-site edits that keep `go build ./...` (darwin + `GOOS=linux`), `go vet ./...` and `go test ./...` green.
- **No behaviour change.** Every engine handler exit returns `Decision{Action: Accept}` with its side effects unchanged. Snaplen stays as it is. Undecodable packets are still accepted inside capture. No production decoder implements `StreamDecoder` yet. Lanes change behaviour in their own commits.
- Import rules:
  - `eventfields` imports stdlib only.
  - `capture` never imports `dpi`, `rules`, `verdict`, `session`, or ICS packages. Do not add `dpi → capture`, because capture already reaches dpi through `events`.
  - `dpi` never imports an ICS decoder.
  - `session` knows tuples, not policy.

## K1 Inline verdicts — `pkg/dp/capture` (new `inline.go`)

```go
// Token identifies one inline-delivered packet. Comparable; map key. Zero = not inline.
type Token struct{ gen uint64; id uint32 }
func NewToken(gen uint64, id uint32) Token // tests and fakes; panics on gen 0 (reserved for the zero Token)
func (t Token) Inline() bool
func (t Token) Generation() uint64
func (t Token) String() string // logs only; never in event JSON

type Verdict uint8
const ( VerdictAccept Verdict = iota + 1; VerdictDrop )

type Disposition uint8
const ( Accept Disposition = iota; Drop; Hold )

type Resolution struct{ Token Token; Verdict Verdict }
type Decision struct {
    Action   Disposition  // current packet
    Reason   string       // machine reason; logs/metrics only
    Resolved []Resolution // earlier Held tokens of the same source
}
type Handler func(pkt Packet) Decision

type Settler interface {
    // Settle submits verdicts for outstanding tokens and returns after submission,
    // one error per request (nil = submitted). Rejected requests (ErrStaleToken,
    // ErrUnknownToken, ErrQueueClosed, ErrNotInline) submit nothing and produce no OnVerdict.
    Settle(res ...Resolution) []error
}
type VerdictFunc func(tok Token, v Verdict, err error)

type SourceEvent struct {
    Generation uint64
    Ready      bool  // true: bound and delivering; false: down (all outstanding tokens of this generation are gone)
    Err        error
}
var ErrStaleToken, ErrUnknownToken, ErrQueueClosed, ErrNotInline error
```

- `Config` gains `OnVerdict VerdictFunc` and `OnSource func(SourceEvent)`.
- `Manager.Settler() Settler` returns a stable handle from construction. Before the queue binds, it rejects requests with `ErrQueueClosed`. In observational modes it rejects them with `ErrNotInline`.
- The engine's `captureRunner` interface and its test fakes gain `Settler()`.

**Lifetime and exactly-once.**
- A token is registered as outstanding **before** the handler is called. It stays outstanding until its verdict is submitted, or its generation goes down.
- Generation numbers are unique per process (a global atomic counter, starting at 1), across Manager instances and Reconfigure.
- A held packet lives at most a few seconds (§8.1 bounds). Within one generation, a packet ID cannot wrap while its token is still outstanding.

**OnVerdict cardinality.** Exactly one call per token that:
- (a) the handler returned `Hold` or `Drop` for, or that a `Resolved` or `Settle` entry named; or
- (b) was accepted immediately, but submission failed.

A successful immediate Accept of a never-held packet produces no call (hot path).

When a generation goes down, each of its outstanding tokens gets one call, `(VerdictDrop, ErrQueueClosed)`. The kernel drops packets that are queued when the queue socket closes (no bypass). Checkpoint 1 proved this for new packets only; L3 must test it for packets that are held at close.

**Ordering and reentrancy.**
- Capture holds no token or source mutex while it calls the handler or OnVerdict.
- `Settle` may be called from any goroutine, including from inside a handler. It never calls OnVerdict on the caller's stack.
- If `Settle` names the token of a callback that is still running, that request is staged and applied when the callback returns. Drop wins over a conflicting Accept that is not yet submitted.
- Within one decision batch (the current packet plus `Resolved`), every Drop is submitted before any Accept.
- OnVerdict and OnSource run on one capture-owned completion goroutine, in submission order.
- A generation's down event and its close completions are delivered before the first packet of the next generation.
- `Stop` drains completions before it returns. If the completion queue overflows, that is a source failure (`OnSource{Ready:false, Err}`); completions are never silently discarded.
- `SetVerdict` may run on any goroutine. That needs netlink ≥ v1.11.2: v1.11.1 blocked Send behind Receive for 7 s in checkpoint 1. A nil return means **submitted**, not kernel-confirmed.

**Start.** NFQUEUE `Start` returns nil only after the queue is bound and registered. After that, supervise-loop rebinds are reported through `OnSource`.

**Packet additions** (capture.go):

```go
type TCPFlags uint8 // FIN 0x01 SYN 0x02 RST 0x04 PSH 0x08 ACK 0x10 URG 0x20 ECE 0x40 CWR 0x80
type TCPMeta struct {
    Valid  bool // header decoded; Seq 0 is a real value
    Seq, Ack uint32
    Flags  TCPFlags
    Window uint16
}
// on Packet:
TCP     TCPMeta
Token   Token
Mark    uint32 // NFQUEUE skb mark when HasMark; opaque to capture
HasMark bool
Invalid string // "" = decoded. Else an exported reason constant: truncated, ip_version, ip_header,
               // fragment, ipv6 (extension headers only; plain IPv6 TCP/UDP is valid), protocol, tcp_header, udp_header
               // Tuple fields are best effort. Payload is always an owned copy.
```

- `func DecodeIPPacket(data []byte) Packet` is exported. It returns a Packet with `Invalid` set and never fails silently. Offline PCAP and AF_PACKET use it, so TCP parsing lives in one place (`decode_ip.go`; today it is duplicated at `afpacket_linux.go:189-201` and `pcap/analyze.go:305`). It detects IPv4 MF / fragment-offset.
- **Envelope mark.** containd reserves skb-mark mask `0x0f000000`. The value `0x01000000` means "steered by an IEC104 envelope rule". L3's nft steering sets it before `queue`. L4 uses it only for packets whose tuple cannot be trusted (`Invalid != ""`): if the mark is set, drop; if not, accept (US unchanged).
- L3 behaviour, not in the contract commit:
  - inline `MaxPacketLen` 65535;
  - invalid packets go to the handler instead of being accepted inside capture.

## K2 Framed streams — `pkg/dp/dpi` (new `stream.go`; `ConsumedBytes` removed)

```go
type StreamDir uint8
const ( DirUnknown StreamDir = iota; ClientToServer; ServerToClient )

type StreamView struct {    // read-only; valid only during ParseStream
    Session string          // incarnation ID (K4) or, for legacy streams, the directional flow hash
    Dir     StreamDir
    Base    int64           // absolute offset of Bytes[0] (see offsets)
    Bytes   []byte
}
type DecodedFrame struct{ Start, End int64; Events []Event } // [Start,End) absolute
type StreamResult struct {
    Frames   []DecodedFrame // contiguous from Base, in order
    Consumed int            // Frames[last].End - Base, or 0
    NeedMore bool           // incomplete tail; not an error
}
type FrameError struct {
    Offset int64  // absolute start of the APDU/frame that cannot be framed
    Reason string
    Event  Event  // its single malformed event: identity + every safely decoded attribute
}
func (e *FrameError) Error() string

type StreamDecoder interface {
    Decoder
    Protocol() string // event Proto, e.g. "iec104", "modbus", "dnp3"
    ParseStream(state *flow.State, v StreamView) (StreamResult, error)
}
```

- **Malformed vs framing error.**
  - If the frame boundary is intact but the content is bad (layout, profile, role, unsupported type), the decoder returns an ordinary `DecodedFrame` whose event kind is `malformed` or `unsupported`, and it continues.
  - If the stream cannot be framed (bad start octet, bad length, reserved control bits), the decoder returns the frames before it plus a `*FrameError`. Nothing after that offset is parsed.
- **Invariants** (contract test):
  - Two frames split over three packets, with a trim between them, give `[0,n1)` and `[n1,n1+n2)`.
  - `Consumed` = the complete prefix.
  - No event comes from a partial frame.
  - Each frame's events are emitted exactly once, never again on retransmission.
  - Decoders keep no reference to `Bytes`.

```go
// ParsedPacket — existing fields kept; added:
TCPSeqValid bool      // TCPSeq is real (Seq 0 valid)
Offset      int64     // absolute start of Payload in this direction (only when HasOffset)
HasOffset   bool      // L4 tracked the handshake and computed Offset
Session     string    // required when HasOffset
Dir         StreamDir // required when HasOffset

type StreamErrKind uint8
const ( StreamOverflow StreamErrKind = iota + 1; StreamOverlapConflict; StreamOutOfOrderLimit )
type StreamError struct{ Kind StreamErrKind; Offset int64; Proto string }
func (e *StreamError) Error() string

type InspectResult struct {
    Proto    string         // framed decoder's Protocol(), "" if none
    Events   []Event        // all events: frame events + the FrameError/StreamError malformed event, once
    Frames   []DecodedFrame // framed decoder only, absolute ranges
    Framed   bool           // a StreamDecoder handled this direction
    NeedMore bool
    Gap      bool           // bytes buffered beyond a hole; nothing after it parsed
    Err      error          // *FrameError or *StreamError
}
func (m *Manager) Inspect(state *flow.State, pkt *ParsedPacket) InspectResult
func (m *Manager) EndStream(session string) // drop both directions (FIN/RST/abort/expiry/generation change)
```

- **Offsets.**
  - `HasOffset=true`: L4 owns handshake tracking, ISN-relative seq/ack unwrapping, and wrap epochs. Offset 0 is the first byte after the SYN. DPI never unwraps sequence numbers itself.
  - `HasOffset=false` (US midstream, offline without SYN): the stream key is the directional `flow.Key.Hash()`. If `TCPSeqValid`, reassembly is sequence-aware, as today; append mode is used only when there is no sequence metadata. Legacy offsets count from the first byte seen, not from the SYN.
  - IEC parsing never runs without `HasOffset`.
- **Who owns which bytes.**
  - The DPI manager compares an overlap byte for byte only against bytes it still holds (unconsumed buffer and OOO). A conflict gives `StreamOverlapConflict`. Bytes below its consumed watermark are treated as duplicates (no events).
  - L4 keeps the byte identity and frame decisions for every received range until its retention obligation ends. That includes consumed bytes whose packet is still held.
  - L4 checks overlaps below the DPI watermark against that history **before** it calls Inspect.
  - L4 releases a token only when its whole `[Offset, Offset+len(Payload))` range is covered by allowed frame decisions and proven-identical bytes. `Frames` being empty, `NeedMore=false`, or `Gap=false` is never enough. Unknown identity aborts.
  - In an IEC enforce envelope, `Framed=false` is an enforcement failure, never an Accept.
- **Errors.**
  - The manager adds the malformed event for a `StreamError` itself, using the decoder's Proto.
  - On any `Err`, the manager discards that direction's buffer.
  - A legacy stream starts fresh with the next packet (today's behaviour).
  - A session stream (`HasOffset`) is marked failed until `EndStream`.
  - All callers process `Events` before they handle `Err`. Today engine and PCAP drop events on error (`engine.go:498-501`, `pcap/analyze.go:141-144`).
- **Dispatch.** `OnPacket` stays the event-only entry point and uses the same parser. On TCP, the manager calls `ParseStream`, never `OnPacket`, for a `StreamDecoder`, on both paths. Only a `StreamDecoder` trims the buffer.
- **Contract commit.** Migrate the existing stream mock and the two integration tests (`reassembly_test.go:189-284`) to the new API, together with the manager's framed dispatch and trim branch. The legacy decoder path stays unchanged.

## K3 Event fields — new `pkg/dp/ics/eventfields` (stdlib only)

```go
func Uint8(a map[string]any, k string) (uint8, bool)
func Uint16(a map[string]any, k string) (uint16, bool)
func Uint32(a map[string]any, k string) (uint32, bool)
func Int64(a map[string]any, k string) (int64, bool)
func Float64(a map[string]any, k string) (float64, bool)
func Bool(a map[string]any, k string) (bool, bool)
func String(a map[string]any, k string) (string, bool)
func Strings(a map[string]any, k string) ([]string, bool) // []string or []any of strings; owned copy
func SessionID(runID string, seq uint64) string            // "<runID>-<seq lowercase hex>"
func APDUID(session string, dir byte /* 'c' | 's' */, start int64) string // "<session>/<c|s>/<start decimal>"
```

- **Integer accessors** accept Go integer kinds when the value is in range. They accept `float64` or `json.Number` only when the value is exactly integral, finite and in range. Absent, nil, a fraction, NaN/Inf, a negative value for an unsigned type, an out-of-range value, or the wrong kind all give `ok=false`. They never truncate.
- **Bool** accepts only `bool`.
- **Constants** cover every key in K4 and the §8.4 keys (`decision`, `ruleId`, `action`, `mode`, `reason`, `outcome`, `target`, `apdu_ids`, `trigger_apdu_id`, `session_id`). They also cover the existing shared keys: `function_code`, `unit_id`, `is_write`, `direction`, `error`, `object_groups`, `message`, `anomaly_type`.
- **Event kind constants:** `ics.decision`, `ics.verdict`, `ics.session`. **Proto constant:** `iec104`.
- **Tests** cover the in-memory form and the form after JSON marshal/unmarshal.

## K4 IEC104 events (spec §5.5 + W5–W7)

**Amendment (Tony, 2026-10-18).** Type 1 (`M_SP_NA_1`) and Type 30
(`M_SP_TB_1`) have B descriptors and class `monitor`. Both decode the
single-point information (SIQ) state and quality; Type 30 also decodes
CP56Time2a. SQ=1 is accepted for Type 1, alongside Types 3 and 13; Type 30
requires SQ=0.

- **Proto and kinds.** `Proto="iec104"`. Kinds: `request`, `response`, `apci`, `malformed`, `unsupported`. One event per information object, and one per S-frame, U-frame or error APDU.
- **Attribute Go types** are as in §5.5. `value` is typed by descriptor:

  | Element | `value` type |
  |---|---|
  | SIQ, DIQ, SCO, DCO, RCO state | `uint8` |
  | normalized (raw) | `int16` |
  | scaled | `int16` |
  | short float | `float32` |
  | bitstring | `uint32` |
  | system types | no `value`; they use `qualifier` |

  `quality` and `qualifier` are `uint8`.
- **Time.**
  - `source_time` is ISO 8601 with no zone.
  - The year field must be 0..99; 100..127 is `malformed`. Year = 2000 + field, a B profile assumption.
  - Minute bit 6 (GEN/RES1) is ignored.
  - An impossible calendar value is `malformed`.
- **IDs.**
  - L4 supplies `Session` for every framed IEC parse. Decoders build IDs only from `StreamView`; they never allocate incarnation IDs.
  - Run ID: random 128-bit lowercase hex, created once per live engine lifetime and once per offline-analysis run.
  - `session_id` = `eventfields.SessionID(runID, seq)`, with seq monotonic inside the run.
  - `apdu_id` = `eventfields.APDUID(...)`.
- **Errors.** `error` is present on `malformed` and `unsupported`. Profile and role restrictions start with `"profile: "`.
- **No `function_code` and no `address`** on IEC104 events.
- **L1 exports** (package `pkg/dp/ics/iec104`):
  - `type Decoder`, `func NewDecoder() *Decoder` (registered as `*iec104.Decoder` → `"iec104"` in `engine/decoders.go`), `Ports() → tcp {2404}`, `Protocol() "iec104"`;
  - `func ClassOf(typeID uint8) string`;
  - `func SafeRead(attrs map[string]any) bool`. This is the exact readOnly set of §6.1 including the W7 correction. It is false for broadcast CA, `malformed` and `unsupported`.
- **Decision and outcome events** (§8.4) are engine events with `Proto="iec104"` and `session_id`.
  - `ics.decision` is emitted for every `deny` and `would_drop`. For `allow`, only when the rule has `log:true`.
  - `ics.verdict.apdu_ids` lists every identified dropped APDU, including the known start of an incomplete tail. Do not invent IDs for unknown boundaries.
  - `trigger_apdu_id` is omitted for timeout, queue and transport aborts that have no identified APDU.

## K5 Policy schema (spec §6)

Both CP `config.ICSPredicate` and DP `rules.ICSPredicate` gain these fields (each package has its own `IOARange`):

```go
TypeIDs []int      `json:"typeIds,omitempty"` // 1..255  (int in BOTH packages: the DP Snapshot is JSON-marshalled to the engine, api/engine/client.go:42-50; []uint8 would be base64)
Classes []string   `json:"classes,omitempty"` // monitor|control|system|unknown
CA      []uint16   `json:"ca,omitempty"`      // 0..65534
IOA     []IOARange `json:"ioa,omitempty"`
type IOARange struct{ Start uint32 `json:"start"`; End uint32 `json:"end"` } // 0..16777215
```

DP `rules.ICSContext` gains `IEC104 *IEC104Context`. Direction stays in the existing `ICSContext.Direction`.

```go
type IEC104Context struct {
    APCIType  string  // "I" | "S" | "U"
    TypeID    *uint8
    CA        *uint16
    IOA       *uint32
    Class     string
    SafeRead  bool    // iec104.SafeRead
    Broadcast bool    // I-frame with CA 65535
    Malformed, Unsupported bool
}
func (e *Evaluator) IEC104Envelope(ctx EvalContext, globalMode string) (matched bool, mode string)
func (e *Evaluator) EvaluateIEC104(ctx EvalContext) (Action, *Entry) // IEC rules only; (DENY, nil) on no match
// pkg/cp/compile:
func ICSPredicate(p config.ICSPredicate) rules.ICSPredicate // the one CP→DP mapping; compile and HTTP preview both use it
```

- **Envelope.** It matches the opener-oriented L3/L4 scope of the IEC rules and ignores ASDU predicates. Any match whose effective mode is enforce (rule > global) makes the envelope enforce. On no match, L4 applies the envelope mode (G14b). L4 builds every IEC `EvalContext` with the session tuple (source = opener, destination = server, port 2404). It never rewrites `flow.Key.Dir`, which drives US service-port selection (`policy_eval.go:305-309`).
- **Snapshot.Firewall** is the only envelope input for L3's nft steering. There is no private L2/L3 envelope representation.
- **Contract commit:**
  - pass-through in `ics_json.go` (`icsPredicateJSON`, `MarshalJSON`, the raw `UnmarshalJSON` struct);
  - CP→DP copy through `compile.ICSPredicate`, which also copies the dropped `Direction` and `ObjectClasses`;
  - `icsPredicateEmpty` counts the new fields and `Mode`;
  - stubs: `IEC104Envelope` returns `(false, "")`, `EvaluateIEC104` returns DENY;
  - a test that CP JSON → Snapshot → engine HTTP JSON → Snapshot round-trips the four fields as numeric arrays.
- **L2 implements:**
  - strict decode: unknown and duplicate keys; `null` or `[]` on the new fields; keys forbidden per protocol, by presence, so `writeOnly:false` on iec104 is rejected; `mode` counts as a semantic field;
  - validation, the evaluator, preview and PATCH;
  - `SchemaVersionCurrent` `0.1.7` (0.1.x configs still upgrade, `version.go:95-99`).
- **Presence** is checked at decode time and is not stored. `Validate` rejects programmatic non-nil empty lists.
- **The decoder toggle** follows the existing rule (`engine/decoders.go:72-86`): a protocol that is not configured is enabled, and `iec104:false` disables it. E3's "decoder off" means an explicit `false`.

## K6 Health, flows, import

- **Health shape.** `GET /api/v1/health` and the engine's `/health` add `"iec104Enforcement": {"active": bool, "healthy": bool, "reason": string}`.
  - `active` describes the loaded runtime envelope, not the saved config.
  - `healthy=false` covers queue bind, verdict submission, reset send, injector availability, and bounded-worker failures.
  - Inactive with no fault is `{active:false, healthy:true, reason:""}`.
- **Recovery.** `enforce_healthy` is emitted only after readiness is back (`OnSource{Ready:true}`).
- **Engine unreachable.** Management keeps HTTP 200 liveness, so the US is unchanged, and returns `{active:false, healthy:false, reason:"engine unreachable"}`. It never invents healthy.
- **Static causes** (DPI off, iec104 explicitly off, capture not NFQUEUE, queue 0, DPI exclusion overlapping the envelope) are validation errors on commit, candidate and import (E3).
- **Import.** `/config/import` saves only and does not activate. Clients must commit and then check health.
- **Flows.** `/api/v1/flows` stays the event rollup (E4).
  - IEC events, including derived evidence that carries `session_id`, group by `session_id`. Both wire directions of one incarnation form one group, and incarnations that share a tuple are never merged.
  - `FlowSummary` gains `SessionID string \`json:"session_id,omitempty"\``.
  - Aborted incarnations are filtered before the `limit` is applied. The store keeps a bounded aborted-session set for as long as any retained event could re-create that group.
  - Non-IEC grouping is unchanged.

## K7 Reset injector — new `pkg/dp/session`

```go
type Reset struct {
    Src, Dst netip.AddrPort // RST is sent with source Src to Dst (Src spoofed as the peer)
    Seq      uint32
}
type Injector interface {
    SendRST(r Reset) error // one payload-free IPv4 RST; route-selected egress; nil = socket submission
    Close() error
}
func NewInjector() (Injector, error) // linux: opens raw IPPROTO_RAW/IP_HDRINCL; others: ErrUnsupportedPlatform
var ErrUnsupportedPlatform error
type Fake struct{ /* records Resets; configurable error */ } // implements Injector
```

- L4 picks each target's tuple and its forwarded sequence, consumes challenge ACKs, bounds the retries (≤ 3 within 1 s), and deletes conntrack afterwards (`pkg/dp/conntrack`). The reset worker starts after the abort's trigger token has its OnVerdict completion.
- The contract commit adds the interface, `Fake`, and the non-linux `ErrUnsupportedPlatform`. The linux constructor returns `ErrUnsupportedPlatform` until L3 implements it. The checkpoint-1 builder (`test/iec104/preflight/firewall_linux.go`, `sendRawRST`) is the reference.

## K8 Amendments after the contract commit (c98e4540)

These override the text above where they differ.

- **K5 `icsPredicateEmpty`** counts the four new fields only, not `Mode`. Counting `Mode` would make template L4 rules that carry `ics.mode` stop matching in the HTTP preview (`api/http/firewall_rule_handlers.go:204-211`, `pkg/cp/templates/templates.go:87-88`).
- **K5 `compile.ICSPredicate`** does not copy `Direction` and `ObjectClasses` yet. L2 adds that copy in its own commit; it is US-visible change #2 (spec §4.1). L2 also switches the HTTP preview to `compile.ICSPredicate`.
- **K2 errors.** Only framed errors (`*FrameError`, `*StreamError`) discard or fail a stream. A legacy decoder's `OnPacket` error passes through in `Err` unchanged and discards nothing, as today. A `StreamDecoder` must return only `*FrameError`; L3 makes the manager wrap any other error as a `FrameError` at `v.Base` with a synthesized malformed event.
- **K2 dispatch.** The first supporting `StreamDecoder` (registration order) frames a direction; other StreamDecoders are skipped on TCP. Inspect on a failed session stream returns `Framed=true`, the same `Err`, and no events. A `HasOffset` packet without `Session` or `Dir` is not framed (`Framed=false`; the IEC caller fails closed).
- **K2 sequence numbers — correction of "as today".** Today the engine and PCAP pass no sequence number (`pkg/dp/engine/engine.go:470-475`, `pkg/dp/pcap/analyze.go:134-141`). The reassembler then treats every later segment as a retransmission, so on a persistent TCP connection only the first PDU per direction is ever decoded, and every later packet re-reports it (verified 2026-10-09 against main 8ebc4229: read FC3 then write FC6 on one connection → three FC3 events, no FC6). L4 fills `TCPSeq`/`TCPSeqValid` from `capture.Packet.TCP` on both paths. L3 makes reassembly with `TCPSeqValid=false` append in arrival order.
- **K1.**
  - L3 adds `ErrInvalidVerdict` for a `Settle` entry whose Verdict is neither Accept nor Drop.
  - Observational sources (AF_PACKET, NFLOG) ignore the Decision.
  - L3 owns "NFQUEUE Start returns nil only after the queue is bound" (today `startNFQueue` returns before `nfqueue.Open`, `pkg/dp/capture/nfqueue_linux.go:58-70`).
  - L4 owns migrating `pkg/dp/pcap/analyze.go:320-380` to `capture.DecodeIPPacket`.
- **K3.**
  - `Float64` accepts finite `float32`, `float64` and `json.Number`, plus Go integers up to 2^53 in magnitude.
  - The integer accessors reject `float32`.
  - `DirClient`/`DirServer` are the `APDUID` direction bytes.
- The DP `rules.ICSPredicate` keeps its existing untagged fields; only the four new fields carry JSON tags. Engine decoding is case-insensitive, so this is acceptable. Do not retag existing fields: that would change the snapshot wire format.
- **K4 non-finite short floats (Tony, 2026-10-09).** A short float (R32) whose bits are NaN or ±Inf is not `malformed`. The object keeps its normal kind and attributes. `value` is omitted, because JSON cannot carry the number, and `value_invalid` (bool) is `true`. `value_invalid` is absent on every other object. This covers monitor type 13 and set-point commands 50 and 63 alike. Type 36 has no B-profile descriptor and stays `unsupported`. Policy never matches on `value`, so a command's decision is unchanged.
- **K1/K6 envelope steering fails closed until this engine owns the queue (E3, 2026-10-09).**
  - The no-bypass kernel drop covers only a queue with no consumer. When another process holds the queue number, the engine's bind fails and that process decides envelope traffic. The L6 harness showed this: commands reached the RTU while health was correctly unhealthy.
  - IEC104 envelope steering therefore queues to N only while this engine's queue is bound and registered (Start returned nil, no queue-bind fault stands). In every other state, nft drops envelope traffic.
  - The state follows the engine: drop before the first bind and while a bind fault or source-down stands; queue once bound or rebound.
  - Each ruleset apply writes the current state; a rule reapply never opens the envelope on an unbound queue.
  - The switch is atomic and touches neither non-envelope rules nor the US Modbus/DNP3 queue steering, which keep 0.1.31 behaviour.
  - The nft mechanism (jump chain, verdict map or set) is L4's choice.
  - Implemented as the regular chain `iec104_envelope` (6a0bf6ff); each switch is one `flush chain` + `add rule` transaction.
  - The envelope opens only when the queue the installed ruleset steers to equals the group this engine has bound. After a Reconfigure to a new group, it stays closed until the rules are reapplied.
  - A failed switch raises the `steering` health fault (enforcement unhealthy). A failed open still drops. After a failed close, the kernel state is unknown and the fault is the only signal. The fault clears on the next successful switch or apply.
