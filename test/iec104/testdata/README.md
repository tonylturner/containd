# IEC 60870-5-104 reference captures (lib60870 wire traffic)

Test data for the IEC104 decoder and enforcement engine. The
pcaps hold protocol bytes only; they contain no lib60870 code. They are
Apache-2.0 test data under the repository licence. The programs that produced
them (`test/iec104/endpoint/`) are GPLv3 and are not part of containd.

Every byte here is **captured**, never hand-edited. The `malformed.pcap`
scenarios come from the pure-Go `test/iec104/malformer` client (marked
"malformer" below); all other traffic is lib60870-C on both ends.

## How they were produced

```sh
test/iec104/capture/capture.sh            # writes into test/iec104/testdata/
```

- Run on 2026-10-09, Docker Desktop 29.8.0, kernel `7.0.12-linuxkit`, arm64.
- Endpoints: lib60870-C **v2.4.1** (tarball SHA256
  `d5708b9885c2c068ac9d9bae4696a624bd1d1d6645a1b1a9261c00274bc36c3a`), built
  in `test/iec104/endpoint/Dockerfile` on Alpine 3.21
  (`sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507`).
- Application layer: COT 2 octets, CA 2 octets, IOA 3 octets (lib60870
  defaults). APCI: lib60870 defaults k=12, w=8, t0=10 s, t1=15 s, t2=10 s,
  t3=20 s; the session-management control centre sets t3=3 s.
- Topology: one throwaway bridge, `10.235.0.0/24`. RTU (server) `10.235.0.10`
  port 2404; one-shot command clients and the malformer `10.235.0.20`;
  long-lived control centre `10.235.0.21`. No firewall in the path.
- tcpdump (`capture.Dockerfile`, filter `tcp port 2404`) records the bridge
  from the Docker VM's host namespace. Each pcap is a fresh RTU and a fresh
  capture.
- `NAME.expected.tsv` is Wireshark's independent decode of each pcap
  (TShark 4.6.7), one row per TCP segment that carries APDUs; several APDUs
  or objects in one segment are comma-separated. It is a second-parser
  cross-check for the containd decoder. Go tests read the pcaps directly,
  without tshark or a separately extracted copy of their bytes (see below).
- Timestamps, ports, ISNs and the SHA256 sums change on every regeneration;
  the APDU bytes do not, apart from CP56Time2a values and the drifting feeder
  current.

## RTU point map (test/iec104/endpoint/iec104ep.c)

| CA | IOA | Type | Meaning |
|---:|---:|---|---|
| 1 | 1001 | 3 `M_DP_NA_1` (GI), 31 `M_DP_TB_1` (spontaneous) | breaker position, DIQ 2 = closed, 1 = open |
| 1 | 1101 | 13 `M_ME_NC_1` | feeder current: GI COT 20; spontaneous COT 3 every 2 s |
| 1 | 1102 | 13 `M_ME_NC_1` | busbar voltage: GI COT 20; cyclic COT 1 every 10 s |
| 1 | 65535, 65536, 16777215 | 13 `M_ME_NC_1` | IOA edge points in GI (16-bit max, 16-bit + 1, 24-bit max) |
| 2 | 1201 | 13 `M_ME_NC_1` | aux-station frequency (GI on CA 2) |
| 1 | 2001 | 46 `C_DC_NA_1` | breaker double command, select-before-execute; drives IOA 1001 |
| 1 | 2002 | 46 `C_DC_NA_1` | second device, SBO; the harness policy forbids it |
| 2 | 2001 | 46 `C_DC_NA_1` | aux-station breaker, SBO; forbidden (wrong CA) |

Any other command address gets a negative reply with COT 47. DCS 1 = OFF
(open), 2 = ON (close); QU = 0. Station GI uses IOA 0 and QOI 20. The RTU
answers a GI on CA 1 with a type 3 ASDU, then one type 13 ASDU (SQ = 0, five
objects), then ACT_TERM (COT 10).

The RTU's `select` takes the command; `execute` is positive only after a
matching select on the same connection within 3 s. An execute without a
select is answered with COT 7 and P/N = 1 (negative).

## Expected decode, per capture

Directions: "c→s" is client to RTU (port 2404), "s→c" the reverse.
Hex is the full APDU as it appears in the TCP payload.

### startup-gi-monitor.pcap

1. Control centre `.21`: handshake, STARTDT act `680407000000` (c→s),
   STARTDT con `68040b000000` (s→c).
2. Station GI CA 1: act `680e0000000064010600010000000014` (type 100,
   COT 6, CA 1, IOA 0, QOI 20); con COT 7; then
   - type 3, COT 20, IOA 1001, DIQ 0x02:
     `680e02000200030114000100e9030002`;
   - type 13, SQ 0, five objects, COT 20, IOAs 1101, 1102, 65535, 65536,
     16777215 with floats 182.5, 20.4, 65.535, 65.536, 167.77216 and QDS 0:
     `6832040002000d05140001004d040000803643004e04003333a34100ffff00ec118342000000016f12834200ffffffacc5274300`;
   - ACT_TERM, type 100, COT 10.
3. Spontaneous feeder current (type 13, COT 3) and cyclic busbar voltage
   (type 13, COT 1), with S-frames from the client.
4. Command client `.20` selects and executes OPEN at CA 1 / IOA 2001:
   select `680e000000002e0106000100d1070081` (DCO 0x81: S/E = 1, DCS 1),
   con COT 7; execute `...d1070001` (S/E = 0), con COT 7, ACT_TERM COT 10.
5. The breaker change produces type 31 COT 3 at IOA 1001, DIQ 0x01 (open),
   CP56Time2a `94570e12090a1a`: ms 22420, minute 14, hour 18, day 9,
   month 10, year field 26, IV = 0, SU = 0, i.e. `2026-10-09T18:14:22.420`
   in the RTU's UTC clock. Sent to every active session:
   `6815060004001f0103000100e903000194570e12090a1a`.
6. A second command client closes the breaker (DCS 2); type 31 DIQ 0x02.
7. Sessions close with FIN. A one-shot lib60870 client that closes while
   telemetry is still unread follows its FIN with an RST (it happens in
   this capture). That RST comes from the endpoint, not from containd.

### sbo-command.pcap

Four one-shot clients, each with its own handshake, STARTDT and FIN:
SBO OPEN at 2001 (positive); SBO CLOSE at 2001 (positive); a direct execute
at 2001 with no select (con COT 7 with P/N = 1); SBO OPEN at CA 1 / IOA 2002
(positive; this is the device the harness policy forbids). Every positive
execute is followed by ACT_TERM (COT 10) and a type 31 breaker update when
IOA 2001 changed. One client's close ends in an endpoint RST after its FIN, as in
startup-gi-monitor.

### edge-addressing.pcap

GI on CA 1 (as in startup, with IOAs 65535, 65536 and 16777215 in one
type 13 ASDU), GI on CA 2 (`6812020002000d0114000200b104007b14484200`:
IOA 1201, 50.02 Hz), and a direct type 46 to CA 1 / IOA 65535, answered
with COT 47 and P/N = 1 (unknown IOA).

### malformed.pcap (malformer client; not lib60870 on the client side)

| Client stream | Bytes sent (c→s) | What it is | lib60870 RTU reaction |
|---|---|---|---|
| truncated-apdu | `6814000000002e0106000100` | length octet 20, only 10 octets follow, no STARTDT; client then closes (FIN) | none; FIN both ways |
| bad-length | STARTDT, then `68020100` | APCI length octet 2 (< 4) | none until the client closes; lib60870 does not reset |
| malformed-dcs | STARTDT, then `680e000000002e0106000100d1070003` | type 46 with DCS 3 (illegal) | con COT 7, P/N = 1 |
| unsupported-type | `680d00000000680106000100d10700` | I-frame with Type ID 104 (not used in 104) and no STARTDT; note the `0x68` inside the ASDU | RTU closes the connection (FIN) |
| dc-split | STARTDT, then `680e0000` `00002e01` `06000100` `d2070081` in four segments | a SELECT to IOA 2002 split across segments | reassembled; con COT 7 positive |
| coalesced | STARTDT, then `680e0000000064010600010000000014680e020000002e0106000100d2070001` in one segment | GI + an execute to IOA 2002 (no select) | GI con/data/term; execute con COT 7, P/N = 1 |

Wireshark marks none of these frames as malformed: DCS 3 and Type ID 104
decode as plain values, and it does not dissect the `68 02` or truncated
APDUs. lib60870 is not a strictness reference for framing errors.

### session-management.pcap

RTU with cyclic and spontaneous data off (`PERIODIC_MS=0`). Control centre
`.21` with t3 = 3 s: STARTDT, GI, then idle, so TESTFR act `680443000000`
(c→s) / con `680483000000` (s→c) repeat every 3 s; S-frame
`680401000800` acknowledges the GI data. A second client `.20` runs STARTDT,
STOPDT act `680413000000` / con `680423000000`, STARTDT again, then FIN.
The control centre closes last with FIN.

## Not covered by these captures

Types 45, 47-51, 58-64 and 103-107, SQ = 1 objects, IPv4 fragments and
out-of-order delivery are not here; use documented synthetic fixtures for
those. The `abort-reconnect` evidence comes from
`scripts/smoke-iec104.sh` once the integrated engine resets sessions.

## Go decoder regression corpus

`pkg/dp/ics/iec104/captures_test.go` reads all five pcaps listed in
`SHA256SUMS`, verifies each SHA256, decodes Ethernet/IPv4/TCP, and groups
payloads by directional connection tuple. Capture name, packet number,
tuple and port-derived direction remain attached to each input. This is
deterministic extraction at test time, with no generated fixture to drift.
The reader intentionally rejects different pcap formats, truncated records,
tuple reuse, TCP gaps or retransmissions rather than silently changing the
corpus. Regeneration that introduces those features needs an explicit
reader update; this helper is not a general TCP reassembler.

`TestReferenceCapturePackets` delivers the original segments, retaining
incomplete bytes until an APDU completes, and compares the decoder with
every Wireshark row: framing, sequences, U-functions, ASDU headers, object
counts, addresses, values, command select bits, qualifiers, quality and
timestamps. Float comparisons allow the TSV's float32 rounding. CP56Time2a
has no wire timezone, so timestamp comparison uses wall-clock fields,
not Wireshark's attached host offset.

The explicit strictness exceptions are `malformed.pcap` frames 28 and 29
(invalid DCS: malformed), 37 (Type 104: unsupported), and 16 (bad APCI
length: framing error). Wireshark reports object fields for the first
three, but containd deliberately emits no decoded object for these invalid
APDUs; their headers and event kinds are checked instead. The truncated
stream starting at frame 4 stays incomplete and emits no event.

`TestReferenceCaptureStreamTransforms` coalesces each connection direction,
splits it at every byte, and tests complete prefixes with partial-next-APDU
tails. These are labelled transforms of captured bytes, including the
capture's malformed and incomplete streams, not additional captured traffic.
`FuzzAPCI` and `FuzzStream` use both original segments and coalesced streams;
`FuzzASDU` uses every complete captured I-format APDU's ASDU. Synthetic
fixtures remain separate and retain their existing coverage.

```sh
go test ./pkg/dp/ics/iec104/ -run '^TestReferenceCapture'
go test ./pkg/dp/ics/iec104/ -run '^$' -fuzz '^FuzzStream$' -fuzztime 30s
```
