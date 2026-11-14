# IEC 104 peer-stage observations

This harness observes upstream controlled stations, **not containd**. It does
not encode expected response stages. An observed sequence is evidence of what
that particular application sent, not proof of standards conformance or a rule
that a firewall should automatically allow.

## Peers and licences

| Oracle stack | Controlled station | Stage implementation | Licence |
|---|---|---|---|
| `lib60870` | MZ Automation lib60870-C 2.4.1 `examples/cs104_server/simple_server.c`, unchanged | Upstream example callbacks; library defaults for otherwise unhandled requests | GPLv3-or-later or commercial |
| `j60870` | Maintained `gythialy/j60870` fork, 1.8.0 development snapshot `dcf7e2f`, unchanged `SampleServer` | Independent Java implementation, upstream example listener | GPLv3-or-later |
| `c104` | Fraunhofer FIT iec104-python 2.2.1 | Upstream C++ default `Server`/`DataPoint` handlers, configured points, **no authored request callbacks** | GPLv3-or-later |

There are **two independent protocol implementations**, not three: c104 uses
its pinned lib60870 fork for transport, but supplies additional upstream
application-stage behaviour. Java is not a binding to the C library.
[`sources.tsv`](sources.tsv) records full commits, source archive SHA256s and
licences, including c104's pinned lib60870, pybind11 and Mbed TLS dependencies.
The Dockerfile verifies every archive before compiling it. The base image is
digest-pinned. Alpine package repositories are not snapshotted: this reproduces
protocol observations, not byte-identical toolchain binaries.

No upstream GPL source is vendored here. Sources, archive files and upstream
licence texts remain in the disposable local image under `/sources`.
`master.c`, point configuration and harness scripts are Apache-2.0 source;
the master executable linked with lib60870 is a GPL combined work. These images
are local test tools, not containd release artefacts. Do not distribute them
without meeting all corresponding-source and licence obligations.
Captured wire bytes and derived tables are Apache-2.0 test data.

## Reproduce

Requirements: Docker with Linux containers, Bash, host Python 3 and `realpath`.
No host Java, compiler, TShark, root privileges, live UI or firewall needed.
Run from the repository root, choosing two **empty absolute** output directories:

```sh
bash test/pairing/peers/iec104/run.sh /tmp/iec104-peer-first
bash test/pairing/peers/iec104/run.sh /tmp/iec104-peer-second
cmp /tmp/iec104-peer-first/stages.tsv /tmp/iec104-peer-second/stages.tsv
cmp /tmp/iec104-peer-first/oracle.json /tmp/iec104-peer-second/oracle.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s test/pairing/peers/iec104 -p 'test_*.py'
shellcheck -x test/pairing/peers/iec104/run.sh
```

Each invocation builds pinned upstream in a disposable image, creates a unique
`pairingpeer-*` project identity, checks a private /24 against existing Docker
networks, and creates an internal network. All owned images, containers and
networks carry `pairingpeer=true` and the project label. No ports are published.
Master and controlled station are different real processes in the same
container, communicating over TCP/2404 on Linux loopback. The private network
has no egress during measurement. Exit traps remove only that invocation's
containers, network and image tag. Docker build cache and output files remain;
no global prune, Docker restart or modification of other resources occurs.

`tcpdump --immediate-mode -U` starts before the master and ends with SIGINT.
Header-only captures fail. TShark extracts TCP sequence/payload fields;
`analyze.py` reassembles both directions and requires the complete APDU streams
to equal the real master's raw callbacks, including S/U frames. Gaps,
conflicting retransmissions, incomplete frames, missing requests and late replies
of another procedure fail rather than silently producing an oracle.

To refresh committed data, review both runs and copy only the evidence files
listed below from one successful run. Runtime TCP sequence numbers, packet
numbers, timestamps and periodic sample counts need not be byte-identical;
`stages.tsv` and `oracle.json` must be. Run logs and output directories are not
build context.

To regenerate the derived tables and oracle from the committed captures without
Docker or new measurements:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/pairing/peers/iec104/analyze.py test/pairing/peers/iec104
```

## Oracle and evidence format

`oracle.json` is the strict version-1 replay interface:

```json
{"version":1,"sequences":[{"id":"unique-id","peer":"stack version@commit","frames":[{"direction":"request","apdu":"680407000000"},{"direction":"response","apdu":"68040b000000"}]}]}
```

There are no extra fields. Each sequence contains at least two frames, each
holding exactly one complete APDU. Directions are master-to-station `request`
and station-to-master `response`, including autonomous and control frames.
Every byte, including APCI counters, P/N/T, S/E, addresses, qualifiers, values
and timestamps, is retained from the verified capture. No timestamp or counter
normalization is performed. Unsupported episodes remain only in the stage
table and full capture evidence, not this replay interface.

The replay export contains **261 sequences**: 81 positive/control sequences
and 180 rejected episodes (95 Java, 85 c104). It is a **fixed deterministic
subset**, not every observation: all c104 positive I-frame episodes; Java
positive I-frame episodes except its wall-clock clock-sync replies; the C
sample's initial Type45 execute-without-selection episode; one actual
STARTDT/STOPDT/TESTFR pair from each peer; and c104's complete autonomous
startup, including S acknowledgements.
Rejected episodes are also exported when at least one reply has error COT44–47
(either P/N value) or negative ACT_CON (COT7, P/N=N), subject to the same
byte-stability exclusions. The complete ordered I-frame episode is retained,
not just the qualifying reply.
Later C I-frame episodes have periodic-dependent APCI counters, and C/Java
clock replies contain current time. Those observations stay intact in the
stage table and wire evidence rather than being rewritten for repeatability.
This excludes **all lib60870 error episodes**, including its direct Type47/44N
and GI100/46N replies. The per-peer totals are 4 lib60870, 118 Java and 139 c104.
The JSON includes all fourteen command types, GI, counter, Read, clock and test
positive witnesses, plus monitoring/initialization and S/U frames. It does not
invent positive Reset105 or unwitnessed errors. Exported negative shapes include
Java's direct 44N, c104's standalone 7N, and c104's ordered 7N then 44P/46P/47P.
There is no captured COT45 witness.

Sequence IDs `STACK-case-NNN` resolve to `STACK.wire.tsv:case=NNN`; control
exchange IDs and `c104-startup-autonomous` resolve to the peer's wire table
(`case=001` for startup). Application episodes omit unrelated S/U and
autonomous frames while preserving the order and bytes of the I frames.
The previously documented peer disagreements are preserved, not filtered for
compatibility with a particular decoder or pairing implementation.

`stages.tsv` is generated exclusively from observed replies:

* One row per request/variant, plus autonomous and session coverage rows.
* `cot_sequence`, `reply_types` and `pn_sequence` are parallel, ordered lists
  of station-to-master ASDUs. They exclude unrelated autonomous traffic.
  Negative bit `N` and error COT44–47 are preserved separately.
* `qualifier` is command QU/QL, GI QOI, the complete counter QCC byte
  (group bits and freeze bits), Read IOA, reset qualifier or test sequence.
  Bitstring commands 51/64 have no S/E field.
* `optional_stages_observed=10` means termination was actually seen, **not**
  that every other peer must send it. Blank never proves a stage forbidden.
* `stage_owner` distinguishes upstream application decisions, library
  defaults, c104 defaults and explicitly application-triggered autonomous APIs.
* `observed` means a non-error reply was emitted; it does **not** assert the
  reply is compatible with the request. `rejected-by-stack` means only
  negative/error replies. `unsupported-by-stack` means no response/emitter
  in this configured application and observation window, not that the library
  could never implement it. Absent monitor types use `type=*`.
* `capture_reference` identifies `STACK.wire.tsv:case=NNN` or `:all`.
  Wire tables include exact APDU hex and the pcap frame completing each APDU.
  Empty sequences retain the request's capture reference.

Each stack's committed `.pcap`, `.tcp.tsv`, `.master.log`, `.capture.log` and
`.wire.tsv` permits replay and independent inspection. `.tcp.tsv` columns are
frame number, TCP source port, raw TCP sequence, and TCP payload hex, exactly as
TShark emitted them. The master log supplies case boundaries; it is checked
against the capture, not treated as independent delivery evidence.

Requests are sequential, with a 650 ms observation window; the final idle
window is 4.5 s. The master's T3 is 1 s, below the C station's 2 s periodic
interval, so periodic traffic cannot starve its TESTFR probe. Missing
TESTFR confirmation or any STARTDT/STOPDT act/con fails the run rather than
being classified as unsupported. This is **not** a normative response timeout.
Missing delayed terminations remain unknown, not disallowed. This local harness cannot prove
behaviour on WAN latency, retransmission stress or physical RTUs.

### Point map and stimulus

Unchanged C/Java samples use CA1/IOA5000 for single command. The driver's
`point-5000` variants probe that address for every command type, followed by
unknown IOA5001. c104 uses CA=command TypeID, IOA5000; this configures all
fourteen types without overloading one point's TypeID. S/E-capable c104 points
use the library's SELECT_AND_EXECUTE mode; bitstrings use DIRECT.
Every S/E-capable type also probes execute-without-selection, then select at
IOA5002 (a configured DIRECT point only in c104). This obtains default-handler
negative confirmations without an authored failure callback. The unchanged
C/Java examples may instead accept or ignore these probes; the oracle records
what happened, not the intended outcome.

GI probes QOI20 and every group QOI21–36, plus unknown CA2. Counter probes
groups1–5 crossed with freeze/read/reset modes0–3. Reads probe
100/104/110/5000/5001. Clock, reset qualifiers1/2 and timestamped test probe
valid IOA0 and invalid IOA1. The fixed request timestamp is
2024-01-01 00:00:00. It deliberately makes response timestamp changes visible.

c104's CA1 has monitor points Type1/IOA100, Type3/IOA104, Type13/IOA110 and
counter Type15/IOA5000. After its first active connection, the configuration
calls the public initialization API once and transmits Type1 once with each
of COT1/2/3. **These causes are application-selected stimuli**, not evidence
of automatic scheduling/classification. No request handler, P/N decision,
confirmation or termination is authored by the harness.
Eight final Type49/IOA5001 requests exercise the Java sample's receive-window
S acknowledgement. Each run drives 135 requests per controlled station
(138 named windows including startup, idle and stop).

## Observed coverage

The stage table has 441 rows: 147 per stack, including rejected and unsupported
procedures. In the table, numbers are **reply** COTs; `N` is the P/N bit.
`R44` means rejected with unknown-type COT44; `U` means unsupported/no response.
For S/E commands, `7 / 7,10` means select confirmation / execute stages.
All fourteen command types have positive and negative wire evidence through
c104's upstream default handlers; C and Java independently corroborate Type45
but reject or ignore the other command types.

| Procedure | lib60870 example | j60870 example | c104 defaults |
|---|---|---|---|
| Single 45, S/E | 7 / 7 | 7 / 7 | 7 / 7,10 |
| Double 46, S/E | R44 | R44 | 7 / 7,10 |
| Regulating step 47, S/E | R44 | R44 | 7 / 7,10 |
| Normalized setpoint 48, S/E | R44 | R44 | 7 / 7,10 |
| Scaled setpoint 49, S/E | R44 | U | 7 / 7,10 |
| Floating setpoint 50, S/E | R44 | R44 | 7 / 7,10 |
| Bitstring 51, execute | R44 | R44 | 7 |
| Timestamped single 58, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped double 59, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped step 60, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped normalized setpoint 61, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped scaled setpoint 62, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped floating setpoint 63, S/E | R44 | R44 | 7 / 7,10 |
| Timestamped bitstring 64, execute | R44 | R44 | 7 |
| Negative commands | 45:47 **P**, others:44N | 45:U, 49:U, others:44N | S/E known-point refusals:7N; unknown IOA:7N,47P |
| GI100 station QOI20 | 7,20×4,10 | 7,20,10 | 7,20×3,10 |
| GI100 groups QOI21–36 | 7N | **7,20,10 for every group** | 7N |
| GI100 unknown CA2 | 46N | 7,20,10 (CA2 accepted) | 7N,46P |
| Counter101 groups1–4, read mode | R44 | R44 | 7N |
| Counter101 group5, read mode | R44 | R44 | 7,37,10 (Type15 data) |
| Counter101 groups1–5, freeze modes1–3 | R44 | R44 | 7,37,10 for **every** group/mode |
| Read102, IOA100/104/110 | R44 | R44 | **7,5**, returns Type1/3/13 respectively |
| Read102, counter IOA5000 / unknown IOA5001 | R44 | R44 | 7N,44P / 7N,47P |
| Clock103, IOA0 | 7, time replaced | **6**, current time | 7, requested time echoed |
| Clock103, invalid IOA1 | 47N | 6 | 7 |
| Reset105, qualifier1/2 | R44 | R44 | 7N,47P; no positive support |
| Test107, IOA0 | 7 | R44 | 7 |
| Test107, invalid IOA1 | 47N | R44 | **7** |
| Monitor COT1 | Type11, automatic periodic | U | Type1, explicit API stimulus |
| Monitor COT2/3 | U | U | Type1, explicit API stimuli |
| Initialization70/COT4 | U | U | Explicit initialization API |
| S acknowledgement | Master→station observed; reverse U | Both directions observed | Master→station observed; reverse U |
| STARTDT/STOPDT/TESTFR | Master act / station con | Master act / station con | Master act / station con |

### Interpret disagreements before using this as an acceptance oracle

* **Selection is application-defined.** The C sample accepts Type45 execute
  without select; Java ignores it; c104 returns 7N. C/Java send no Type45
  termination in this window. c104 sends 10 after S/E execute, but its
  termination echoes the **selection's S/E=1 payload**, not execute's S/E=0
  payload. See command cases004/005 (Type45),010/011 (Type46), and their wire
  bytes; timestamped commands behave the same. Bitstring direct execution has
  no observed 10.
* **Negative terminal is not universally respected by applications.** c104
  unknown IOA emits 7N followed by 47P. Unknown CA emits 7N then 46P, and
  counter Read emits 7N then 44P. Retain these observations; do not reinterpret
  the second error as positive completion or silently permit it after a
  consumed negative grant.
* **Read has an extra stage in this peer.** c104 Read102 first sends Type102
  COT7, then the requested Type1/3/13 COT5 data. It is not just a bare COT5
  response. All are real captured replies, not assumed expected fixtures.
* **GI group support is not established by a positive confirmation.** Java
  ignores QOI for data selection and always sends station-interrogated COT20.
  It also accepts CA2. C and c104 explicitly refuse groups. No tested peer
  provides positive group-specific COT21–36 data.
* **Counter group/freeze semantics need independent evidence.** c104 rejects
  group1–4 read mode, but its default condition accepts every non-read freeze
  mode and returns general-counter COT37 regardless of group. This shows
  stages, not correct group isolation or successful physical freeze/reset.
* **Clock and invalid-address behaviour differ.** Java sends a new activation
  COT6 with current time, not COT7 confirmation. The C sample sends COT7 but
  replaces the request timestamp with its current time. c104 echoes it,
  including for invalid IOA1. The newer C test-command default rejects
  invalid IOA1; c104's older lib60870 fork accepts it. Do not turn these
  malformed-stimulus observations into permissions for valid procedures.

**Positive evidence gaps:** reset105 qualifiers1/2 have no supporting tested
peer; GI group-specific responses and counter group1–4 read responses have
no positive compatible witness. Other return-type mappings for Read102 are
not established. COT2/3 and initialization evidence is application-triggered,
not independent automatic station behaviour. These are explicit limitations,
not procedures silently removed from the oracle.
