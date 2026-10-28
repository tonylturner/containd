// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

/*
Package corpus provides portable, test-only capture loading and Manager replay.
Production code must not import it. Decoder tests supply their own constructors;
this package never imports a protocol decoder or decodertest. Tests in dpi that
import corpus must use package dpi_test to avoid an import cycle. Go's internal
visibility prevents generation tools under the root test directory importing it.

# API

	Load(fsys fs.FS, manifestPath string) ([]Fixture, error)
	ReadPCAP(r io.Reader, captureName string, opts ReadOptions) ([]Packet, []SkippedRecord, error)
	ReadOracle(r io.Reader, captureName string) ([]OracleRow, error)
	Replay(makeManager func() *dpi.Manager, f Fixture, opts ReplayOptions) ([]Step, error)
	Apply(f Fixture, transforms ...Transform) (Fixture, error)
	Split(maxPayload int) Transform
	Coalesce(maxPayload int) Transform
	Reorder(window int, permutation []int) Transform
	Retransmit(packetIndices []int) Transform
	EveryCuts(f Fixture, maxVariants int) ([]Fixture, error)
	Seeds(f Fixture) [][]byte
	StreamSeeds(f Fixture) ([][]byte, error)

All helper failures are returned errors; callers choose Fatal versus fuzz Skip.
An invalid committed fixture is a test failure, not a reason to skip coverage.
Load authenticates the entire inventory before parsing any fixture. Fixtures'
Manifest, Spec, Oracle and Expectations are read-only metadata shared by derived
fixtures. Packets, their transport payloads and Source spans are owned copies.
SourceSpan.Start/End are payload-relative ranges in the original one-based
capture record, not Ethernet offsets. Empty controls have an empty span.

# Fixture layout and manifest schema

Each protocol uses test/<protocol>/capture/ for pinned generation scripts,
Dockerfiles, endpoint adapters, dependency/source locks, oracle exporters and
third-party notices. test/<protocol>/testdata/ contains README.md, LICENSE,
manifest.json, SHA256SUMS, <scenario>.pcap, <scenario>.expected.tsv and
<scenario>.expectations.json. Additional hashed assets may retain PDML, nested
JSON observations, generator logs and configuration evidence.

The version-1 JSON structure is below. Required strings are nonempty; unknown
struct members are rejected. All artifact names are single relative filenames
without whitespace, slash or backslash. File references and scenario names must
be unique. Paths and every filesystem component are checked against symlinks.
The manifest itself may be below the fs root. Optional arrays default to empty,
optional booleans to false; sequence anchors may be omitted or null.

	Manifest = {
	  "version": 1,
	  "protocol": "modbus" | "dnp3" | "iec104" | "cip",
	  "provenance": {
	    "source": string, "generator": string, "oracle": string,
	    "license": string, "topology": string, "capture_side": string,
	    ...additional string-valued evidence...
	  },
	  "scenarios": [Scenario, ...] // 1..1000
	}
	Scenario = {
	  "name": filename, "pcap": filename, "oracle": filename,
	  "expectations": filename, "transport": "tcp" | "udp",
	  "checksum_offload": string,
	  "oracle_frames": [positive unique frame numbers, ...],
	  "unobserved_frames"?: [positive unique frame numbers, ...],
	  "assets"?: [filename, ...],
	  "roles"?: [Role, ...],
	  "allow_midstream"?: boolean,
	  "contiguous"?: boolean,
	  "ignore_ethertypes"?: [uint16, ...]
	}
	Role = {
	  "transport": "tcp" | "udp",
	  "client": "IPv4:port", "server": "IPv4:port",
	  "client_sequence"?: uint32 | null,
	  "server_sequence"?: uint32 | null
	}

The provenance strings retain actual source commits/archive digests, generator
versions, oracle versions/preferences, image digests, config/script hashes,
license/origin and topology/capture-side evidence. This helper checks presence,
not the truth or reproducibility of third-party provenance. checksum_offload
must explicitly say "none" or explain observed endpoint-offload artifacts. The
reader retains original checksum bytes but does not certify checksum validity.

SHA256SUMS uses lowercase 64-hex digests followed by two spaces (or space-star)
and a filename, one per line. It covers exactly every referenced pcap, oracle,
expectation file and asset; duplicates, missing/extra entries, traversal,
symlinks and mismatches fail. Do not self-hash the manifest or SHA256SUMS.
Expectation JSON is a nonempty object retained as map[string]json.RawMessage.
Its protocol-owned keys describe coverage, findings and EOF tails separately
from independent oracle observations; corpus does not interpret product verdicts.

Oracle TSV has a unique nonempty header, frame.number and tcp.payload and/or
udp.payload. Optional pdu and object columns contain nonnegative ordinals
(default zero if absent). (frame.number,pdu,object) must be unique; multiple
rows may refer to one packet. Payload is full raw transport payload hex,
optionally colon-separated, repeated on each object/PDU row, not reassembled
bytes. It must equal the selected capture record; the other transport's column
must be empty. All other columns are retained verbatim, including empty cells
versus "0"; comma-joined columns are never interpreted as object structure.
oracle_frames must match observed frame numbers exactly. Every selected payload
record must occur either there or in unobserved_frames (not both); the latter
explicitly accounts for unrecognized/malformed/continuation records. Even an
unobserved payload is replayed. No request fields are imputed onto responses.

# Reader and connection identity

ReadPCAP accepts classic pcap 2.4, either byte order, micro/nanosecond time,
Ethernet/IPv4/TCP or UDP. Limits are 32 MiB/capture, 100000 records and 65549
bytes/record. Load limits JSON/checksum metadata to 1 MiB each and the entire
hashed inventory to 128 MiB. Oracle input is limited to 8 MiB and 100000 rows.
pcapng, other linktypes, truncated captures/headers, invalid transport lengths,
IPv4 fragments and IPv6 are rejected explicitly. Unhandled EtherTypes fail
unless explicitly ignored; IPv6 is never ignorable. Load selects the declared
protocol/transport using the ICS port registry; nonselected records and allowed
EtherTypes are accounted for in Skipped, with their original frame numbers.
Controls, timestamps, sequence zero, wrap, ACK/flags, duplicates and reordered
arrivals survive unchanged. No parser reassembles or deduplicates TCP.

An initial SYN identifies the opener; server-port guesses never prove roles.
UDP and midstream TCP require explicit endpoint roles. TCP picked up without
an opening SYN additionally requires allow_midstream. Midstream offset replay
requires explicit first-payload sequence anchors for every observed direction.
SYN retries keep identity; a changed opener SYN or a SYN after RST/both FINs
creates a new incarnation. Stable connection IDs are scenario-name/ordinal;
roles/directions retain the actual wire endpoints, even with source service
ports. A SYN conflicting with explicit roles/anchors fails.

# Replay and lifecycle

Replay calls the constructor once per run; it MUST create fresh Manager and
fresh decoders for every original, derivative and repetition. Sequence uses
TCPSeqValid even for zero and passes raw Seq+1 on SYN only, modulo uint32.
SessionOffsets uses Connection+Dir with offsets computed as signed modular
deltas from ISN+1 or an explicit anchor; negative or greater-than-2^30 deltas
are rejected as unsupported/ambiguous. Neither mode uses arrival append or a
helper-side reassembler. ReplayOptions.SimulateHandshake explicitly sets
TCPHandshake on captured SYNs, not on fabricated controls. It is a simulation
assumption, not kernel conntrack evidence. FailClosed controls Manager transport
verification, not tolerant/strict protocol policy.

Every selected record is inspected in global delivery order, with flow times
and counters updated from capture time. Replay never sleeps or tests Manager
wall-clock idle expiry. Step.Kind is inspect, close, reset, end_session or
flow_end. Result retains all events, frames, NeedMore, Gap, errors and Failed.
Helper errors occur before Manager construction; decoder/Manager/lifecycle
errors remain observations in Steps and are never silently swallowed.

Sequence closes FIN/RST via CloseStream and resets the peer after an accepted
RST. Both modes call OnFlowEnd on observed directional flows after the last
record of each incarnation (including EOF partial tails). OnFlowEnd is final
cleanup even if CloseStream already emitted flow-end events. Offset sessions
call EndStream before that cleanup, never on the first half-close. Lifecycle
steps preserve their events/errors separately from inspect steps. These public
Manager calls also deliver StreamEnded when Manager supports its dispatch;
corpus never invokes a private decoder lifecycle hook. EOF does not synthesize
an incomplete-frame error. Compare ordered per-connection/direction semantic
multiplicity, not a set or globally sorted bag of events. Decoder-specific
correlation and engine policy/enforcement assertions belong to their owners.

# Derivatives and fuzz seeds

All transforms require TCP with valid sequence metadata and preserve sequence
mapping and Source spans. Split/coalesce never cross controls or opposite
directions; coalesce additionally requires adjacent contiguous bytes with equal
ACK/window, so gaps, overlaps and incarnations are barriers. PSH is retained
only on the last split piece and taken from the last coalesced piece. Reorder
permutes only full same-direction data windows, keeping controls, opposite
directions and incomplete windows in place. The explicit permutation is a
bijection; window is 2..32. Retransmit inserts an exact owned data duplicate
immediately after each selected current-input index; control retransmission and
conflicting-byte mutations are not provided by this equivalence transform.
All TCP transforms, including EveryCuts, reject UDP, even no-op cases.

Split/coalesce payload parameters are 1..32768; reorder windows have at most
32768 payload bytes; each transform is limited to 200000 packets. EveryCuts
enumerates all ordinary-payload two-part cuts, failing rather than sampling
above its explicit variant budget, 128 MiB aggregate payload or 200000 total
records. Payload controls with SYN/FIN/RST/URG/ECE/CWR are kept intact, not
repacketized. Derived records have Wire=nil: these are Manager inputs, not
exportable pcaps with stale checksums. Derived lists parameterized recipes and
times are generated monotonically at 1 microsecond intervals from the first
original arrival. The original fixture remains unchanged.

Seeds returns owned nonempty TCP segments/UDP datagrams, preserving duplicates.
StreamSeeds is separate parser-fuzz input: it requires a pristine TCP fixture
explicitly marked contiguous, anchored sequences and exact per-direction
contiguity (even identical retransmissions are rejected). It returns streams
in first-data-direction occurrence order; UDP, derivatives, gaps and overlaps
fail. Protocol-specific sublayer extraction stays with the protocol decoder.

For direct parser contract tests with stateful decoders, use

	decodertest.CheckStreamFactory or decodertest.CheckSplitsFactory. They isolate

whole/prefix/split replays; the head and tail of one split share decoder state.
The pre-existing instance-taking helpers remain stateless-only entry points,
so existing out-of-package callers need not change signatures.
*/
package corpus
