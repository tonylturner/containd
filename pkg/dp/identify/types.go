// SPDX-License-Identifier: Apache-2.0

package identify

import "time"

type State string

const (
	NeedMore   State = "need_more"
	Reject     State = "reject"
	Candidate  State = "candidate"
	Confirmed  State = "confirmed"
	Incomplete State = "identification_incomplete"
	Ambiguous  State = "ambiguous"
)

type Protocol string

const (
	Modbus Protocol = "modbus"
	DNP3   Protocol = "dnp3"
	IEC104 Protocol = "iec104"
	ENIP   Protocol = "cip"
)

// ProfileVersion versions the supported evidence rules, not a decoder schema.
const ProfileVersion = 2

type Role string

const (
	Unknown Role = "unknown"
	Client  Role = "client"
	Server  Role = "server"
)

// Range is a half-open examined range in a supplied directional prefix.
type Range struct{ Start, End int }

type Result struct {
	Protocol  Protocol
	State     State
	States    [2]State // directional evidence before cross-direction pairing; absent TCP bytes need_more
	Examined  [2]Range
	Reason    string
	Transport uint8
	// Role describes the sender of the first argument to Probe. Unknown is
	// intentional for symmetric messages and IEC act/con functions.
	Role    Role
	Version int
}

type Coverage string

const (
	Budget    Coverage = "budget"
	Timeout   Coverage = "timeout"
	Conflict  Coverage = "conflict"
	Midstream Coverage = "midstream/no-SYN"
	Truncated Coverage = "truncated"
	Closed    Coverage = "closed"
)

type Budgets struct {
	// Protocols limits probing; nil enables all profiles, an empty slice enables none.
	Protocols         []Protocol
	BytesPerDirection int
	PendingRanges     int
	Arrivals          int
	Duration          time.Duration
	UDPDatagrams      int
	Entries           int
	ChargedBytes      int
}

func DefaultBudgets() Budgets {
	return Budgets{BytesPerDirection: 1024, PendingRanges: 8, Arrivals: 16, Duration: 5 * time.Second, UDPDatagrams: 4, Entries: 4096, ChargedBytes: 16 << 20}
}

// Key is an opaque caller-assigned connection incarnation identity.
// The caller must Release on close, tuple reuse and reconfiguration.
type Key string

// Meta ports are endpoint ports in the same order as Arrival.Direction. They
// inform Expected only; they never decide content identity or sender role.
type Meta struct {
	Transport uint8
	Ports     [2]uint16
}

type Arrival struct {
	Direction uint8 // 0 or 1
	Sequence  uint32
	SYN       bool // SYN or SYN-ACK; payload begins at Sequence+1
	Payload   []byte
	Truncated bool
}

type Decision struct {
	State    State
	Protocol Protocol // set only for a unique candidate/confirmed protocol
	Coverage Coverage
	Expected [2]Protocol
	Results  [4]Result
}

// Counters count connections reaching each evidence/terminal category once,
// except Overflow, which counts refused admissions or byte-growth attempts.
type Counters struct {
	Candidates, Confirms, Rejects, Ambiguity, Overflow uint64
	Incomplete                                         [6]uint64 // Budget, Timeout, Conflict, Midstream, Truncated, Closed
}

// Datagram refers to a whole UDP message in Replay.Bytes[Direction].
type Datagram struct {
	order     uint64 // table-wide ingestion order, preserved through adoption
	Direction uint8
	Range     Range
	Length    int // original datagram length; may exceed Range length for an incomplete clipped replay
}

// Segment is a retained TCP range beyond a gap. Feed it through the bound
// stream reassembler with its sequence, not directly into a contiguous decoder.
type Segment struct {
	Sequence uint32
	Bytes    []byte
}

// Replay transfers ownership of retained bytes to the caller. For TCP, only
// contiguous prefixes appear in Bytes, starting at Sequence. Pending preserves
// all already-observed out-of-order bytes. UDP boundaries must be honored. The
// table no longer charges these arrays after Take.
type Replay struct {
	// TriggerRetained reports that the entire last Observe payload was admitted.
	// False means no caller may treat its missing bytes as replayed.
	TriggerRetained bool
	Bytes           [2][]byte
	Sequence        [2]uint32
	Pending         [2][]Segment
	Datagrams       []Datagram
}
