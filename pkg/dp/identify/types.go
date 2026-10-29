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
const ProfileVersion = 1

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
)

type Budgets struct {
	BytesPerDirection int
	PendingRanges     int
	Arrivals          int
	Duration          time.Duration
	UDPDatagrams      int
	Entries           int
	ChargedBytes      int
}

func DefaultBudgets() Budgets {
	return Budgets{1024, 8, 16, 5 * time.Second, 4, 4096, 16 << 20}
}

// Key is an opaque caller-assigned connection identity plus an incarnation.
// The caller must Release on close, tuple reuse and reconfiguration.
type Key struct{ Connection, Incarnation uint64 }

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
	Incomplete                                         [5]uint64 // Budget, Timeout, Conflict, Midstream, Truncated
}

// Datagram refers to a whole UDP message in Replay.Bytes[Direction].
type Datagram struct {
	Direction uint8
	Range     Range
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
	Bytes     [2][]byte
	Sequence  [2]uint32
	Pending   [2][]Segment
	Datagrams []Datagram
}
