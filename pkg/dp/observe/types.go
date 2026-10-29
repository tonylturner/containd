// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

type Binding string

const (
	None        Binding = "none"
	Legacy      Binding = "legacy"
	Observation Binding = "observation"
)

// Options callbacks must be pure, nonblocking and take no locks. They execute
// under the observer mutex. Scope returns bool or "unknown"; nil means unknown.
// Manager must be exclusively owned, with fresh decoders for enabled protocols.
type Options struct {
	Budgets       identify.Budgets
	Markers       int              // capacity across pending, bound and terminal incarnations
	Now           func() time.Time // ingestion/deadline clock, not capture time
	Manager       *dpi.Manager
	LegacyDecodes func(identify.Key, identify.Protocol) bool
	Scope         func(identify.Key, identify.Protocol) any
}

// Packet keeps wire Sequence (before SYN), capture time and directional state.
// SYNACK distinguishes the passive server role; Arrival.SYN covers both SYNs.
type Packet struct {
	identify.Arrival
	State            *flow.State
	At               time.Time
	SYNACK, FIN, RST bool
}

// Batch is attributed to the direction and capture arrival that released its
// events. Err is decoder/coverage telemetry, never an enforcement instruction.
type Batch struct {
	Key    identify.Key
	Dir    uint8
	State  *flow.State
	Events []dpi.Event
	At     time.Time
	Err    error
}

type Identification struct {
	Key      identify.Key
	Decision identify.Decision
	Binding  Binding
	Event    dpi.Event
}

type Output struct {
	Identifications []Identification
	Batches         []Batch
}

func (o *Output) append(other Output) {
	o.Identifications = append(o.Identifications, other.Identifications...)
	o.Batches = append(o.Batches, other.Batches...)
}

// Snapshot is pure, has fixed protocol/outcome dimensions and owns no maps.
// Outcomes columns: confirmed, reject, incomplete. Protocols rows follow
// Modbus, DNP3, IEC104, CIP, unknown. Incomplete coverage follows identify.Counters.
type Snapshot struct {
	Evidence                                 identify.Counters
	Outcomes                                 [5][3]uint64
	Incomplete                               [6]uint64
	Refusals, AdoptionConflicts              uint64
	Entries, ChargedBytes, Markers, Bindings int
}

type stamp struct {
	dir    uint8
	seq    uint32
	length int
	at     time.Time
	state  *flow.State
	order  uint64
}

// Status is a copy of current binding/coverage metadata, suitable for flow
// rollups and passive learner exclusions. Session is frozen across adoption.
type Status struct {
	// Observed remains true after close/conflict: passive connections must stay
	// excluded from portless learning until the incarnation is retired.
	Observed    bool
	Protocol    identify.Protocol
	Binding     Binding
	Coverage    identify.Coverage
	SYNCoverage [2]bool
	Session     string
}

type connection struct {
	meta     identify.Meta
	syn      [2]bool
	base     [2]uint32
	high     [2]int64 // sequence-unwrapped largest payload end
	roles    [2]dpi.StreamDir
	states   [2]*flow.State
	at       [2]time.Time
	stamps   []stamp
	observed bool
	binding  Binding
	protocol identify.Protocol
	coverage identify.Coverage
	session  string // frozen through adoption
	fin      [2]bool
	ended    uint64 // terminal order, not capture time
}

// Observer serializes table, bindings, replay, adoption and disposal. No
// observer operation calls into the owner except the two pure predicates.
type Observer struct {
	mu      sync.Mutex
	table   *identify.Table
	opts    Options
	entries map[identify.Key]*connection
	counts  Snapshot
	serial  uint64
	drained bool
}
