// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
)

// Token identifies one inline-delivered packet: the queue generation that
// delivered it plus its NFQUEUE packet ID. It is comparable and usable as a
// map key. The zero Token means "not inline". Tokens never appear in event
// JSON.
type Token struct {
	gen uint64
	id  uint32
}

// NewToken builds a Token for tests and fakes. Generation 0 is reserved for
// the zero (non-inline) Token, so NewToken panics when gen is 0.
func NewToken(gen uint64, id uint32) Token {
	if gen == 0 {
		panic("capture: NewToken generation 0 is invalid")
	}
	return Token{gen: gen, id: id}
}

// Inline reports whether the token names an inline-delivered packet.
func (t Token) Inline() bool { return t.gen != 0 }

// Generation returns the queue generation that delivered the packet.
func (t Token) Generation() uint64 { return t.gen }

// String formats the token for logs only.
func (t Token) String() string {
	if !t.Inline() {
		return "none"
	}
	return "g" + strconv.FormatUint(t.gen, 10) + "/" + strconv.FormatUint(uint64(t.id), 10)
}

// Verdict is the kernel verdict submitted for an inline packet.
type Verdict uint8

const (
	VerdictAccept Verdict = iota + 1
	VerdictDrop
)

// Disposition is a handler's decision for the current packet.
type Disposition uint8

const (
	Accept Disposition = iota
	Drop
	Hold
)

// Resolution settles one earlier Held token.
type Resolution struct {
	Token   Token
	Verdict Verdict
}

// Decision is returned by a Handler for every delivered packet.
type Decision struct {
	Action   Disposition  // current packet
	Reason   string       // machine reason; logs/metrics only
	Resolved []Resolution // earlier Held tokens of the same source
	// Notify requests OnVerdict even for a successful immediate Accept.
	Notify bool
}

// Handler receives decoded capture packets and decides the current packet.
type Handler func(pkt Packet) Decision

// Settler submits verdicts for outstanding inline tokens.
type Settler interface {
	// Settle submits verdicts for outstanding tokens and returns after
	// submission, one error per request (nil = submitted). Rejected requests
	// (ErrStaleToken, ErrUnknownToken, ErrQueueClosed, ErrNotInline) submit
	// nothing and produce no OnVerdict.
	Settle(res ...Resolution) []error
}

// VerdictFunc reports the completion of one submitted (or failed) verdict.
type VerdictFunc func(tok Token, v Verdict, err error)

// SourceEvent reports an inline source state change.
type SourceEvent struct {
	Generation uint64
	// Ready is true when the source is bound and delivering; false when it
	// is down and all outstanding tokens of this generation are gone.
	Ready bool
	Err   error
}

var (
	ErrStaleToken     = errors.New("capture: token belongs to a closed queue generation")
	ErrUnknownToken   = errors.New("capture: token is not outstanding")
	ErrQueueClosed    = errors.New("capture: inline queue is not bound")
	ErrNotInline      = errors.New("capture: source is not inline")
	ErrInvalidVerdict = errors.New("capture: verdict is neither accept nor drop")
)

// generations numbers inline queue generations for the whole process,
// across Manager instances and rebinds. 0 is the zero Token.
var generations atomic.Uint64

func nextGeneration() uint64 { return generations.Add(1) }

func (v Verdict) valid() bool { return v == VerdictAccept || v == VerdictDrop }

// String names the verdict for logs.
func (v Verdict) String() string {
	switch v {
	case VerdictAccept:
		return "accept"
	case VerdictDrop:
		return "drop"
	default:
		return "invalid(" + strconv.Itoa(int(v)) + ")"
	}
}

// Settler returns the manager's stable verdict handle.
func (m *Manager) Settler() Settler { return m.settler }

// settler is the Manager's Settler. It routes each request to the current
// queue generation. Observational sources reject everything with
// ErrNotInline; NFQUEUE rejects with ErrQueueClosed until a generation is
// bound.
//
// A request that names a token whose handler callback is still running is
// staged: Settle returns nil for it at once, and the verdict (Drop winning
// over Accept) is submitted when the callback returns. OnVerdict reports
// that submission.
type settler struct {
	inline bool

	mu  sync.Mutex
	cur *generation
}

func (s *settler) publish(g *generation) {
	s.mu.Lock()
	s.cur = g
	s.mu.Unlock()
}

func (s *settler) current() *generation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *settler) Settle(res ...Resolution) []error {
	errs := make([]error, len(res))
	if len(res) == 0 {
		return errs
	}
	g := s.current()
	batch := make([]int, 0, len(res))
	for i, r := range res {
		if errs[i] = routeError(s.inline, g, r); errs[i] == nil {
			batch = append(batch, i)
		}
	}
	if len(batch) > 0 {
		g.settle(res, batch, errs)
	}
	return errs
}

// routeError rejects a request that cannot reach generation g.
func routeError(inline bool, g *generation, r Resolution) error {
	switch {
	case !r.Verdict.valid():
		return ErrInvalidVerdict
	case !inline || !r.Token.Inline():
		return ErrNotInline
	case g == nil:
		return ErrQueueClosed
	case r.Token.gen < g.id:
		return ErrStaleToken
	case r.Token.gen > g.id:
		return ErrUnknownToken
	default:
		return nil
	}
}
