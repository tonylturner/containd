// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"strconv"
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
	ErrStaleToken   = errors.New("capture: token belongs to a closed queue generation")
	ErrUnknownToken = errors.New("capture: token is not outstanding")
	ErrQueueClosed  = errors.New("capture: inline queue is not bound")
	ErrNotInline    = errors.New("capture: source is not inline")
)

// Settler returns the manager's stable verdict handle.
func (m *Manager) Settler() Settler { return m.settler }

// stubSettler is the contract-commit Settler. No source registers inline
// tokens yet, so every request is rejected: observational modes with
// ErrNotInline, NFQUEUE with ErrQueueClosed until the inline queue exists.
type stubSettler struct {
	inline bool
}

func (s stubSettler) Settle(res ...Resolution) []error {
	errs := make([]error, len(res))
	for i, r := range res {
		switch {
		case !s.inline || !r.Token.Inline():
			errs[i] = ErrNotInline
		default:
			errs[i] = ErrQueueClosed
		}
	}
	return errs
}
