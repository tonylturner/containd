// SPDX-License-Identifier: Apache-2.0

package flow

// Admission owns two directional slots until its final state is removed.
// Union links preserve ownership when verified NAT evidence joins histories.
// All operations require the engine flow-table lock.
type Admission struct {
	parent      *Admission
	refs        int
	seen        uint8
	syn         bool
	synAck      bool
	synSeq      uint32
	synAckSeq   uint32
	synAckOf    uint32
	established bool
}

func (a *Admission) root() *Admission {
	if a.parent != nil {
		a.parent = a.parent.root()
		return a.parent
	}
	return a
}

func NewAdmission() *Admission { return &Admission{} }

func (a *Admission) Retain() { a.root().refs++ }

// Release reports the end of the connection's reservation.
func (a *Admission) Release() bool {
	r := a.root()
	r.refs--
	return r.refs == 0
}

// Merge reports whether a duplicate reservation can be returned.
func (a *Admission) Merge(b *Admission) bool {
	a, b = a.root(), b.root()
	if a == b {
		return false
	}
	b.parent = a
	a.refs += b.refs
	a.seen |= b.seen
	if !a.syn && b.syn {
		a.syn, a.synSeq = true, b.synSeq
	}
	if !a.synAck && b.synAck {
		a.synAck, a.synAckSeq, a.synAckOf = true, b.synAckSeq, b.synAckOf
	}
	a.established = a.established || b.established
	return true
}

// Observe records reply/handshake progress, not guessed midstream completion.
func (a *Admission) Observe(proto uint8, dir Direction, syn, ack, handshake bool, seq, ackSeq uint32) {
	r := a.root()
	r.seen |= 1 << dir
	if proto != 6 {
		r.established = r.seen == 3
		return
	}
	if syn && !ack && dir == DirForward {
		if r.syn && r.synSeq != seq && handshake {
			r.synAck, r.established = false, false
		}
		if r.established {
			return // an unverified SYN cannot change a live connection
		}
		r.syn = true
		r.synSeq = seq
	}
	if syn && ack && dir == DirReverse {
		r.synAck = true
		r.synAckSeq = seq
		r.synAckOf = ackSeq
	}
	if !syn && ack && dir == DirForward && r.syn && r.synAck &&
		r.synAckOf == r.synSeq+1 && seq == r.synSeq+1 && ackSeq == r.synAckSeq+1 {
		r.established = true
	}
}

func (a *Admission) Established() bool { return a.root().established }
