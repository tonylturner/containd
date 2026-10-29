// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"

	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
)

var protocols = [4]Protocol{Modbus, DNP3, IEC104, ENIP}

type evidence struct {
	state      State
	end        int
	role       Role
	why        string
	neutral    bool // a complete NOP-only prefix, not a partial UDP frame
	modbus     []modbusMessage
	enip       []enipMessage
	uAct, uCon uint8
}

// Probe is pure and non-emitting. TCP arguments start at stream origin; UDP
// arguments are whole individual datagrams, never concatenated datagrams.
// Callers must bound their input (Table enforces its configured byte budget).
func Probe(p Protocol, transport uint8, forward, reverse []byte) Result {
	return probe(p, transport, forward, reverse, [2]int{len(forward), len(reverse)})
}

// wireLengths preserves UDP boundaries when admission clips the available bytes.
// Public Probe always receives complete datagrams.
func probe(p Protocol, transport uint8, forward, reverse []byte, wireLengths [2]int) Result {
	r := Result{Protocol: p, State: Reject, States: [2]State{Reject, Reject}, Transport: transport, Role: Unknown, Version: ProfileVersion}
	if transport != ics.TCP && (transport != ics.UDP || p != ENIP) {
		r.Reason = "unsupported transport"
		return r
	}
	a, b := inspect(p, transport, forward, wireLengths[0]), inspect(p, transport, reverse, wireLengths[1])
	r.States = [2]State{a.state, b.state}
	r.Examined = [2]Range{{End: a.end}, {End: b.end}}
	best := a
	if len(forward) == 0 || len(reverse) > 0 && strength(b.state) > strength(a.state) {
		best = b
	}
	r.State, r.Reason = best.state, best.why
	r.Role = a.role
	if len(forward) == 0 && len(reverse) == 0 {
		r.State, r.Reason = NeedMore, "empty"
		if transport == ics.UDP && wireLengths == [2]int{} {
			r.State, r.Reason = Reject, "empty datagram"
			r.States[0] = Reject
		}
	}
	// Correlation cannot rehabilitate a partner that failed its own profile
	// checks (including datagram boundaries and encapsulation size limits).
	if strength(a.state) >= 2 && strength(b.state) >= 2 &&
		paired(p, a, b) {
		r.State, r.Reason = Confirmed, "paired frames"
	}
	if r.State == Confirmed && (len(forward) > 0 && a.state == Reject || len(reverse) > 0 && b.state == Reject) {
		r.State, r.Reason = Candidate, "contradictory directional evidence"
	}
	return r
}

func paired(p Protocol, a, b evidence) bool {
	switch p {
	case Modbus:
		for _, x := range a.modbus {
			for _, y := range b.modbus {
				if x.tid == y.tid && x.unit == y.unit && x.fc == y.fc && (x.req && y.rsp || x.rsp && y.req) {
					return true
				}
			}
		}
	case ENIP:
		for _, x := range a.enip {
			for _, y := range b.enip {
				if enipPair(x, y) || enipPair(y, x) {
					return true
				}
			}
		}
	case IEC104:
		return a.uAct&b.uCon != 0 || a.uCon&b.uAct != 0
	}
	return false
}

func strength(s State) int {
	switch s {
	case Confirmed:
		return 3
	case Candidate:
		return 2
	case NeedMore:
		return 1
	default:
		return 0
	}
}

func inspect(p Protocol, transport uint8, b []byte, wireLength int) evidence {
	if len(b) == 0 {
		return evidence{state: NeedMore, role: Unknown, why: "empty direction"}
	}
	var e evidence
	switch p {
	case Modbus:
		e = modbusEvidence(b)
	case DNP3:
		e = dnpEvidence(b)
	case IEC104:
		e = iecEvidence(b)
	case ENIP:
		e = enipEvidence(b, transport == ics.UDP, wireLength)
		if transport == ics.UDP && e.state == NeedMore && !e.neutral && wireLength == len(b) {
			e = invalid(b)
		}
	default:
		e = evidence{state: Reject, why: "unknown protocol"}
	}
	if e.role == "" {
		e.role = Unknown
	}
	return e
}

func pending(b []byte) evidence {
	return evidence{state: NeedMore, end: len(b), why: "partial frame"}
}

func invalid(b []byte) evidence {
	return evidence{state: Reject, end: len(b), why: "invalid frame"}
}

func dnpEvidence(b []byte) evidence {
	if b[0] != 5 || len(b) > 1 && b[1] != 0x64 {
		return invalid(b[:min(len(b), 2)])
	}
	f, err := dnp3.ParseFrame(b)
	if err == dnp3.ErrTooShort {
		return pending(b)
	}
	if err != nil || !f.DataCRCValid() || !legalLinkControl(f.Control) {
		return invalid(b)
	}
	size := 10 + len(f.Data) + 2*((len(f.Data)+15)/16)
	role := Server
	if f.Control&dnp3.ControlDIR != 0 {
		role = Client
	}
	return evidence{state: Confirmed, end: size, role: role, why: "link header and block CRCs"}
}

func legalLinkControl(c byte) bool {
	fc := c & 15
	if c&dnp3.ControlPRM != 0 {
		switch fc {
		case 0, 1, 2, 3, 4, 9:
			sequenced := fc == 2 || fc == 3
			return (c&dnp3.ControlFCV != 0) == sequenced
		}
		return false
	}
	return c&dnp3.ControlFCB == 0 && (fc == 0 || fc == 1 || fc == 11 || fc == 15)
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
