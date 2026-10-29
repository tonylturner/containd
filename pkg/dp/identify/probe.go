// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"

	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
)

var protocols = [4]Protocol{Modbus, DNP3, IEC104, ENIP}

type evidence struct {
	state State
	end   int
	role  Role
	why   string
	// Correlation is applied only to complete, shape-checked frames.
	pair func([]byte) bool
}

// Probe is pure and non-emitting. TCP arguments start at stream origin; UDP
// arguments are whole individual datagrams, never concatenated datagrams.
// Callers must bound their input (Table enforces its configured byte budget).
func Probe(p Protocol, transport uint8, forward, reverse []byte) Result {
	r := Result{Protocol: p, State: Reject, Transport: transport, Role: Unknown, Version: ProfileVersion}
	if transport != ics.TCP && (transport != ics.UDP || p != ENIP) {
		r.Reason = "unsupported transport"
		return r
	}
	a, b := inspect(p, transport, forward), inspect(p, transport, reverse)
	r.Examined = [2]Range{{End: a.end}, {End: b.end}}
	best := a
	if strength(b.state) > strength(a.state) {
		best = b
	}
	r.State, r.Reason = best.state, best.why
	r.Role = a.role
	if len(forward) == 0 && len(reverse) == 0 {
		r.State, r.Reason = NeedMore, "empty"
		if transport == ics.UDP {
			r.State, r.Reason = Reject, "empty datagram"
		}
	}
	// Correlation cannot rehabilitate a partner that failed its own profile
	// checks (including datagram boundaries and encapsulation size limits).
	if strength(a.state) >= 2 && strength(b.state) >= 2 &&
		(a.pair != nil && a.pair(reverse) || b.pair != nil && b.pair(forward)) {
		r.State, r.Reason = Confirmed, "paired frames"
	}
	return r
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

func inspect(p Protocol, transport uint8, b []byte) evidence {
	if len(b) == 0 {
		return evidence{state: Reject, role: Unknown, why: "empty direction"}
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
		e = enipEvidence(b, transport == ics.UDP)
		if transport == ics.UDP && e.state == NeedMore {
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
			return (c&dnp3.ControlFCV != 0) == sequenced &&
				(sequenced || c&dnp3.ControlFCB == 0)
		}
		return false
	}
	return c&dnp3.ControlFCB == 0 && (fc == 0 || fc == 1 || fc == 11 || fc == 15)
}

func iecEvidence(b []byte) evidence {
	if b[0] != 0x68 {
		return invalid(b[:1])
	}
	v, err := iec104.ValidateAPDU(b)
	if err != nil {
		return invalid(b)
	}
	if v.Size == 0 {
		return pending(b)
	}
	e := evidence{state: Candidate, end: v.Size, why: "single APDU"}
	if !v.Supported {
		e.why = "unsupported ASDU profile"
		return e
	}
	if v.UFunction != "" {
		e.pair = func(other []byte) bool {
			w, err := iec104.ValidateAPDU(other)
			if err != nil || w.Size == 0 || w.UFunction == "" {
				return false
			}
			switch v.UFunction + "/" + w.UFunction {
			case "startdt_act/startdt_con", "startdt_con/startdt_act",
				"stopdt_act/stopdt_con", "stopdt_con/stopdt_act",
				"testfr_act/testfr_con", "testfr_con/testfr_act":
				return true
			}
			return false
		}
	}
	w, err := iec104.ValidateAPDU(b[v.Size:])
	if err == nil && w.Size > 0 && w.Supported && (v.Format != "S" || w.Format != "S") {
		e.state, e.end, e.why = Confirmed, v.Size+w.Size, "consecutive APDUs"
	}
	return e
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
