// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"errors"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func modbusEvidence(b []byte) evidence {
	if len(b) >= 4 && be16(b[2:4]) != 0 {
		return invalid(b[:4])
	}
	f, err := modbus.ParseTCPFrame(b)
	if errors.Is(err, modbus.ErrTooShort) {
		return pending(b)
	}
	if err != nil || f.ProtocolID != 0 || f.FunctionCode&0x7f == 0 {
		return invalid(b)
	}
	req, rsp, supported := modbusShape(f)
	e := evidence{state: Candidate, end: 6 + int(f.Length), why: "unsupported function shape"}
	if !supported {
		return e
	}
	if !req && !rsp {
		return invalid(b[:e.end])
	}
	e.why = "complete FC shape"
	if req && !rsp {
		e.role = Client
	} else if rsp && !req {
		e.role = Server
	}
	e.pair = func(other []byte) bool {
		g, err := modbus.ParseTCPFrame(other)
		if err != nil || g.ProtocolID != 0 || g.TransactionID != f.TransactionID ||
			g.UnitID != f.UnitID || g.FunctionCode&0x7f != f.FunctionCode&0x7f {
			return false
		}
		greq, grsp, ok := modbusShape(g)
		return ok && (req && grsp || rsp && greq)
	}
	return e
}

// Shape validation is deliberately separate from the tolerant framing reader.
// Unsupported public/private FC layouts stay candidates and cannot pair-confirm.
func modbusShape(f *modbus.TCPFrame) (req, rsp, supported bool) {
	p, fc := f.PDU, f.FunctionCode
	if fc&0x80 != 0 {
		_, _, supported = modbusShape(&modbus.TCPFrame{FunctionCode: fc & 0x7f})
		return false, len(p) == 1 && p[0] >= 1 && p[0] <= 11, supported
	}
	supported = true
	switch fc {
	case 1, 2, 3, 4:
		maxQ := uint16(2000)
		if fc >= 3 {
			maxQ = 125
		}
		req = len(p) == 4 && be16(p[2:]) > 0 && be16(p[2:]) <= maxQ
		rsp = len(p) >= 2 && int(p[0]) == len(p)-1 && (fc <= 2 || p[0]%2 == 0)
	case 5:
		req = len(p) == 4 && (be16(p[2:]) == 0 || be16(p[2:]) == 0xff00)
		rsp = req
	case 6:
		req, rsp = len(p) == 4, len(p) == 4
	case 7:
		req, rsp = len(p) == 0, len(p) == 1
	case 8:
		req, rsp = len(p) >= 4 && len(p)%2 == 0, len(p) >= 4 && len(p)%2 == 0
	case 15, 16:
		maxQ := uint16(1968)
		if fc == 16 {
			maxQ = 123
		}
		quantityOK := len(p) >= 4 && be16(p[2:]) > 0 && be16(p[2:]) <= maxQ
		rsp = len(p) == 4 && quantityOK
		if len(p) >= 5 && quantityOK {
			n := (int(be16(p[2:])) + 7) / 8
			if fc == 16 {
				n = int(be16(p[2:])) * 2
			}
			req = n == int(p[4]) && len(p) == 5+n
		}
	case 17:
		req = len(p) == 0
		rsp = len(p) >= 3 && int(p[0]) == len(p)-1
	case 22:
		req, rsp = len(p) == 6, len(p) == 6
	case 23:
		rsp = len(p) >= 3 && p[0]%2 == 0 && int(p[0]) == len(p)-1
		if len(p) >= 9 {
			rq, wq := be16(p[2:]), be16(p[6:])
			req = rq > 0 && rq <= 125 && wq > 0 && wq <= 121 &&
				int(p[8]) == 2*int(wq) && len(p) == 9+int(p[8])
		}
	default:
		supported = false
	}
	return
}
