// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"errors"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

type modbusMessage struct {
	tid      uint16
	unit, fc uint8
	req, rsp bool
}

func modbusEvidence(b []byte) evidence {
	e := pending(b)
	for offset := 0; offset < len(b); {
		rest := b[offset:]
		if len(rest) >= 4 && be16(rest[2:4]) != 0 {
			return invalid(b[:offset+4])
		}
		f, err := modbus.ParseTCPFrame(rest)
		if errors.Is(err, modbus.ErrTooShort) {
			break
		}
		if err != nil || f.ProtocolID != 0 || f.FunctionCode&0x7f == 0 {
			return invalid(b)
		}
		req, rsp, supported := modbusShape(f)
		if supported && !req && !rsp {
			return invalid(b)
		}
		e.state, e.why = Candidate, "complete FC shape"
		if !supported {
			e.why = "unsupported function shape"
		} else {
			e.modbus = append(e.modbus, modbusMessage{f.TransactionID, f.UnitID, f.FunctionCode & 0x7f, req, rsp})
		}
		role := Unknown
		if req && !rsp {
			role = Client
		} else if rsp && !req {
			role = Server
		}
		if offset == 0 {
			e.role = role
		} else if e.role != role {
			e.role = Unknown
		}
		offset += 6 + int(f.Length)
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
