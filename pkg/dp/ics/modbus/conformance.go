// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"slices"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func addConformance(state *flow.State, f *TCPFrame, kind string, attrs map[string]any) {
	var codes []string
	if f.ProtocolID != 0 {
		codes = append(codes, "modbus.pid_nonzero")
	}
	if f.FunctionCode >= 128 && state != nil && state.Key.Dir == flow.DirForward {
		codes = append(codes, "modbus.request_exception")
	}
	if !validLayout(f.FunctionCode, f.PDU, kind == "response") {
		codes = append(codes, "modbus.pdu_layout")
	}
	limit := uint16(0)
	switch f.FunctionCode {
	case 1, 2:
		limit = maxReadBits
	case 3, 4:
		limit = maxReadRegisters
	case 15:
		limit = maxWriteBits
	case 16:
		limit = maxWriteRegisters
	}
	for key, maxQty := range map[string]uint16{
		attrQuantity: limit, attrReadQuantity: maxReadRegisters, attrWriteQuantity: maxRWWrite,
	} {
		if q, ok := eventfields.Uint16(attrs, key); ok && maxQty != 0 && (q == 0 || q > maxQty) {
			codes = append(codes, "modbus.quantity_range")
		}
	}
	if len(codes) > 0 {
		slices.Sort(codes)
		attrs[eventfields.KeyConformance] = slices.Compact(codes)
	}
}

// Validate known layouts and device identification objects, not vendor-defined
// function codes or MEI formats whose layout we do not interpret.
func validLayout(fc uint8, p []byte, response bool) bool {
	if fc >= 128 {
		return len(p) == 1
	}
	if response {
		switch fc {
		case 7:
			return len(p) == 1
		case 11:
			return len(p) == 4
		case 12, 17:
			return len(p) >= 1 && len(p) == 1+int(p[0])
		case 1, 2, 3, 4, 23:
			return len(p) >= 1 && p[0] > 0 && len(p) == 1+int(p[0]) &&
				((fc == 1 || fc == 2) || p[0]%2 == 0)
		case 5, 6, 15, 16:
			return len(p) == 4
		case 22:
			return len(p) == 6
		}
	} else {
		switch fc {
		case 7, 11, 12, 17:
			return len(p) == 0
		case 1, 2, 3, 4, 5, 6:
			return len(p) == 4
		case 15, 16:
			if len(p) < 5 || len(p) != 5+int(p[4]) {
				return false
			}
			q := int(be16(p, 2))
			want := 2 * q
			if fc == 15 {
				want = (q + 7) / 8
			}
			return int(p[4]) == want
		case 22:
			return len(p) == 6
		case 23:
			return len(p) >= 9 && len(p) == 9+int(p[8]) && int(p[8]) == 2*int(be16(p, 6))
		}
	}
	switch fc {
	case 8:
		return len(p) >= 4 && len(p)%2 == 0
	case 43:
		if len(p) < 1 {
			return false
		}
		if p[0] != 14 {
			return true // other MEI formats are not interpreted
		}
		if !response {
			return len(p) == 3
		}
		if len(p) < 6 {
			return false
		}
		pos := 6
		for i := 0; i < int(p[5]); i++ {
			if len(p)-pos < 2 {
				return false
			}
			size := int(p[pos+1])
			pos += 2
			if size > len(p)-pos {
				return false
			}
			pos += size
		}
		return pos == len(p)
	}
	return true
}
