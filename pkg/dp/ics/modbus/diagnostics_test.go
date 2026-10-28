// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"fmt"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestDiagnosticSubfunctions(t *testing.T) {
	// Independent expected access categories, not read back from the descriptor.
	for _, sub := range []uint16{0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20} {
		t.Run(fmt.Sprint(sub), func(t *testing.T) {
			write := slices.Contains([]uint16{1, 3, 4, 10, 20}, sub)
			data := uint16(0)
			if sub == 3 {
				data = 0x0a00
			}
			p := []byte{byte(sub >> 8), byte(sub), byte(data >> 8), byte(data)}
			st := modbusState()
			for _, reply := range []bool{false, true} {
				if reply {
					st.Key = st.Key.Reversed()
				}
				ev := aduEvent(st, &TCPFrame{FunctionCode: 8, PDU: p}, nil)
				kind := "request"
				if reply {
					kind = "response"
				}
				if ev.Kind != kind || ev.Attributes["is_write"] != write || ev.Attributes["sub_function"] != sub {
					t.Fatal(ev)
				}
				codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance)
				if slices.Contains(codes, "modbus.pdu_layout") != (reply && sub == 4) {
					t.Fatalf("reply=%v: %v", reply, ev)
				}
				// Exceptions carry no subfunction. Never invent request identity
				// or copy its write category onto an uncorrelated exception.
				ex := aduEvent(st, &TCPFrame{FunctionCode: 0x88, PDU: []byte{3}}, nil)
				if ex.Kind != "exception" || ex.Attributes["function_code"] != byte(8) ||
					ex.Attributes["is_write"] != false || ex.Attributes["exception_code"] != byte(3) {
					t.Fatal(ex)
				}
				if _, ok := ex.Attributes["sub_function"]; ok {
					t.Fatal("exception invented a subfunction")
				}
				ec, _ := eventfields.Strings(ex.Attributes, eventfields.KeyConformance)
				if slices.Contains(ec, "modbus.request_exception") != !reply {
					t.Fatal(ex)
				}
				for _, bad := range [][]byte{p[:2], append(slices.Clone(p), 0, 0), append(slices.Clone(p), 1)} {
					if sub == 0 && len(bad) == 6 {
						continue // query data is explicitly multiple words
					}
					if validLayout(8, bad, reply) {
						t.Fatalf("accepted bad layout %x reply=%v", bad, reply)
					}
				}
			}
		})
	}
}

func TestDiagnosticDataRules(t *testing.T) {
	for _, tc := range []struct {
		sub, data uint16
		reply, ok bool
	}{
		{0, 0xabcd, false, true}, {1, 0xff00, false, true},
		{1, 1, false, false}, {1, 1, true, false},
		{2, 1, false, false}, {2, 0xffff, true, true},
		{3, 0x0a00, false, true}, {3, 0x000a, false, false},
		{3, 0x000a, true, false}, {4, 0, true, false},
		{4, 1, false, false}, {10, 1, false, false}, {10, 1, true, false},
		{11, 1, false, false}, {11, 0xffff, true, true},
		{18, 1, false, false}, {18, 0xffff, true, true},
		{20, 1, false, false}, {20, 1, true, false},
	} {
		p := []byte{byte(tc.sub >> 8), byte(tc.sub), byte(tc.data >> 8), byte(tc.data)}
		if got := validLayout(8, p, tc.reply); got != tc.ok {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
	for _, sub := range []uint16{5, 9, 19, 21, 0xffff} {
		ev := aduEvent(nil, &TCPFrame{FunctionCode: 8, PDU: []byte{byte(sub >> 8), byte(sub), 0, 0}}, nil)
		codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyUndecoded)
		if !slices.Equal(codes, []string{"modbus.diagnostics_subfunction"}) {
			t.Fatal(ev)
		}
	}
}
