// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"fmt"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func assertAccess(t *testing.T, attrs map[string]any, known, write bool) {
	t.Helper()
	got, present := eventfields.Bool(attrs, eventfields.KeyIsWrite)
	if present != known || known && got != write {
		t.Fatalf("is_write=%v/%v want=%v/%v attrs=%+v", got, present, write, known, attrs)
	}
	if _, present := attrs["is_control"]; present {
		t.Fatal("Modbus unexpectedly emitted is_control")
	}
}

func TestAccessEveryFunctionCode(t *testing.T) {
	for code := range 256 {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			fc := uint8(code)
			base := fc & 0x7f // Exceptions identify only the base function.
			write := slices.Contains([]uint8{5, 6, 15, 16, 21, 22, 23}, base)
			known := write || slices.Contains([]uint8{1, 2, 3, 4, 7, 11, 12, 17, 20, 24}, base)
			for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
				st := modbusState()
				st.Key.Dir = dir
				var pdu []byte
				if fc >= 128 {
					pdu = []byte{14} // Exception data is never a MEI subtype.
				}
				ev := aduEvent(st, &TCPFrame{FunctionCode: fc, PDU: pdu}, nil)
				kind := "request"
				if dir == flow.DirReverse {
					kind = "response"
				}
				if fc >= 128 {
					kind = "exception"
				}
				if ev.Kind != kind || ev.Attributes["function_code"] != base {
					t.Fatal(ev)
				}
				for _, attrs := range decodertest.Forms(t, ev.Attributes) {
					assertAccess(t, attrs, known, write)
				}
			}
		})
	}
}

func TestAccessEveryDiagnosticSubfunction(t *testing.T) {
	for sub := range 1 << 16 {
		write := slices.Contains([]int{1, 3, 4, 10, 20}, sub)
		known := write || slices.Contains([]int{0, 2, 11, 12, 13, 14, 15, 16, 17, 18}, sub)
		for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
			st := modbusState()
			st.Key.Dir = dir
			ev := aduEvent(st, &TCPFrame{FunctionCode: 8, PDU: []byte{byte(sub >> 8), byte(sub), 0, 0}}, nil)
			assertAccess(t, ev.Attributes, known, write)
		}
	}
	for _, pdu := range [][]byte{nil, {0}} {
		ev := aduEvent(nil, &TCPFrame{FunctionCode: 8, PDU: pdu}, nil)
		assertAccess(t, ev.Attributes, false, false)
	}
}

func TestAccessEveryMEIType(t *testing.T) {
	for mei := range 256 {
		t.Run(fmt.Sprint(mei), func(t *testing.T) {
			for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
				st := modbusState()
				st.Key.Dir = dir
				ev := aduEvent(st, &TCPFrame{FunctionCode: 43, PDU: []byte{byte(mei), 1, 0}}, nil)
				for _, attrs := range decodertest.Forms(t, ev.Attributes) {
					assertAccess(t, attrs, mei == 14, false)
				}
			}
		})
	}
}
