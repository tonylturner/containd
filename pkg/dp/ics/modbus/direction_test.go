// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestModbusConnectionDirection(t *testing.T) {
	for _, ports := range [][2]uint16{{502, 41000}, {502, 502}, {41000, 502}} {
		for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
			st := modbusState()
			st.Key.SrcPort, st.Key.DstPort, st.Key.Dir = ports[0], ports[1], dir
			kind := "request"
			if dir == flow.DirReverse {
				kind = "response"
			}
			for _, tc := range []struct {
				adu  []byte
				kind string
			}{
				{[]byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 10, 0, 2}, kind},
				{writeADU, kind},
				{[]byte{0, 1, 0, 0, 0, 3, 1, 0x83, 2}, "exception"},
			} {
				// Both packet and streaming entry points must use the same authority.
				evs, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: tc.adu})
				if err != nil || len(evs) != 1 {
					t.Fatalf("packet: %+v %v", evs, err)
				}
				res, err := NewDecoder().ParseStream(st, dpi.StreamView{Bytes: tc.adu})
				if err != nil || len(res.Frames) != 1 {
					t.Fatalf("stream: %+v %v", res, err)
				}
				for _, ev := range []dpi.Event{evs[0], res.Frames[0].Events[0]} {
					if ev.Kind != tc.kind {
						t.Fatalf("ports=%v dir=%v kind=%q want %q", ports, dir, ev.Kind, tc.kind)
					}
					if tc.adu[7] == 3 && dir == flow.DirForward && ev.Attributes["address"] != uint16(10) {
						t.Fatalf("request lost its address: %+v", ev)
					}
					if tc.kind == "exception" && (ev.Attributes["function_code"] != uint8(3) || ev.Attributes["exception_code"] != uint8(2)) {
						t.Fatalf("exception lost its fields: %+v", ev)
					}
				}
			}
		}
	}
}
