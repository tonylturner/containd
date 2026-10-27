// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func findingADU(pid uint16, fc byte, p []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[2:4], pid)
	binary.BigEndian.PutUint16(b[4:6], uint16(2+len(p)))
	b[6], b[7] = 1, fc
	return append(b, p...)
}

func TestConformanceTwins(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		pid        uint16
		fc         byte
		bad, good  []byte
		reply      bool
	}{
		{"pid", "modbus.pid_nonzero", 1, 3, []byte{0, 1, 0, 1}, []byte{0, 1, 0, 1}, false},
		{"short diagnostic", "modbus.pdu_layout", 0, 8, []byte{0, 0}, []byte{0, 0, 0, 1}, false},
		{"short device ID", "modbus.pdu_layout", 0, 43, []byte{14}, []byte{14, 1, 0}, false},
		{"short device ID object", "modbus.pdu_layout", 0, 43, []byte{14, 1, 1, 0, 0, 1, 0, 2, 1}, []byte{14, 1, 1, 0, 0, 1, 0, 2, 1, 2}, true},
		{"short status", "modbus.pdu_layout", 0, 7, nil, []byte{0}, true},
		{"short", "modbus.pdu_layout", 0, 3, []byte{0, 1, 0}, []byte{0, 1, 0, 1}, false},
		{"trailing", "modbus.pdu_layout", 0, 6, []byte{0, 1, 0, 1, 0}, []byte{0, 1, 0, 1}, false},
		{"byte count", "modbus.pdu_layout", 0, 16, []byte{0, 1, 0, 2, 2, 0, 1}, []byte{0, 1, 0, 1, 2, 0, 1}, false},
		{"truncated data", "modbus.pdu_layout", 0, 16, []byte{0, 1, 0, 1, 2, 0}, []byte{0, 1, 0, 1, 2, 0, 1}, false},
		{"zero", "modbus.quantity_range", 0, 3, []byte{0, 1, 0, 0}, []byte{0, 1, 0, 1}, false},
		{"limit", "modbus.quantity_range", 0, 3, []byte{0, 1, 0, 126}, []byte{0, 1, 0, 125}, false},
		{"two quantities", "modbus.quantity_range", 0, 23, []byte{0, 1, 0, 0, 0, 1, 0, 0, 0}, []byte{0, 1, 0, 1, 0, 1, 0, 1, 2, 0, 1}, false},
		{"request exception", "modbus.request_exception", 0, 0x83, []byte{2}, []byte{2}, true},
		{"odd register reply", "modbus.pdu_layout", 0, 3, []byte{1, 0}, []byte{2, 0, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []bool{true, false} {
				p, pid := tc.good, uint16(0)
				st := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 40000, 502), time.Now())
				if tc.reply {
					st.Key = st.Key.Reversed()
				}
				if bad {
					p, pid = tc.bad, tc.pid
					if tc.code == "modbus.request_exception" {
						st.Key = st.Key.Reversed()
					}
				}
				raw := findingADU(pid, tc.fc, p)
				res, err := NewDecoder().ParseStream(st, dpi.StreamView{Bytes: append(raw, findingADU(0, 3, []byte{0, 1, 0, 1})...)})
				if err != nil || len(res.Frames) != 2 || res.Consumed != len(raw)+12 {
					t.Fatalf("boundary: %+v %v", res, err)
				}
				for form, attrs := range decodertest.Forms(t, res.Frames[0].Events[0].Attributes) {
					codes, _ := eventfields.Strings(attrs, eventfields.KeyConformance)
					var want []string
					if bad {
						want = []string{tc.code}
					}
					if !reflect.DeepEqual(codes, want) {
						t.Fatalf("%s bad=%v codes=%v want=%v", form, bad, codes, want)
					}
				}
			}
		})
	}
}

func TestPartialFieldsRemainAbsentWhenUnread(t *testing.T) {
	ev := aduEvent(nil, &TCPFrame{FunctionCode: 23, PDU: []byte{0, 1, 0, 2, 0}}, nil)
	if ev.Attributes["read_address"] != uint16(1) || ev.Attributes["read_quantity"] != uint16(2) {
		t.Fatal(ev.Attributes)
	}
	for _, k := range []string{"write_address", "write_quantity", "byte_count"} {
		if _, ok := ev.Attributes[k]; ok {
			t.Fatalf("invented %s", k)
		}
	}
}
