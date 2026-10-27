// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// goldenADU is one ADU captured on the wire between a pymodbus 3.11.4
// client and server, with the fields the decoder must emit for it and the
// spans they bound.
type goldenADU struct {
	name   string
	hex    string
	reply  bool
	fields map[string]any // data-access fields only
	spans  []Span
	ok     bool
}

var goldenADUs = []goldenADU{
	// FC 1 read coils 5 count 10, and its reply of two data bytes.
	{"fc1 request", "00010000000601010005000a", false, map[string]any{"address": uint16(5), "quantity": uint16(10)}, []Span{{5, 14}}, true},
	{"fc1 reply", "0001000000050101020000", true, map[string]any{"byte_count": uint8(2)}, nil, false},
	// FC 3 read holding registers 10 count 2; the reply carries values 11
	// and 12, never an address or quantity.
	{"fc3 request", "0002000000060103000a0002", false, map[string]any{"address": uint16(10), "quantity": uint16(2)}, []Span{{10, 11}}, true},
	{"fc3 reply", "000200000007010304000b000c", true, map[string]any{"byte_count": uint8(4), "register_count": uint16(2)}, nil, false},
	// Formerly decoded as address 1024, quantity 2816.
	{"fc3 reply seen as address 1024", "000100000007010304000b000c", true, map[string]any{"byte_count": uint8(4), "register_count": uint16(2)}, nil, false},
	{"fc3 range-crossing request", "0001000000060103000b0008", false, map[string]any{"address": uint16(11), "quantity": uint16(8)}, []Span{{11, 18}}, true},
	// FC 5 write single coil 7 on; the reply echoes it.
	{"fc5 request", "00030000000601050007ff00", false, map[string]any{"address": uint16(7), "value": uint16(0xFF00)}, []Span{{7, 7}}, true},
	{"fc5 reply", "00030000000601050007ff00", true, map[string]any{"address": uint16(7), "value": uint16(0xFF00)}, []Span{{7, 7}}, true},
	// FC 6 write single register 100 value 123; the reply echoes it.
	{"fc6 request", "00040000000601060064007b", false, map[string]any{"address": uint16(100), "value": uint16(123)}, []Span{{100, 100}}, true},
	{"fc6 reply", "00040000000601060064007b", true, map[string]any{"address": uint16(100), "value": uint16(123)}, []Span{{100, 100}}, true},
	// FC 15 write multiple coils 20 count 10 (two data bytes); the reply
	// echoes address and quantity.
	{"fc15 request", "000500000009010f0014000a02cd01", false, map[string]any{"address": uint16(20), "quantity": uint16(10), "byte_count": uint8(2)}, []Span{{20, 29}}, true},
	{"fc15 reply", "000500000006010f0014000a", true, map[string]any{"address": uint16(20), "quantity": uint16(10)}, []Span{{20, 29}}, true},
	// FC 16 write multiple registers 30 values 123, 456; reply echoes.
	{"fc16 request", "00060000000b0110001e000204007b01c8", false, map[string]any{"address": uint16(30), "quantity": uint16(2), "byte_count": uint8(4)}, []Span{{30, 31}}, true},
	{"fc16 reply", "0006000000060110001e0002", true, map[string]any{"address": uint16(30), "quantity": uint16(2)}, []Span{{30, 31}}, true},
	{"fc16 range-crossing request", "0001000000170110000b000810038403850386038703880389038a038b", false, map[string]any{"address": uint16(11), "quantity": uint16(8), "byte_count": uint8(16)}, []Span{{11, 18}}, true},
	// FC 23 read 40 count 2, write 50 values 7, 8; the reply carries the
	// two read values.
	{"fc23 request", "00070000000f011700280002003200020400070008", false, map[string]any{"read_address": uint16(40), "read_quantity": uint16(2), "write_address": uint16(50), "write_quantity": uint16(2), "byte_count": uint8(4)}, []Span{{40, 41}, {50, 51}}, true},
	{"fc23 reply", "0007000000070117040029002a", true, map[string]any{"byte_count": uint8(4), "register_count": uint16(2)}, nil, false},
	// Unknown function code 0x5a and a PDU of only a function code.
	{"unknown fc request", "007000000006015a000a0002", false, map[string]any{}, nil, false},
	{"short pdu request", "0073000000020103", false, map[string]any{}, nil, false},
}

func TestGoldenADUFields(t *testing.T) {
	for _, tc := range goldenADUs {
		raw, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", tc.name, err)
		}
		st := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 40000, 502), time.Now())
		wantKind := "request"
		if tc.reply {
			st.Key = st.Key.Reversed()
			wantKind = "response"
		}
		events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: raw})
		if err != nil || len(events) != 1 {
			t.Fatalf("%s: OnPacket = %d events, %v", tc.name, len(events), err)
		}
		ev := events[0]
		if ev.Kind != wantKind {
			t.Fatalf("%s: kind %q, want %q", tc.name, ev.Kind, wantKind)
		}
		got := map[string]any{}
		for k, v := range ev.Attributes {
			switch k {
			case "transaction_id", "unit_id", "function_code", "is_write", "raw_hex":
			default:
				got[k] = v
			}
		}
		if !reflect.DeepEqual(got, tc.fields) {
			t.Errorf("%s: fields %#v, want %#v", tc.name, got, tc.fields)
		}
		// Spans read the same from the live and the stored JSON form.
		for form, attrs := range decodertest.Forms(t, ev.Attributes) {
			spans, ok := AddressSpans(attrs)
			if ok != tc.ok || !reflect.DeepEqual(spans, tc.spans) {
				t.Errorf("%s/%s: AddressSpans = %v, %v; want %v, %v", tc.name, form, spans, ok, tc.spans, tc.ok)
			}
		}
	}
}
