// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import (
	"reflect"
	"testing"
)

func fcAttrs(fc uint8, kv ...any) map[string]any {
	attrs := map[string]any{"function_code": fc}
	for i := 0; i < len(kv); i += 2 {
		attrs[kv[i].(string)] = kv[i+1]
	}
	return attrs
}

// AddressSpans bounds a message only within the specification's quantity
// limits, a matching byte count and the 16-bit address space.
func TestAddressSpansLimits(t *testing.T) {
	u16 := func(v int) uint16 { return uint16(v) }
	cases := []struct {
		name  string
		attrs map[string]any
		spans []Span
		ok    bool
	}{
		{"fc1 max", fcAttrs(1, "address", u16(0), "quantity", u16(2000)), []Span{{0, 1999}}, true},
		{"fc1 over", fcAttrs(1, "address", u16(0), "quantity", u16(2001)), nil, false},
		{"fc2 zero", fcAttrs(2, "address", u16(0), "quantity", u16(0)), nil, false},
		{"fc3 max", fcAttrs(3, "address", u16(10), "quantity", u16(125)), []Span{{10, 134}}, true},
		{"fc3 over", fcAttrs(3, "address", u16(10), "quantity", u16(126)), nil, false},
		{"fc4 zero", fcAttrs(4, "address", u16(10), "quantity", u16(0)), nil, false},
		{"fc3 last address", fcAttrs(3, "address", u16(65535), "quantity", u16(1)), []Span{{65535, 65535}}, true},
		{"fc3 past 65535", fcAttrs(3, "address", u16(65535), "quantity", u16(2)), nil, false},
		{"fc3 missing quantity", fcAttrs(3, "address", u16(10)), nil, false},
		{"fc6 single", fcAttrs(6, "address", u16(9), "value", u16(0xFFFF)), []Span{{9, 9}}, true},
		{"fc6 missing address", fcAttrs(6), nil, false},
		{"fc22 single", fcAttrs(22, "address", u16(4), "and_mask", u16(0xF2), "or_mask", u16(0x25)), []Span{{4, 4}}, true},
		{"fc15 max", fcAttrs(15, "address", u16(0), "quantity", u16(1968), "byte_count", uint8(246)), []Span{{0, 1967}}, true},
		{"fc15 over", fcAttrs(15, "address", u16(0), "quantity", u16(1969), "byte_count", uint8(247)), nil, false},
		{"fc15 byte count short", fcAttrs(15, "address", u16(0), "quantity", u16(10), "byte_count", uint8(1)), nil, false},
		{"fc16 max", fcAttrs(16, "address", u16(0), "quantity", u16(123), "byte_count", uint8(246)), []Span{{0, 122}}, true},
		{"fc16 over", fcAttrs(16, "address", u16(0), "quantity", u16(124), "byte_count", uint8(248)), nil, false},
		{"fc16 zero", fcAttrs(16, "address", u16(0), "quantity", u16(0), "byte_count", uint8(0)), nil, false},
		// Byte count for 8 registers with a quantity of 2: the server may
		// write either count, so the span is not bounded.
		{"fc16 byte count disagrees", fcAttrs(16, "address", u16(10), "quantity", u16(2), "byte_count", uint8(16)), nil, false},
		{"fc16 echo without byte count", fcAttrs(16, "address", u16(10), "quantity", u16(2)), []Span{{10, 11}}, true},
		{"fc23 max", fcAttrs(23, "read_address", u16(0), "read_quantity", u16(125), "write_address", u16(200), "write_quantity", u16(121), "byte_count", uint8(242)), []Span{{0, 124}, {200, 320}}, true},
		{"fc23 read over", fcAttrs(23, "read_address", u16(0), "read_quantity", u16(126), "write_address", u16(200), "write_quantity", u16(1), "byte_count", uint8(2)), nil, false},
		{"fc23 write over", fcAttrs(23, "read_address", u16(0), "read_quantity", u16(1), "write_address", u16(200), "write_quantity", u16(122), "byte_count", uint8(244)), nil, false},
		{"fc23 byte count disagrees", fcAttrs(23, "read_address", u16(0), "read_quantity", u16(1), "write_address", u16(200), "write_quantity", u16(2), "byte_count", uint8(2)), nil, false},
		{"fc23 reply", fcAttrs(23, "byte_count", uint8(4), "register_count", u16(2)), nil, false},
		{"fc8 diagnostics", fcAttrs(8, "sub_function", u16(1)), nil, true},
		{"fc43 device identification", fcAttrs(43, "mei_type", uint8(14)), nil, true},
		{"fc43 other MEI", fcAttrs(43, "mei_type", uint8(13)), nil, false},
		{"fc17 report server id", fcAttrs(17), nil, true},
		{"fc20 file record", fcAttrs(20), nil, false},
		{"fc24 fifo", fcAttrs(24), nil, false},
		{"unknown fc", fcAttrs(90), nil, false},
		{"no function code", map[string]any{"address": u16(1), "quantity": u16(1)}, nil, false},
	}
	for _, tc := range cases {
		spans, ok := AddressSpans(tc.attrs)
		if ok != tc.ok || !reflect.DeepEqual(spans, tc.spans) {
			t.Errorf("%s: AddressSpans = %v, %v; want %v, %v", tc.name, spans, ok, tc.spans, tc.ok)
		}
	}
}

// A request PDU whose length does not fit its function code's layout emits
// no data-access fields, so AddressSpans does not bound it.
func TestRequestFieldsRequireExactLayout(t *testing.T) {
	cases := []struct {
		name string
		fc   uint8
		pdu  []byte
	}{
		{"fc3 short", 3, []byte{0, 10, 0}},
		{"fc3 trailing byte", 3, []byte{0, 10, 0, 2, 0}},
		{"fc6 short", 6, []byte{0, 10}},
		{"fc16 no byte count", 16, []byte{0, 10, 0, 2}},
		{"fc16 byte count past PDU", 16, []byte{0, 10, 0, 2, 4, 0, 1}},
		{"fc16 data past byte count", 16, []byte{0, 10, 0, 1, 2, 0, 1, 0, 2}},
		{"fc22 short", 22, []byte{0, 4, 0, 0xF2, 0}},
		{"fc23 short", 23, []byte{0, 1, 0, 1, 0, 2, 0, 1}},
		{"fc23 byte count past PDU", 23, []byte{0, 1, 0, 1, 0, 2, 0, 1, 2, 0}},
	}
	for _, tc := range cases {
		attrs := map[string]any{"function_code": tc.fc}
		addRequestFields(tc.fc, tc.pdu, attrs)
		if len(attrs) != 1 {
			t.Errorf("%s: emitted %v", tc.name, attrs)
		}
		if spans, ok := AddressSpans(attrs); ok || spans != nil {
			t.Errorf("%s: AddressSpans = %v, %v", tc.name, spans, ok)
		}
	}
}
