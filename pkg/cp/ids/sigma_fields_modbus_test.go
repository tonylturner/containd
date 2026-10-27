// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// TestModbusDecoderKeysAreSigmaFields decodes one ADU of every Modbus layout
// in both directions and requires each emitted attribute to be a Sigma field,
// so a decoder key added without the allowlist fails here.
func TestModbusDecoderKeysAreSigmaFields(t *testing.T) {
	for _, tt := range []struct {
		name  string
		reply bool
		adu   string
		want  []string // keys this layout must emit
	}{
		{"read holding registers request", false, "000100000006010300000002", []string{"address", "quantity"}},
		{"write single coil request", false, "00010000000601050003ff00", []string{"address", "value"}},
		{"write multiple registers request", false, "00010000000b0110000a000204000a000b", []string{"address", "quantity", "byte_count"}},
		{"mask write register request", false, "0001000000080116000400f20025", []string{"address", "and_mask", "or_mask"}},
		{"read/write multiple registers request", false, "000100000011011700030006000e00030600ff00ff00ff",
			[]string{"read_address", "read_quantity", "write_address", "write_quantity", "byte_count"}},
		{"diagnostics request", false, "000100000006010800000000", []string{"sub_function", "sub_function_name"}},
		{"read device identification request", false, "000100000005012b0e0100", []string{"mei_type", "mei_type_name"}},
		{"read holding registers reply", true, "000100000007010304000b000c", []string{"byte_count", "register_count"}},
		{"read coils reply", true, "0001000000040101010d", []string{"byte_count"}},
		{"write single register reply", true, "000100000006010600010003", []string{"address", "value"}},
		{"write multiple coils reply", true, "000100000006010f0013000a", []string{"address", "quantity"}},
		{"exception reply", true, "000100000003018302", []string{"exception_code", "exception_description"}},
		{"unframeable bytes", false, "000100000001", []string{"error"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ev := decodeModbusADU(t, tt.adu, tt.reply)
			for _, key := range tt.want {
				if _, ok := ev.Attributes[key]; !ok {
					t.Fatalf("decoder event lacks %q: %v", key, ev.Attributes)
				}
			}
			for key := range ev.Attributes {
				if got := normalizeField(key); got != "attr."+key {
					t.Errorf("decoder key %q normalizes to %q, want %q", key, got, "attr."+key)
				}
			}
		})
	}
}

func decodeModbusADU(t *testing.T, aduHex string, reply bool) dpi.Event {
	t.Helper()
	adu, err := hex.DecodeString(aduHex)
	if err != nil {
		t.Fatal(err)
	}
	key := flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 49152, DstPort: 502, Proto: 6}
	if reply {
		key = flow.Key{SrcIP: key.DstIP, DstIP: key.SrcIP, SrcPort: 502, DstPort: 49152, Proto: 6, Dir: flow.DirReverse}
	}
	events, err := modbus.NewDecoder().OnPacket(flow.NewState(key, time.Unix(1, 0)), &dpi.ParsedPacket{
		Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort, Payload: adu,
	})
	if len(events) != 1 {
		t.Fatalf("decode %s: %d events, error %v", aduHex, len(events), err)
	}
	return events[0]
}
