// SPDX-License-Identifier: Apache-2.0
package anomaly

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
)

func TestDecodedCIPProgramService(t *testing.T) {
	for _, tc := range []struct {
		service byte
		name    string
	}{{0x06, "Start"}, {0x07, "Stop"}} {
		t.Run(tc.name, func(t *testing.T) {
			// EtherNet/IP SendRRData: null address and unconnected CIP
			// data item, followed by the service and an empty EPATH.
			payload := make([]byte, 24+18)
			binary.LittleEndian.PutUint16(payload[0:2], 0x6f)
			binary.LittleEndian.PutUint16(payload[2:4], 18)
			binary.LittleEndian.PutUint16(payload[30:32], 2)
			binary.LittleEndian.PutUint16(payload[36:38], 0xb2)
			binary.LittleEndian.PutUint16(payload[38:40], 2)
			payload[40] = tc.service
			ev := decodeOne(t, cip.NewDecoder(), 44818, payload)
			for _, event := range []dpi.Event{ev, jsonRoundTrip(t, ev)} {
				want := fmt.Sprintf("CIP Program %s command detected (service 0x%02X)", tc.name, tc.service)
				if got := New().Check("10.0.0.1", "10.0.0.2", event); !hasMessage(got, want) {
					t.Fatalf("service_code %v not detected: %+v", event.Attributes["service_code"], got)
				}
			}
		})
	}
}

func TestCIPServiceCodeStrictness(t *testing.T) {
	for _, value := range []any{nil, 7.5, "7", -1, 263, false} {
		ev := dpi.Event{Proto: "cip", Kind: "request", Attributes: map[string]any{"service_code": value}}
		if got := New().checkCIP("10.0.0.1", "10.0.0.2", ev); len(got) != 0 {
			t.Fatalf("invalid service_code %v created anomaly: %+v", value, got)
		}
	}
	for _, value := range []any{uint8(7), int(7), float64(7)} {
		ev := dpi.Event{Proto: "cip", Kind: "request", Attributes: map[string]any{"service_code": value}}
		got := New().checkCIP("10.0.0.1", "10.0.0.2", ev)
		if len(got) != 1 || got[0].Attributes["service_code"] != uint8(7) {
			t.Fatalf("valid service_code %v not normalized: %+v", value, got)
		}
	}
}
