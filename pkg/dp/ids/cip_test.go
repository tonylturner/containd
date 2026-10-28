// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestEvaluatorSendUnitDataCPFItems(t *testing.T) {
	// Interface handle, timeout, two CPF items: connected address and
	// connected data (including its sequence count).
	payload := []byte{
		0, 0, 0, 0, 0, 0, 2, 0,
		0xa1, 0, 4, 0, 1, 0, 0, 0,
		0xb1, 0, 4, 0, 1, 0, 0x4c, 0,
	}
	frame := make([]byte, 24)
	binary.LittleEndian.PutUint16(frame[0:2], 0x0070) // SendUnitData
	binary.LittleEndian.PutUint16(frame[2:4], uint16(len(payload)))
	binary.LittleEndian.PutUint32(frame[4:8], 1)
	frame = append(frame, payload...)
	state := flow.NewState(flow.Key{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 12345, DstPort: 44818, Proto: 6,
	}, time.Now())
	events, err := cip.NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: frame})
	if err != nil || len(events) != 1 {
		t.Fatalf("decode: events=%v err=%v", events, err)
	}
	event := events[0]
	if event.Attributes["enip_command"] != "SendUnitData" {
		t.Fatalf("unexpected command: %v", event.Attributes)
	}
	for _, tc := range []struct {
		op, value string
		match     bool
	}{
		{"contains", "0x00b1", true},
		{"contains", "0x00b2", false},
		{"equals", "0x00a1,0x00b1", true},
		{"equals", "0x00b1", false},
		{"regex", "^0x00a1,0x00b1$", true},
	} {
		t.Run(tc.op+"/"+tc.value, func(t *testing.T) {
			evaluator := New(rules.IDSConfig{
				Enabled: true,
				Rules: []rules.IDSRule{{
					ID: "connected-data", Proto: "cip",
					When: rules.IDSCondition{Field: "attr.cpf_item_types", Op: tc.op, Value: tc.value},
				}},
			})
			alerts := evaluator.Evaluate(event)
			if len(alerts) != 0 && (len(alerts) != 1 || alerts[0].Proto != "ids" || alerts[0].Kind != "alert") {
				t.Fatalf("unexpected alerts: %v", alerts)
			}
			if (len(alerts) == 1) != tc.match {
				t.Fatalf("%s %q: got %d alerts, match=%t", tc.op, tc.value, len(alerts), tc.match)
			}
		})
	}
}
