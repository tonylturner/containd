// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	dpids "github.com/tonylturner/containd/pkg/dp/ids"
)

func TestCIPBuiltinDecodedEvent(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.IDS = config.DefaultIDSConfig()
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := dpids.New(snap.IDS)
	for _, tc := range []struct {
		service byte
		id      string
	}{{0x05, "IDS-CIP-001"}, {0x07, "IDS-CIP-002"}} {
		t.Run(tc.id, func(t *testing.T) {
			// A real EtherNet/IP SendRRData frame containing an unconnected CIP request.
			payload := make([]byte, 42)
			binary.LittleEndian.PutUint16(payload[0:2], 0x6f)
			binary.LittleEndian.PutUint16(payload[2:4], 18)
			binary.LittleEndian.PutUint16(payload[30:32], 2)
			binary.LittleEndian.PutUint16(payload[36:38], 0xb2)
			binary.LittleEndian.PutUint16(payload[38:40], 2)
			payload[40] = tc.service
			events, err := cip.NewDecoder().OnPacket(&flow.State{}, &dpi.ParsedPacket{Payload: payload, Proto: "tcp", DstPort: 44818})
			if err != nil || len(events) != 1 || events[0].Proto != "cip" {
				t.Fatalf("decode: %+v %v", events, err)
			}
			blob, err := json.Marshal(events[0])
			if err != nil {
				t.Fatal(err)
			}
			var wire dpi.Event
			if err := json.Unmarshal(blob, &wire); err != nil {
				t.Fatal(err)
			}
			for _, ev := range []dpi.Event{events[0], wire} {
				alerts := evaluator.Evaluate(ev)
				matched := false
				for _, alert := range alerts {
					if alert.Attributes["rule_id"] == tc.id {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("stock %s did not fire on decoded %+v; alerts=%+v", tc.id, ev, alerts)
				}
			}
		})
	}
}
