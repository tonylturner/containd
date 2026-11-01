// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

type rawProbe struct{ calls *atomic.Int64 }

func (p rawProbe) MarshalJSON() ([]byte, error) { p.calls.Add(1); return []byte(`"raw"`), nil }
func TestEvidenceOfferDoesNotSerializeRawEvents(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), DstPort: 502, Proto: 6}, time.Now())
	a.watch.offer(state, []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"raw_hex": rawProbe{&calls}, "function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}})
	if calls.Load() != 0 {
		t.Fatal("verdict path JSON-serialized raw events")
	}
	if _, err := a.watch.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkEvidenceHook(b *testing.B) {
	for _, active := range []bool{false, true} {
		name := "inactive"
		if active {
			name = "active"
		}
		b.Run(name, func(b *testing.B) {
			a := newEvidenceTestAPI(b)
			// Snapshot size must not multiply per-event hook work.
			snapshot := rules.Snapshot{Version: "benchmark"}
			for i := range 512 {
				snapshot.Firewall = append(snapshot.Firewall, rules.Entry{ID: string(rune(i + 1)), Sources: []string{"192.0.2.1/32"}, Action: rules.ActionAllow})
			}
			a.watch.engine.LoadRules(snapshot)
			if active {
				if _, err := a.watch.start(context.Background(), evidence.StartWatchRequest{}); err != nil {
					b.Fatal(err)
				}
			}
			state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
			events := []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				a.watch.engine.RecordDPIEvents(state, nil, events)
			}
			b.StopTimer()
		})
	}
}

func TestEvidenceEventCopyOwnsNestedValuesAndBoundsCycles(t *testing.T) {
	value := uint16(7)
	attrs := map[string]any{"nested": []any{&value, map[string]any{"points": []uint16{1, 2}}}}
	owned, size, ok := ownEvidenceEvents([]dpi.Event{{Attributes: attrs}})
	if !ok || size <= 0 {
		t.Fatal("valid decoded fields rejected")
	}
	value = 9
	attrs["nested"].([]any)[1].(map[string]any)["points"].([]uint16)[0] = 99
	got := owned[0].Attributes["nested"].([]any)
	if *got[0].(*uint16) != 7 || got[1].(map[string]any)["points"].([]uint16)[0] != 1 {
		t.Fatal("queued event aliases mutable decoder fields")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, _, ok := ownEvidenceEvents([]dpi.Event{{Attributes: cycle}}); ok {
		t.Fatal("cyclic input bypassed copy bounds")
	}
	if _, _, ok := ownEvidenceEvents([]dpi.Event{{Attributes: map[string]any{"large": make([]byte, 1<<21)}}}); ok {
		t.Fatal("oversized input bypassed copy bounds")
	}
}
