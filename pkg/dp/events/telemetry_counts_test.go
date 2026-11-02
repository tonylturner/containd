// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/common/telemetry"
)

func TestStoreTelemetryCountsPerOriginAndClass(t *testing.T) {
	store := NewStore(2)
	emptyCounts := store.TelemetryCounts()
	if len(emptyCounts) != 2 || emptyCounts[0].Origin != telemetry.OriginReal || emptyCounts[1].Origin != telemetry.OriginDemo {
		t.Fatalf("empty-store origins = %+v, want real and demo", emptyCounts)
	}
	for _, counts := range emptyCounts {
		if counts.Total != 0 {
			t.Errorf("empty-store %s total = %d, want 0", counts.Origin, counts.Total)
		}
	}
	store.Append(Event{Proto: "ids", Kind: "alert"})
	store.Append(Event{Origin: telemetry.OriginReal, Proto: "modbus", Kind: "request", Attributes: map[string]any{"is_write": true}})
	store.Append(Event{Origin: telemetry.OriginDemo, Kind: "service.av.detected"})
	store.Append(Event{Origin: telemetry.OriginDemo, Kind: "service.av.block_flow"})
	store.Append(Event{Origin: telemetry.Origin("fixture"), Kind: "other"})

	got := make(map[telemetry.Origin]telemetry.EventCounts)
	for _, counts := range store.TelemetryCounts() {
		got[counts.Origin] = counts
	}
	if len(got) != 3 {
		t.Fatalf("origins = %v, want real, demo, fixture", got)
	}
	real := got[telemetry.OriginReal]
	if real.Total != 2 || real.Classes[telemetry.ClassIDSAlert] != 1 || real.Classes[telemetry.ClassModbusWrite] != 1 {
		t.Fatalf("real counts = %+v", real)
	}
	demo := got[telemetry.OriginDemo]
	if demo.Total != 2 || demo.Classes[telemetry.ClassAVDetection] != 1 || demo.Classes[telemetry.ClassAVBlock] != 1 {
		t.Fatalf("demo counts = %+v", demo)
	}
	if fixture := got[telemetry.Origin("fixture")]; fixture.Total != 1 {
		t.Fatalf("fixture counts = %+v", fixture)
	}
	for origin, counts := range got {
		if len(counts.Classes) != 4 {
			t.Errorf("%s class counters = %v, want all four classes", origin, counts.Classes)
		}
	}
}

func TestStoreTelemetryCountsConcurrentAppends(t *testing.T) {
	const workers, perWorker = 12, 250
	store := NewStore(1)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			origin := telemetry.OriginReal
			if worker%2 == 1 {
				origin = telemetry.OriginDemo
			}
			for i := 0; i < perWorker; i++ {
				store.Append(Event{
					Origin: origin,
					Proto:  "modbus",
					Kind:   "request",
					Attributes: map[string]any{
						"is_write": i%2 == 0,
					},
				})
			}
		}(worker)
	}
	wg.Wait()

	wantTotal := uint64(workers * perWorker / 2)
	for _, counts := range store.TelemetryCounts() {
		if counts.Origin != telemetry.OriginReal && counts.Origin != telemetry.OriginDemo {
			continue
		}
		if counts.Total != wantTotal {
			t.Errorf("%s total = %d, want %d", counts.Origin, counts.Total, wantTotal)
		}
		if counts.Classes[telemetry.ClassModbusWrite] != wantTotal/2 {
			t.Errorf("%s modbus writes = %d, want %d", counts.Origin, counts.Classes[telemetry.ClassModbusWrite], wantTotal/2)
		}
	}
}

func TestFlowSummaryCarriesEventOrigin(t *testing.T) {
	store := NewStore(8)
	store.Append(Event{FlowID: "demo-flow", Origin: telemetry.OriginDemo})
	store.Append(Event{FlowID: "real-flow"})
	store.Append(Event{FlowID: "mixed-flow", Origin: telemetry.OriginDemo})
	store.Append(Event{FlowID: "mixed-flow"})

	got := make(map[string]FlowSummary)
	for _, summary := range store.Flows(0) {
		got[summary.FlowID] = summary
	}
	if got["demo-flow"].Origin != telemetry.OriginDemo {
		t.Errorf("demo flow origin = %q", got["demo-flow"].Origin)
	}
	if got["real-flow"].Origin != "" {
		t.Errorf("real flow origin = %q, want empty real default", got["real-flow"].Origin)
	}
	if got["mixed-flow"].Origin != "" {
		t.Errorf("mixed flow origin = %q, want real when any event is real", got["mixed-flow"].Origin)
	}
}
