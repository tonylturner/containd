// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestEvidenceOutcomeJoinNeverFabricatesDelivery(t *testing.T) {
	for _, tc := range []struct {
		kind, outcome, delivery string
	}{
		{eventfields.KindDecision, "would_allow", "unknown"},
		{eventfields.KindVerdict, "would_drop", "unknown"},
		{eventfields.KindVerdict, "dropped", "blocked"},
		{"evidence.delivery", "delivered", "delivered"},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			a := newEvidenceTestAPI(t)
			ctx := context.Background()
			watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			id := "session/c/0"
			attrs := map[string]any{eventfields.KeyAPDUID: id, eventfields.KeyDecision: tc.outcome, eventfields.KeyOutcome: tc.outcome, "delivery": tc.outcome, eventfields.KeyMode: "monitor"}
			// Outcomes may precede decode; neither order implies forwarding.
			a.watch.offer(nil, []dpi.Event{{Proto: "iec104", Kind: tc.kind, Attributes: attrs}})
			state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 2404, Proto: 6}, time.Now())
			a.watch.engine.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "iec104", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{
				eventfields.KeyAPDUID: id, eventfields.KeyAPCIType: "I", eventfields.KeyTypeID: uint8(45), eventfields.KeyCA: uint16(1), eventfields.KeyCause: uint8(6),
				eventfields.KeyOriginator: uint8(0), eventfields.KeyCOTNegative: false, eventfields.KeyCOTTest: false, eventfields.KeyDirection: "request",
				eventfields.KeyObjectCount: uint32(1), eventfields.KeyObjectIndex: uint32(0), eventfields.KeyIOA: uint32(7), eventfields.KeySelect: false, eventfields.KeyValue: uint8(1), eventfields.KeyQualifier: uint8(0),
			}}})
			if _, err := a.watch.stop(ctx, watch.ID); err != nil {
				t.Fatal(err)
			}
			page, err := a.store.ListObservations(ctx, watch.DatasetID, evidence.PageRequest{})
			if err != nil || len(page.Items) != 1 || page.Items[0].Outcome.Delivery != tc.delivery {
				t.Fatalf("decision became delivery: %+v %v", page, err)
			}
			if tc.kind == eventfields.KindDecision && len(page.Items[0].Outcome.Decisions) != 1 {
				t.Fatal("shadow decision lost")
			}
		})
	}
}

func TestEvidenceQueueLossAndPendingBounds(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
	a.watch.engine.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}})
	lease := a.watch.active.Load()
	for range 3 {
		lease.drop(nil, nil)
	}
	join := newEvidenceJoin(a.watch, newEvidenceWatchWriter(a.watch, ctx))
	for i := range joinRecords + 1 {
		join.entry(string(rune(i+1)), lease)
	}
	if len(join.entries) != joinRecords {
		t.Fatal("unbounded outcome rendezvous")
	}
	join.expire(time.Now().Add(joinTTL))
	if len(join.entries) != 0 {
		t.Fatal("pending outcome TTL ignored")
	}
	if _, err := a.watch.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	dataset, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || len(dataset.Gaps) != 1 {
		t.Fatal("queue loss hidden", err)
	}
	counts, err := a.store.Counters(ctx)
	if err != nil || counts.LostBatches != 3 {
		t.Fatalf("loss counters: %+v %v", counts, err)
	}
	result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: watch.DatasetID})
	if err != nil || len(result.Suggestions) != 0 || result.Withheld[evidence.WithheldCollectionLoss] != 1 {
		t.Fatalf("unlocalized queue loss did not exclude retained parent: %+v %v", result, err)
	}

}

func TestEvidenceAutomaticDeadlineDrainsPendingParents(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{DurationSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 2404, Proto: 6}, time.Now())
	a.watch.engine.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "iec104", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{
		eventfields.KeyAPDUID: "deadline/c/0", eventfields.KeyAPCIType: "I", eventfields.KeyTypeID: uint8(45), eventfields.KeyCA: uint16(1), eventfields.KeyCause: uint8(6), eventfields.KeyDirection: "request",
		eventfields.KeyOriginator: uint8(0), eventfields.KeyCOTNegative: false, eventfields.KeyCOTTest: false, eventfields.KeyObjectCount: uint32(1), eventfields.KeyObjectIndex: uint32(0), eventfields.KeyIOA: uint32(7), eventfields.KeySelect: false, eventfields.KeyValue: uint8(1), eventfields.KeyQualifier: uint8(0),
	}}})
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatal("watch never stopped")
		case <-ticker.C:
			stopped, err := a.store.GetWatch(ctx, watch.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stopped.StoppedAt == nil {
				continue
			}
			ds, err := a.store.GetDataset(ctx, watch.DatasetID)
			if err != nil || ds.Records != 1 || len(ds.Gaps) != 0 {
				counts, _ := a.store.Counters(ctx)
				t.Fatalf("deadline lost pending parent: %+v %v counters=%+v collector=%v", ds, err, counts, a.watch.err())
			}
			page, err := a.store.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			if err != nil || len(page.Items) != 1 || page.Items[0].Outcome.Delivery != "unknown" {
				t.Fatalf("pending join not drained: %+v %v", page, err)
			}
			if _, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID}); err != nil {
				t.Fatal("deadline dataset cannot generate", err)
			}
			return
		}
	}
}
