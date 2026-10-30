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
	lease := a.watch.active.Load()
	lease.dropped.Add(3)
	join := newEvidenceJoin(a.watch, ctx)
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
}
