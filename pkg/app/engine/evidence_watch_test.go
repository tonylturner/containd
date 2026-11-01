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

func TestDroppedBindingCannotCertifyConnection(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
	state.Connection.Store(&flow.Connection{Key: "mismatched-connection"})
	a.watch.offer(state, []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{
		"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false,
	}}})
	// Oversized decoded metadata causes a real collection rejection of the
	// confirmed binding, not a synthetic increment of the lost-batch counter.
	a.watch.offer(state, []dpi.Event{{Proto: eventfields.ProtoIdentify, Kind: eventfields.KindIdentification, Timestamp: time.Now(), Attributes: map[string]any{
		eventfields.KeyProtocol: "iec104", eventfields.KeyIdentificationState: "confirmed",
		eventfields.KeyBinding: "observation", eventfields.KeyMismatch: true, "oversized": make([]byte, 1<<21),
	}}})
	if _, err := a.watch.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || ds.Records != 1 || len(ds.Gaps) == 0 {
		t.Fatalf("fixture did not retain parent and record binding loss: %+v %v", ds, err)
	}
	result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Suggestions) != 0 {
		t.Fatalf("lost binding produced actionable suggestions: %+v; gaps=%v", result, ds.Gaps)
	}
	if len(ds.Losses) != 1 || ds.Losses[0].ConnectionID != "mismatched-connection" || result.Withheld[evidence.WithheldCollectionLoss] != 1 {
		t.Fatalf("drop identity or withheld reason lost: %+v %+v", ds, result)
	}
}

func TestEvidenceLossFlushPreservesIdentityOnFailure(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.store.StartWatch(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	lease := &watchLease{dataset: evidence.Dataset{ID: watch.DatasetID}}
	state := flow.NewState(flow.Key{}, time.Now())
	state.Connection.Store(&flow.Connection{Key: "dropped"})
	for range 2 {
		lease.drop(state, nil)
	}
	at := time.Now().UTC()
	lease.drop(nil, []dpi.Event{{Timestamp: at}})
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := a.watch.flushLosses(cancelled, lease); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	if err := a.watch.flushLosses(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.StopWatch(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || len(ds.Losses) != 2 {
		t.Fatalf("retry lost localization: %+v %v", ds, err)
	}
	for _, loss := range ds.Losses {
		if loss.ConnectionID != "dropped" && (loss.ConnectionID != "" || !loss.Start.Equal(at) || !loss.End.Equal(at)) {
			t.Fatalf("retry lost connection or time-only scope: %+v", loss)
		}
	}
	counts, err := a.store.Counters(ctx)
	if err != nil || counts.LostBatches != 3 {
		t.Fatalf("retry lost counters: %+v %v", counts, err)
	}
}
