// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func iecLoadEvent(id string) dpi.Event {
	return dpi.Event{Proto: "iec104", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{
		eventfields.KeyAPDUID: id, eventfields.KeyAPCIType: "I", eventfields.KeyTypeID: uint8(45), eventfields.KeyCA: uint16(1), eventfields.KeyCause: uint8(6), eventfields.KeyDirection: "request",
		eventfields.KeyOriginator: uint8(0), eventfields.KeyCOTNegative: false, eventfields.KeyCOTTest: false, eventfields.KeyObjectCount: uint32(1), eventfields.KeyObjectIndex: uint32(0), eventfields.KeyIOA: uint32(7), eventfields.KeySelect: false, eventfields.KeyValue: uint8(1), eventfields.KeyQualifier: uint8(0)}}
}

func TestIEC104WatchLoad(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 2404, Proto: 6}, time.Now())
	state.Connection.Store(&flow.Connection{Key: "iec-load"})
	// More than the rendezvous capacity forces persistence during collection,
	// not merely after Stop has disabled offers. 500 APDUs/s exceeds a normal
	// lab command watch; each APDU generates separate decoded and outcome offers.
	const count = 5000
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	started := time.Now()
	for i := range count {
		<-tick.C
		id := fmt.Sprintf("load/c/%d", i)
		a.watch.engine.RecordDPIEvents(state, nil, []dpi.Event{iecLoadEvent(id)})
		a.watch.offer(nil, []dpi.Event{{Proto: "iec104", Kind: "evidence.delivery", Timestamp: time.Now(), Attributes: map[string]any{eventfields.KeyAPDUID: id, "delivery": "delivered"}}})
	}
	if _, err := a.watch.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	counters, err := a.store.Counters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("IEC104: apdus=%d offers=%d retained=%d lost_batches=%d gaps=%v elapsed=%s", count, 2*count, ds.Records, counters.LostBatches, ds.Gaps, time.Since(started))
	if ds.Records != count || counters.LostBatches != 0 || len(ds.Gaps) != 0 {
		t.Fatal("normal paced watch lost certification inputs")
	}
	result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) == 0 {
		t.Fatalf("normal live watch not useful: %+v %v", result, err)
	}
	positives := uint64(0)
	for _, selection := range result.Suggestions {
		suggestion, err := a.store.GetSuggestion(ctx, selection.ID)
		if err != nil {
			t.Fatal(err)
		}
		if suggestion.Proof == nil || len(suggestion.Proof.ParentRefs) > 512 {
			t.Fatal("unbounded or absent proof")
		}
		positives += suggestion.Proof.Positive.Total
	}
	if positives != count {
		t.Fatalf("large relation lost positive references: %d", positives)
	}
	t.Logf("IEC104: certified_suggestions=%d positive_references=%d", len(result.Suggestions), positives)
}

func TestOutcomeQueueDropKeepsConcurrentConnectionsEligible(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	// Hold the worker until admission pressure has deterministically occurred.
	w := &evidenceWatch{store: a.store, engine: a.watch.engine, queue: make(chan evidenceBatch, 1), done: make(chan struct{})}
	watch, err := w.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	lease := w.active.Load()
	at := time.Now()
	var serial uint64
	for _, id := range []string{"first", "second"} {
		state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, at)
		state.Connection.Store(&flow.Connection{Key: id})
		ev := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: at, Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}
		parents, err := learn.Normalize(lease.dataset, state, []dpi.Event{ev}, &serial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Parents: parents}); err != nil {
			t.Fatal(err)
		}
	}
	w.queue <- evidenceBatch{}
	w.offer(nil, []dpi.Event{{Kind: "evidence.delivery", Timestamp: at}})
	<-w.queue
	worker, cancel := context.WithCancel(ctx)
	go w.run(worker)
	defer func() { cancel(); <-w.done }()
	if _, err := w.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.store.Counters(ctx)
	if err != nil || c.LostBatches != 1 {
		t.Fatal("outcome drop not counted", c, err)
	}
	result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 1 || len(result.Withheld) != 0 {
		t.Fatalf("outcome-only drop excluded concurrent parents: %+v %v", result, err)
	}
	if len(ds.Gaps) != 0 || len(ds.Losses) != 1 || ds.Losses[0].Code != "outcome_loss" {
		t.Fatal(ds)
	}
}

func TestPendingLossBoundAndNormalizedDedupe(t *testing.T) {
	lease := &watchLease{}
	at := time.Now()
	lease.drop(nil, []dpi.Event{{Timestamp: at}})
	lease.drop(nil, []dpi.Event{{Timestamp: at.Round(0).In(time.FixedZone("offset", 3600))}})
	if len(lease.losses) != 1 {
		t.Fatal("pending interval duplicated across time domains")
	}
	for i := range evidence.MaxLosses + 20 {
		state := flow.NewState(flow.Key{}, at)
		state.Connection.Store(&flow.Connection{Key: fmt.Sprint(i)})
		lease.drop(state, nil)
	}
	if len(lease.losses) != 1 || !lease.losses[evidence.CollectionLoss{Code: "collection_loss"}] {
		t.Fatal("unbounded pending identities")
	}
}

func TestEvidenceQueueCopyBudgetAndCreditRelease(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	w := &evidenceWatch{store: a.store, engine: a.watch.engine, queue: make(chan evidenceBatch, watchQueueBatches), done: make(chan struct{})}
	watch, err := w.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	lease := w.active.Load()
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
	state.Connection.Store(&flow.Connection{Key: "byte-budget"})
	ev := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}
	lease.queuedBytes.Store(watchQueueBytes)
	w.offer(state, []dpi.Event{ev})
	if len(w.queue) != 0 || lease.dropped != 1 || lease.queuedBytes.Load() != watchQueueBytes {
		t.Fatal("byte-budget rejection lost accounting")
	}
	lease.queuedBytes.Store(0)
	w.offer(state, []dpi.Event{ev})
	if len(w.queue) != 1 || lease.queuedBytes.Load() <= 0 {
		t.Fatal("queued copy not charged")
	}
	worker, cancel := context.WithCancel(ctx)
	go w.run(worker)
	defer func() { cancel(); <-w.done }()
	if _, err := w.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	if lease.queuedBytes.Load() != 0 {
		t.Fatal("dequeued copy retained byte credit")
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || ds.Records != 1 || len(ds.Losses) != 1 || ds.Losses[0].ConnectionID != "byte-budget" {
		t.Fatalf("copy budget lost scoped exclusion: %+v %v", ds, err)
	}
}
