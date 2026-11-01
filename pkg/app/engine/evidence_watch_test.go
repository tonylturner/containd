// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
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
		if loss.ConnectionID != "dropped" && (loss.ConnectionID != "" || !loss.Start.IsZero() || !loss.End.IsZero() || loss.Scope != (evidence.LossScope{})) {
			t.Fatalf("retry lost connection or dataset-wide uncertainty: %+v", loss)
		}
	}
	counts, err := a.store.Counters(ctx)
	if err != nil || counts.LostBatches != 3 {
		t.Fatalf("retry lost counters: %+v %v", counts, err)
	}
}

func TestEvidenceWriterStallDrainsIntakeAndFencesStop(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	w := &evidenceWatch{
		store: a.store, engine: a.watch.engine,
		queue: make(chan evidenceBatch, watchQueueBatches), done: make(chan struct{}),
	}
	writer := newEvidenceWatchWriter(w, ctx)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var grouped atomic.Bool
	writer.ingest = func(ctx context.Context, req evidence.IngestRequest) (evidence.IngestResult, error) {
		once.Do(func() {
			close(entered)
			select {
			case <-resume:
			case <-ctx.Done():
			}
		})
		if len(req.Parents) > 1 {
			grouped.Store(true)
		}
		return a.store.Ingest(ctx, req)
	}
	go func() {
		defer close(w.done)
		w.runWithWriter(ctx, writer)
	}()
	defer func() { cancel(); <-w.done }()
	watch, err := w.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
	state.Connection.Store(&flow.Connection{Key: "writer-stall"})
	offer := func() {
		w.offer(state, []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{
			"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false,
		}}})
	}
	for range 128 {
		offer()
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("writer never started")
	}
	// Deliberately keep persistence stopped while more than the old count
	// bound arrives. No sleeps or scheduler-speed assumptions induce the stall.
	for range 1024 {
		offer()
	}
	lease := w.active.Load()
	barrier := make(chan error, 1)
	w.queue <- evidenceBatch{barrier: barrier}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for lease.queuedBytes.Load() != 0 || len(w.queue) != 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("persistence stalled intake")
		}
	}
	if size := writer.bytes.Load(); size <= 0 || size > watchWriteBytes {
		t.Fatalf("queued/in-progress writes not byte-bounded: %d", size)
	}
	select {
	case <-barrier:
		t.Fatal("barrier acknowledged before persistence")
	default:
	}
	close(resume)
	select {
	case err := <-barrier:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer never drained barrier")
	}
	if writer.bytes.Load() != 0 || !grouped.Load() {
		t.Fatal("group commit did not release its byte credit")
	}
	if _, err := w.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	ds, err := a.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || ds.Records != 1152 || len(ds.Gaps) != 0 {
		t.Fatalf("barrier lost parents: %+v %v", ds, err)
	}
	counters, err := a.store.Counters(ctx)
	if err != nil || counters.LostBatches != 0 {
		t.Fatalf("persistence stall became collection loss: %+v %v", counters, err)
	}
}

func TestEvidenceWriterRejectsImpossibleReservation(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	writer := newEvidenceWatchWriter(a.watch, ctx)
	finished := make(chan struct{})
	go func() {
		writer.submit(evidenceWrite{bytes: watchWriteBytes + 1})
		close(finished)
	}()
	defer func() { cancel(); <-finished }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("impossible byte reservation blocked intake")
	}
	if !errors.Is(a.watch.err(), sqlite.ErrBudget) || writer.bytes.Load() != 0 || len(writer.queue) != 0 {
		t.Fatal("oversized group did not fail closed without retaining credit")
	}
}
