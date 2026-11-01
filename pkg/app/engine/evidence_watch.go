// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

const decoderVersion = "ics-1"

// Absorb bounded SQLite flush/scheduler bursts without raising the previous
// 64 MiB decoded-copy budget. Packet verdicts never wait for the worker.
const watchQueueBatches = 256
const watchQueueBytes = 64 << 20

type watchLease struct {
	dataset     evidence.Dataset
	watch       evidence.Watch
	lossMu      sync.Mutex
	dropped     uint64
	losses      map[evidence.CollectionLoss]bool
	queuedBytes atomic.Int64
	inflight    atomic.Int64
	changed     atomic.Bool
	token       engine.InspectionToken
}
type evidenceBatch struct {
	bytes       int
	lease       *watchLease
	parents     []evidence.Observation
	outcomes    []dpi.Event
	barrier     chan error
	collectedAt time.Time
	state       *flow.State
	events      []dpi.Event
}
type evidenceWatch struct {
	mu         sync.Mutex
	active     atomic.Pointer[watchLease]
	stopping   *watchLease // protected by mu; retained until a successful seal
	queue      chan evidenceBatch
	done       chan struct{}
	maintained chan struct{}
	store      *sqlite.Store
	engine     *engine.Engine
	serial     atomic.Uint64
	failure    atomic.Pointer[error]
}

func evidenceMetadata(e *engine.Engine) (evidence.Dataset, error) {
	return evidenceMetadataFrom(e.InspectionSnapshot())
}
func evidenceMetadataFrom(inputs engine.InspectionSnapshot) (evidence.Dataset, error) {
	var enabled []string
	for _, d := range inputs.Decoders {
		if stream, ok := d.(dpi.StreamDecoder); ok {
			enabled = append(enabled, stream.Protocol())
		} else {
			enabled = append(enabled, fmt.Sprintf("%T", d))
		}
	}
	sort.Strings(enabled)
	p, err := evidence.Digest(struct {
		Parsing map[string]string
		Enabled []string
	}{inputs.Parsing, enabled})
	if err != nil {
		return evidence.Dataset{}, err
	}
	s, err := evidence.Digest(inputs.Rules)
	if err != nil {
		return evidence.Dataset{}, err
	}
	return evidence.Dataset{SchemaVersion: evidence.SchemaVersion, DecoderVersion: decoderVersion, ProfileFingerprint: p, SnapshotFingerprint: s}, nil
}
func newEvidenceWatch(ctx context.Context, store *sqlite.Store, e *engine.Engine) *evidenceWatch {
	w := &evidenceWatch{queue: make(chan evidenceBatch, watchQueueBatches), done: make(chan struct{}), maintained: make(chan struct{}), store: store, engine: e}
	go w.run(ctx)
	go w.maintain(ctx)
	return w
}
func (w *evidenceWatch) fail(err error) {
	if err != nil {
		w.failure.Store(&err)
	}
}
func (w *evidenceWatch) err() error {
	if err := w.failure.Load(); err != nil {
		return *err
	}
	return nil
}
func (w *evidenceWatch) offer(state *flow.State, events []dpi.Event) {
	lease := w.active.Load()
	if lease == nil || lease.changed.Load() {
		return
	}
	collectedAt := w.store.Clock()
	if !collectedAt.Before(lease.watch.Deadline) {
		return
	}
	lease.inflight.Add(1)
	defer lease.inflight.Add(-1)
	if lease != w.active.Load() {
		return
	}

	if w.engine.InspectionToken() != lease.token {
		lease.changed.Store(true)
		return
	}

	owned, size, ok := ownEvidenceEvents(events)
	if !ok {
		lease.drop(state, events)
		return
	}
	if lease.queuedBytes.Add(int64(size)) > watchQueueBytes {
		lease.queuedBytes.Add(-int64(size))
		lease.drop(state, events)
		return
	}
	var snapshot *flow.State
	if state != nil {
		copy := *state
		copy.Key.SrcIP = append([]byte(nil), state.Key.SrcIP...)
		copy.Key.DstIP = append([]byte(nil), state.Key.DstIP...)
		copy.Tags = nil
		copy.Connection = flow.ConnectionSlot{}
		copy.Connection.Store(state.Connection.Load())
		snapshot = &copy
	}
	select {
	case w.queue <- evidenceBatch{lease: lease, state: snapshot, events: owned, collectedAt: collectedAt, bytes: size}:
	default:
		lease.queuedBytes.Add(-int64(size))
		lease.drop(state, events)
	}
}
func (w *evidenceWatch) run(ctx context.Context) {
	defer close(w.done)
	join := newEvidenceJoin(w, ctx)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-w.queue:
			if batch.lease != nil {
				batch.lease.queuedBytes.Add(-int64(batch.bytes))
			}
			if batch.barrier != nil {
				join.flushAll()
				batch.barrier <- w.err()
			} else {
				if batch.state != nil {
					serial := w.serial.Add(uint64(len(batch.events))) - uint64(len(batch.events))
					parents, err := learn.Normalize(batch.lease.dataset, batch.state, batch.events, &serial)
					if err != nil {
						batch.lease.drop(batch.state, batch.events)
						continue
					}
					batch.parents = parents
					data, err := json.Marshal(parents)
					if err != nil || len(parents) > 128 || len(data) > (1<<20)-4096 {
						batch.lease.drop(batch.state, batch.events)
						continue
					}
				}
				for _, ev := range batch.events {
					if ev.Kind == "ics.decision" || ev.Kind == "ics.verdict" || ev.Kind == "evidence.delivery" {
						batch.outcomes = append(batch.outcomes, ev)
					}
				}
				join.accept(batch)
			}
		case <-ticker.C:
			join.expire(time.Now())
			join.flushWrites()
			if lease := w.active.Load(); lease != nil {
				w.fail(w.flushLosses(ctx, lease))
			}
		}
	}
}
func (w *evidenceWatch) maintain(ctx context.Context) {
	defer close(w.maintained)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.maintainWatch(ctx)
			w.mu.Lock()
			if w.err() == nil {
				w.fail(w.store.Maintain(ctx))
			}
			w.mu.Unlock()
		}
	}
}

// Retry detached automatic stops as well as checking active watch boundaries.
func (w *evidenceWatch) maintainWatch(ctx context.Context) {
	w.mu.Lock()
	lease := w.active.Load()
	detached := lease == nil
	if detached {
		lease = w.stopping
	}
	w.mu.Unlock()
	if lease == nil {
		return
	}
	if !detached && w.engine.InspectionToken() != lease.token {
		lease.changed.Store(true)
	}
	if detached || lease.changed.Load() || !w.store.Clock().Before(lease.watch.Deadline) {
		_, err := w.stop(ctx, lease.watch.ID)
		w.fail(err)
	}
}

func (w *evidenceWatch) start(ctx context.Context, req evidence.StartWatchRequest) (evidence.Watch, error) {
	if lease := w.active.Load(); lease != nil && !w.store.Clock().Before(lease.watch.Deadline) {
		if _, err := w.stop(ctx, lease.watch.ID); err != nil {
			return evidence.Watch{}, err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping != nil {
		return evidence.Watch{}, sqlite.ErrConflict
	}
	if w.err() != nil {
		if w.active.Load() != nil {
			return evidence.Watch{}, sqlite.ErrConflict
		}
		if err := w.store.Maintain(ctx); err != nil {
			return evidence.Watch{}, err
		}
		w.failure.Store(nil)
	}
	watch, err := w.store.StartWatch(ctx, req)
	if err != nil {
		return watch, err
	}
	// Retain cleanup authority before any subsequent fallible initialization.
	lease := &watchLease{dataset: evidence.Dataset{ID: watch.DatasetID}, watch: watch}
	w.stopping = lease
	defer func() {
		if w.stopping == lease {
			lease.lossMu.Lock()
			lease.addLossLocked(evidence.CollectionLoss{Code: "watch_storage_loss"})
			lease.lossMu.Unlock()
		}
	}()
	ds, err := w.store.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		w.fail(err)
		return watch, err
	}
	inputs := w.engine.InspectionSnapshot()
	metadata, err := evidenceMetadataFrom(inputs)
	if err != nil {
		w.fail(err)
		return watch, err
	}
	lease.dataset, lease.token = ds, inputs.Token
	if metadata.ProfileFingerprint != ds.ProfileFingerprint || metadata.SnapshotFingerprint != ds.SnapshotFingerprint {
		lease.changed.Store(true)
	}
	w.active.Store(lease)
	w.engine.SetLearnLossHook(func(loss evidence.CollectionLoss) {
		lease.lossMu.Lock()
		lease.addLossLocked(loss)
		lease.lossMu.Unlock()
	})
	w.engine.SetLearnWatchHook(w.offer)
	w.stopping = nil
	return watch, nil
}
func (w *evidenceWatch) stop(ctx context.Context, id string) (out evidence.Watch, outErr error) {
	disabled := false
	defer func() {
		if disabled && outErr != nil {
			w.fail(outErr)
		}
	}()
	w.mu.Lock()
	defer w.mu.Unlock()
	lease := w.active.Load()
	if lease == nil {
		lease = w.stopping
	}
	watch, err := w.store.GetWatch(ctx, id)
	if err != nil {
		return watch, err
	}
	if lease == nil || lease.dataset.ID != watch.DatasetID {
		if watch.StoppedAt != nil {
			return watch, nil
		}
		if _, err := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: watch.DatasetID, Losses: []evidence.CollectionLoss{{Code: "watch_storage_loss"}}}); err != nil {
			return watch, err
		}
		return w.store.StopWatch(ctx, id)
	}
	if err := ctx.Err(); err != nil {
		return watch, err
	}
	w.stopping = lease
	w.engine.SetLearnLossHook(nil)
	w.active.Store(nil)
	w.engine.SetLearnWatchHook(nil)
	disabled = true
	control, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	ctx = control
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for lease.inflight.Load() != 0 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return watch, ctx.Err()
		}
	}
	barrier := make(chan error, 1)
	select {
	case w.queue <- evidenceBatch{barrier: barrier}:
	case <-w.done:
		return watch, context.Canceled
	case <-ctx.Done():
		return watch, ctx.Err()
	}
	select {
	case <-w.done:
		return watch, context.Canceled
	case err := <-barrier:
		if err != nil {
			// Persist the loss and seal even after an earlier ingestion error.
			// A healthy cleanup write must remain possible.
			// A failed write may itself contain loss metadata. Wall-clock
			// lease bounds cannot localize missing capture-time authority.
			if _, writeErr := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Gaps: []string{"watch_storage_loss"}}); writeErr != nil {
				return watch, writeErr
			}
		}
	case <-ctx.Done():
		return watch, ctx.Err()
	}
	if err := w.flushLosses(ctx, lease); err != nil {
		return watch, err
	}
	if lease.changed.Load() {
		out, outErr = w.store.StopWatchReason(ctx, id, "policy_changed")
	} else {
		out, outErr = w.store.StopWatch(ctx, id)
	}
	if outErr == nil {
		w.stopping = nil
		w.failure.Store(nil)
	}
	return out, outErr
}

// Rejection must retain identity before decoded metadata is discarded. This
// small critical section owns only identity/time metadata, never packet data.
func (lease *watchLease) addLossLocked(loss evidence.CollectionLoss) {
	if lease.losses == nil {
		lease.losses = map[evidence.CollectionLoss]bool{}
	}
	global := evidence.CollectionLoss{Code: "collection_loss"}
	if lease.losses[global] {
		return
	}
	loss = loss.Normalized()
	if lease.losses[loss] {
		return
	}
	if len(lease.losses) >= evidence.MaxLosses {
		lease.losses = map[evidence.CollectionLoss]bool{global: true}
		return
	}
	lease.losses[loss] = true
}
func (lease *watchLease) drop(state *flow.State, events []dpi.Event) {
	lease.lossMu.Lock()
	defer lease.lossMu.Unlock()
	lease.dropped++
	if state == nil && len(events) > 0 {
		outcomes := true
		for _, ev := range events {
			outcomes = outcomes && (ev.Kind == "ics.decision" || ev.Kind == "ics.verdict" || ev.Kind == "evidence.delivery")
		}
		if outcomes {
			lease.addLossLocked(evidence.CollectionLoss{Code: "outcome_loss"})
			return
		}
	}
	if len(events) == 0 {
		lease.addLossLocked(droppedEventLoss(state, dpi.Event{}))
	}
	for _, event := range events {
		lease.addLossLocked(droppedEventLoss(state, event))
	}
}

func droppedEventLoss(state *flow.State, event dpi.Event) evidence.CollectionLoss {
	loss := evidence.CollectionLoss{Code: "watch_collection_loss", ConnectionID: learn.EvidenceConnectionID(state, event)}
	return loss.Normalized()
}

func (w *evidenceWatch) flushLosses(ctx context.Context, lease *watchLease) error {
	lease.lossMu.Lock()
	losses, lost := lease.losses, lease.dropped
	lease.losses, lease.dropped = nil, 0
	lease.lossMu.Unlock()
	// 128 maximum-sized identities fit comfortably inside the ingest byte bound.
	for len(losses) > 0 {
		batch := make([]evidence.CollectionLoss, 0, 128)
		for loss := range losses {
			batch = append(batch, loss)
			if len(batch) == 128 {
				break
			}
		}
		_, err := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, LostBatches: lost, Losses: batch})
		if err != nil {
			lease.lossMu.Lock()
			for pending := range losses {
				lease.addLossLocked(pending)
			}
			lease.dropped += lost
			lease.lossMu.Unlock()
			return err
		}
		for _, loss := range batch {
			delete(losses, loss)
		}
		lost = 0
	}
	return nil
}
