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

type watchLease struct {
	dataset  evidence.Dataset
	watch    evidence.Watch
	dropped  atomic.Uint64
	inflight atomic.Int64
	changed  atomic.Bool
	token    engine.InspectionToken
}
type evidenceBatch struct {
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
	w := &evidenceWatch{queue: make(chan evidenceBatch, 64), done: make(chan struct{}), maintained: make(chan struct{}), store: store, engine: e}
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
	owned, ok := ownEvidenceEvents(events)
	if !ok {
		lease.dropped.Add(1)
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
	case w.queue <- evidenceBatch{lease: lease, state: snapshot, events: owned, collectedAt: collectedAt}:
	default:
		lease.dropped.Add(1)
	}
}
func (w *evidenceWatch) run(ctx context.Context) {
	defer close(w.done)
	join := newEvidenceJoin(w, ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-w.queue:
			if batch.barrier != nil {
				join.flushAll()
				batch.barrier <- w.err()
			} else {
				if batch.state != nil {
					serial := w.serial.Add(uint64(len(batch.events))) - uint64(len(batch.events))
					parents, err := learn.Normalize(batch.lease.dataset, batch.state, batch.events, &serial)
					if err != nil {
						batch.lease.dropped.Add(1)
						continue
					}
					batch.parents = parents
					data, err := json.Marshal(parents)
					if err != nil || len(parents) > 128 || len(data) > (1<<20)-4096 {
						batch.lease.dropped.Add(1)
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
			if lease := w.active.Load(); lease != nil {
				if w.engine.InspectionToken() != lease.token {
					lease.changed.Store(true)
				}
				if lease.changed.Load() || !w.store.Clock().Before(lease.watch.Deadline) {
					_, err := w.stop(ctx, lease.watch.ID)
					w.fail(err)
				}
			}
			w.mu.Lock()
			if w.err() == nil {
				w.fail(w.store.Maintain(ctx))
			}
			w.mu.Unlock()
		}
	}
}
func (w *evidenceWatch) start(ctx context.Context, req evidence.StartWatchRequest) (evidence.Watch, error) {
	if lease := w.active.Load(); lease != nil && !time.Now().Before(lease.watch.Deadline) {
		if _, err := w.stop(ctx, lease.watch.ID); err != nil {
			return evidence.Watch{}, err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
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
	ds, err := w.store.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		return watch, err
	}
	inputs := w.engine.InspectionSnapshot()
	metadata, err := evidenceMetadataFrom(inputs)
	if err != nil {
		return watch, err
	}
	lease := &watchLease{dataset: ds, watch: watch, token: inputs.Token}
	if metadata.ProfileFingerprint != ds.ProfileFingerprint || metadata.SnapshotFingerprint != ds.SnapshotFingerprint {
		lease.changed.Store(true)
	}
	w.active.Store(lease)
	w.engine.SetLearnWatchHook(w.offer)
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
	watch, err := w.store.GetWatch(ctx, id)
	if err != nil {
		return watch, err
	}
	if lease == nil || lease.dataset.ID != watch.DatasetID {
		return w.store.StopWatch(ctx, id)
	}
	if err := ctx.Err(); err != nil {
		return watch, err
	}
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
			if _, writeErr := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Gaps: []string{"watch_storage_loss"}}); writeErr != nil {
				return watch, writeErr
			}
		}
	case <-ctx.Done():
		return watch, ctx.Err()
	}
	if dropped := lease.dropped.Swap(0); dropped > 0 {
		if _, err := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Gaps: []string{"watch_collection_loss"}, LostBatches: dropped}); err != nil {
			return watch, err
		}
	}
	if lease.changed.Load() {
		return w.store.StopWatchReason(ctx, id, "policy_changed")
	}
	return w.store.StopWatch(ctx, id)
}
