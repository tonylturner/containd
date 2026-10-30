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
}
type evidenceBatch struct {
	lease       *watchLease
	parents     []evidence.Observation
	outcomes    []dpi.Event
	barrier     chan error
	collectedAt time.Time
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
	e.SetLearnWatchHook(w.offer)
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
	if lease == nil {
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
	if state != nil {
		metadata, err := evidenceMetadata(w.engine)
		if err != nil || metadata.ProfileFingerprint != lease.dataset.ProfileFingerprint || metadata.SnapshotFingerprint != lease.dataset.SnapshotFingerprint {
			lease.dropped.Add(1)
			return
		}
	}
	data, err := json.Marshal(events)
	if err != nil || len(data) > 1<<20 {
		lease.dropped.Add(1)
		return
	}
	var owned []dpi.Event
	if err := json.Unmarshal(data, &owned); err != nil {
		lease.dropped.Add(1)
		return
	}
	for i := range owned {
		owned[i].Connection = events[i].Connection
	}
	var parents []evidence.Observation
	if state != nil {
		serial := w.serial.Add(uint64(len(events))) - uint64(len(events))
		parents, err = learn.Normalize(lease.dataset, state, owned, &serial)
		if err != nil {
			lease.dropped.Add(1)
			return
		}
	}
	var outcomes []dpi.Event
	for _, ev := range owned {
		if ev.Kind == "ics.decision" || ev.Kind == "ics.verdict" || ev.Kind == "evidence.delivery" {
			outcomes = append(outcomes, ev)
		}
	}
	size, err := json.Marshal(parents)
	if err != nil || len(size) > 1<<20 || len(parents) > 128 {
		lease.dropped.Add(1)
		return
	}
	if len(parents) == 0 && len(outcomes) == 0 {
		return
	}
	select {
	case w.queue <- evidenceBatch{lease: lease, parents: parents, outcomes: outcomes, collectedAt: collectedAt}:
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
			if lease := w.active.Load(); lease != nil && !time.Now().Before(lease.watch.Deadline) {
				_, err := w.stop(ctx, lease.watch.ID)
				w.fail(err)
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
	watch, err := w.store.StartWatch(ctx, req)
	if err != nil {
		return watch, err
	}
	ds, err := w.store.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		return watch, err
	}
	w.active.Store(&watchLease{dataset: ds, watch: watch})
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
			return watch, err
		}
	case <-ctx.Done():
		return watch, ctx.Err()
	}
	if dropped := lease.dropped.Swap(0); dropped > 0 {
		if _, err := w.store.Ingest(ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Gaps: []string{"watch_collection_loss"}, LostBatches: dropped}); err != nil {
			return watch, err
		}
	}
	return w.store.StopWatch(ctx, id)
}
