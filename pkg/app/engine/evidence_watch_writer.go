// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

const watchCommitInterval = 100 * time.Millisecond
const watchWriteBytes = 32 << 20
const watchWriteOverhead = 1024

type evidenceWrite struct {
	lease       *watchLease
	parents     []evidence.Observation
	collectedAt time.Time
	bytes       int
	barrier     chan error
}

// Only the normalization/join worker submits here, never the packet path.
// Credit includes queued AND currently persisting groups. A stalled database
// can backpressure that worker only after this separate byte budget is full;
// packet offers still use nonblocking, byte-bounded admission.
type evidenceWatchWriter struct {
	watch    *evidenceWatch
	ctx      context.Context
	queue    chan evidenceWrite
	done     chan struct{}
	released chan struct{}
	bytes    atomic.Int64
	ingest   func(context.Context, evidence.IngestRequest) (evidence.IngestResult, error)
}

func newEvidenceWatchWriter(w *evidenceWatch, ctx context.Context) *evidenceWatchWriter {
	return &evidenceWatchWriter{
		watch: w, ctx: ctx, queue: make(chan evidenceWrite, watchWriteBytes/watchWriteOverhead),
		done: make(chan struct{}), released: make(chan struct{}, 1), ingest: w.store.Ingest,
	}
}

func (p *evidenceWatchWriter) release(size int) {
	p.bytes.Add(-int64(size))
	select {
	case p.released <- struct{}{}:
	default:
	}
}

func (p *evidenceWatchWriter) submit(batch evidenceWrite) {
	// Joined outcomes can grow beyond a decoded batch's original bound. An
	// impossible reservation must fail closed, not wait forever for credit.
	if batch.bytes > watchWriteBytes {
		p.watch.fail(sqlite.ErrBudget)
		return
	}
	for p.bytes.Load()+int64(batch.bytes) > watchWriteBytes {
		select {
		case <-p.ctx.Done():
			return
		case <-p.released:
		}
	}
	p.bytes.Add(int64(batch.bytes))
	select {
	case p.queue <- batch:
	case <-p.ctx.Done():
		p.release(batch.bytes)
	}
}

func (p *evidenceWatchWriter) run() {
	defer close(p.done)
	ticker := time.NewTicker(watchCommitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case batch := <-p.queue:
			if batch.barrier != nil {
				// FIFO handoff follows join.flushAll: acknowledge only after
				// every preceding group has finished its SQLite transaction.
				batch.barrier <- p.watch.err()
				continue
			}
			err := p.watch.flushLosses(p.ctx, batch.lease)
			if err == nil {
				_, err = p.ingest(p.ctx, evidence.IngestRequest{DatasetID: batch.lease.dataset.ID, Parents: batch.parents, CollectedAt: batch.collectedAt})
			}
			p.watch.fail(err)
			p.release(batch.bytes)
		case <-ticker.C:
			if lease := p.watch.active.Load(); lease != nil {
				p.watch.fail(p.watch.flushLosses(p.ctx, lease))
			}
		}
	}
}
