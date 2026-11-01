// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// worker runs I/O jobs (nft updates, TCP resets, conntrack deletes) off the
// packet path, one at a time, from a bounded queue. Jobs are submitted only
// after the verdicts they depend on, so no job can delay a verdict.
type worker struct {
	jobs      chan func()
	submitted func()
}

func newWorker(capacity int) *worker {
	return &worker{jobs: make(chan func(), capacity)}
}

// submit queues job without blocking. It reports false when the queue is
// full; the caller treats that as a bounded-worker failure.
func (w *worker) submit(job func()) bool {
	if w.submitted != nil {
		w.submitted()
	}
	select {
	case w.jobs <- job:
		return true
	default:
		return false
	}
}

// flush waits for all jobs queued before its barrier to run. It returns false
// if the worker's run stopped before reaching the barrier.
func (w *worker) flush(stopped <-chan struct{}) bool {
	done := make(chan struct{})
	select {
	case w.jobs <- func() { close(done) }:
	case <-stopped:
		return false
	}
	select {
	case <-done:
		return true
	case <-stopped:
		return false
	}
}

// run executes queued jobs until ctx is done. Jobs still queued at that
// point belong to the stopped run and are discarded.
func (w *worker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-w.jobs:
			job()
		}
	}
}

// afterVerdict defers jobs until the verdict of the packet that caused them
// has completed: capture reports every Drop and explicitly notified decision
// through OnVerdict exactly once, including when the generation goes down.
type afterVerdict struct {
	mu        sync.Mutex
	pending   map[capture.Token]func()
	limit     int
	submitted func()
}

func newAfterVerdict(limit int) *afterVerdict {
	return &afterVerdict{pending: make(map[capture.Token]func()), limit: limit}
}

// add registers job to run once tok's verdict completes. It reports false
// when the pending set is full.
func (a *afterVerdict) add(tok capture.Token, job func()) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.submitted != nil {
		a.submitted()
	}
	if len(a.pending) >= a.limit {
		return false
	}
	a.pending[tok] = job
	return true
}

// take removes and returns the job registered for tok, if any.
func (a *afterVerdict) take(tok capture.Token) func() {
	a.mu.Lock()
	defer a.mu.Unlock()
	job := a.pending[tok]
	delete(a.pending, tok)
	return job
}
