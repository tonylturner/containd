// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

type blockingCapture struct {
	done       chan struct{}
	stopCalls  atomic.Int32
	stopWaited atomic.Bool
}

func newBlockingCapture() *blockingCapture {
	return &blockingCapture{done: make(chan struct{})}
}

func (c *blockingCapture) Start(ctx context.Context, _ capture.Handler) error {
	started := make(chan struct{})
	go func() {
		close(started)
		<-ctx.Done()
		close(c.done)
	}()
	<-started
	return nil
}

func (c *blockingCapture) Stop() {
	c.stopCalls.Add(1)
	select {
	case <-c.done:
		c.stopWaited.Store(true)
	case <-time.After(2 * time.Second):
	}
}

func (c *blockingCapture) Interfaces() []string { return nil }

func engineWithCapture(t *testing.T, runner captureRunner) *Engine {
	t.Helper()
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	e.capture = runner
	return e
}

func TestReconfigureStopsEachRunAndKeepsGoroutinesFlat(t *testing.T) {
	const cycles = 50
	const tolerance = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseline := runtime.NumGoroutine()
	current := newBlockingCapture()
	e := engineWithCapture(t, current)
	if err := e.Start(ctx); err != nil {
		t.Fatalf("initial Start: %v", err)
	}

	for i := 0; i < cycles; i++ {
		previous := current
		current = newBlockingCapture()
		e.Reconfigure(engineWithCapture(t, current))
		if previous.stopCalls.Load() != 1 || !previous.stopWaited.Load() {
			t.Fatalf("cycle %d: previous capture Stop did not wait for its worker", i)
		}
		select {
		case <-previous.done:
		default:
			t.Fatalf("cycle %d: previous capture goroutine still running before next Start", i)
		}
		if err := e.Start(ctx); err != nil {
			t.Fatalf("Start after Reconfigure %d: %v", i, err)
		}
	}

	last := current
	e.Reconfigure(engineWithCapture(t, newBlockingCapture()))
	if last.stopCalls.Load() != 1 || !last.stopWaited.Load() {
		t.Fatal("final Reconfigure did not wait for the previous capture worker")
	}

	deadline := time.Now().Add(2 * time.Second)
	var final int
	for {
		runtime.GC()
		final = runtime.NumGoroutine()
		if final <= baseline+tolerance || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("goroutine-flatness: baseline=%d final=%d tolerance=+%d reconfigure_start_cycles=%d", baseline, final, tolerance, cycles)
	if final > baseline+tolerance {
		t.Fatalf("goroutine count did not return to baseline: baseline=%d final=%d tolerance=+%d", baseline, final, tolerance)
	}
}
