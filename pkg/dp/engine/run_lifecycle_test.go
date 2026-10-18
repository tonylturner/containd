// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

var errCapturePreflight = errors.New("capture preflight failed")

// retryCapture and blockingCapture stop like capture.Manager: Stop cancels
// the capture's own context and waits for its run to exit. Reconfigure stops
// the old capture before it cancels the engine run (see engine.go).
type retryCapture struct {
	startCalls atomic.Int32
	stopCalls  atomic.Int32
	done       chan struct{}
	cancel     context.CancelFunc
}

func (c *retryCapture) Start(ctx context.Context, _ capture.Handler) error {
	if c.startCalls.Add(1) == 1 {
		return errCapturePreflight
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})
	go func(done chan struct{}) {
		<-runCtx.Done()
		close(done)
	}(c.done)
	return nil
}

func (c *retryCapture) Stop() {
	c.stopCalls.Add(1)
	if c.cancel != nil {
		c.cancel()
	}
	if c.done != nil {
		<-c.done
	}
}

func (c *retryCapture) Interfaces() []string { return nil }

func (c *retryCapture) Settler() capture.Settler { return nil }

func TestStartRetriesAfterCaptureFailure(t *testing.T) {
	ctx := context.Background()
	c := &retryCapture{}
	e := engineWithCapture(t, c)
	if err := e.Start(ctx); !errors.Is(err, errCapturePreflight) {
		t.Fatalf("first Start error = %v, want %v", err, errCapturePreflight)
	}
	if got := c.stopCalls.Load(); got != 0 {
		t.Fatalf("capture Stop called after failed Start: %d times", got)
	}
	if err := e.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if got := c.startCalls.Load(); got != 2 {
		t.Fatalf("capture Start calls = %d, want 2", got)
	}
	e.Reconfigure(engineWithCapture(t, newBlockingCapture()))
	if got := c.stopCalls.Load(); got != 1 {
		t.Fatalf("capture Stop calls after Reconfigure = %d, want 1", got)
	}
	select {
	case <-c.done:
	default:
		t.Fatal("Reconfigure returned before capture run exited")
	}
}

type blockingCapture struct {
	done       chan struct{}
	cancel     context.CancelFunc
	stopCalls  atomic.Int32
	stopWaited atomic.Bool
}

func newBlockingCapture() *blockingCapture {
	return &blockingCapture{done: make(chan struct{})}
}

func (c *blockingCapture) Start(ctx context.Context, _ capture.Handler) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	started := make(chan struct{})
	go func() {
		close(started)
		<-runCtx.Done()
		close(c.done)
	}()
	<-started
	return nil
}

func (c *blockingCapture) Stop() {
	c.stopCalls.Add(1)
	if c.cancel != nil {
		c.cancel()
	}
	select {
	case <-c.done:
		c.stopWaited.Store(true)
	case <-time.After(2 * time.Second):
	}
}

func (c *blockingCapture) Interfaces() []string { return nil }

func (c *blockingCapture) Settler() capture.Settler { return nil }

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
