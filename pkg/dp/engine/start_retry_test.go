// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// bindCapture fails its first n Starts like an unbound NFQUEUE.
type bindCapture struct {
	onReady func()
	fails   int32
	starts  atomic.Int32
}

var errBind = errors.New("nfqueue: bind: operation not permitted")

func (c *bindCapture) Start(context.Context, capture.Handler) error {
	if c.starts.Add(1) <= c.fails {
		return errBind
	}
	if c.onReady != nil {
		c.onReady()
	}
	return nil
}
func (c *bindCapture) Stop()                    {}
func (c *bindCapture) Interfaces() []string     { return nil }
func (c *bindCapture) Settler() capture.Settler { return nil }

func fastRetry(t *testing.T, attempts int) {
	t.Helper()
	i, m, a := startRetryInitial, startRetryMax, startRetryAttempts
	startRetryInitial, startRetryMax, startRetryAttempts = time.Millisecond, 4*time.Millisecond, attempts
	t.Cleanup(func() { startRetryInitial, startRetryMax, startRetryAttempts = i, m, a })
}

func inlineEngine(t *testing.T, c captureRunner) *Engine {
	t.Helper()
	e := engineWithCapture(t, c)
	e.nfqueueGroup = 101
	e.iec.injector = &session.Fake{}
	e.iec.health.clear(faultInjector) // engineWithCapture built a non-inline engine
	e.LoadRules(iecSnapshot("enforce"))
	return e
}

func TestStartWithRetryBindsAfterFailures(t *testing.T) {
	fastRetry(t, 8)
	c := &bindCapture{fails: 3}
	e := inlineEngine(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.StartWithRetry(ctx); err != nil {
		t.Fatalf("StartWithRetry = %v", err)
	}
	if got := c.starts.Load(); got != 4 {
		t.Fatalf("starts = %d, want 4", got)
	}
	// Unbound, IEC104 enforcement reports the queue-bind fault until the
	// queue reports ready.
	if st := e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "queue bind") {
		t.Fatalf("health while the queue was unbound = %+v", st)
	}
	e.hooks.onSource(capture.SourceEvent{Generation: 1, Ready: true})
	if st := e.IEC104Enforcement(); !st.Healthy {
		t.Fatalf("health after bind = %+v", st)
	}
}

func TestStartWithRetryIsBounded(t *testing.T) {
	fastRetry(t, 3)
	c := &bindCapture{fails: 100}
	e := inlineEngine(t, c)
	err := e.StartWithRetry(context.Background())
	if !errors.Is(err, errBind) || !strings.Contains(err.Error(), "giving up after 3") || c.starts.Load() != 3 {
		t.Fatalf("StartWithRetry = %v after %d starts", err, c.starts.Load())
	}
	if st := e.IEC104Enforcement(); st.Healthy {
		t.Fatalf("health after giving up = %+v", st)
	}
}

func TestStartWithRetryStopsOnReconfigure(t *testing.T) {
	fastRetry(t, 1000)
	i := startRetryInitial
	startRetryInitial = 20 * time.Millisecond
	t.Cleanup(func() { startRetryInitial = i })
	c := &bindCapture{fails: 1000}
	e := inlineEngine(t, c)
	done := make(chan error, 1)
	go func() { done <- e.StartWithRetry(context.Background()) }()
	time.Sleep(5 * time.Millisecond)
	e.Reconfigure(engineWithCapture(t, &bindCapture{}))
	select {
	case err := <-done:
		if !errors.Is(err, errStartSuperseded) {
			t.Fatalf("StartWithRetry = %v, want superseded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop survived Reconfigure")
	}
}

func TestStartWithRetryDoesNotRetryAFPacket(t *testing.T) {
	fastRetry(t, 8)
	c := &bindCapture{fails: 1}
	e := engineWithCapture(t, c)
	if err := e.StartWithRetry(context.Background()); !errors.Is(err, errBind) || c.starts.Load() != 1 {
		t.Fatalf("observational start = %v after %d starts", err, c.starts.Load())
	}
}

func TestNormalQueueCloseIsNotLoggedAsError(t *testing.T) {
	var logged []error
	e, err := New(Config{OnError: func(err error) { logged = append(logged, err) }})
	if err != nil {
		t.Fatal(err)
	}
	e.hooks.onSource(capture.SourceEvent{Generation: 1, Err: capture.ErrQueueClosed})
	if len(logged) != 0 {
		t.Fatalf("a queue closed by Stop was logged: %v", logged)
	}
	e.hooks.onSource(capture.SourceEvent{Generation: 2, Err: errBind})
	if len(logged) != 1 {
		t.Fatalf("a queue failure was not logged: %v", logged)
	}
}

// TestStartWithRetryAfterGivingUpStartsAgain: the retry loop gives up, and
// a later call (an unchanged config POST) retries the bind and starts.
func TestStartWithRetryAfterGivingUpStartsAgain(t *testing.T) {
	fastRetry(t, 3)
	c := &bindCapture{fails: 3}
	e := inlineEngine(t, c)
	if err := e.StartWithRetry(context.Background()); !errors.Is(err, errBind) {
		t.Fatalf("first StartWithRetry = %v, want give-up", err)
	}
	if err := e.StartWithRetry(context.Background()); err != nil || c.starts.Load() != 4 {
		t.Fatalf("second StartWithRetry = %v after %d starts", err, c.starts.Load())
	}
	if err := e.StartWithRetry(context.Background()); err != nil || c.starts.Load() != 4 {
		t.Fatalf("StartWithRetry on a started engine must be a no-op: %v after %d starts", err, c.starts.Load())
	}
}
