// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

type logRegistration struct {
	ctx      context.Context
	source   func(capture.SourceEvent)
	reply    chan error
	stopping chan struct{}
	stopped  chan struct{}
}

type logRetryHarness struct {
	calls       chan *logRegistration
	count       atomic.Int32
	stopRelease chan struct{}
}

func (h *logRetryHarness) start(ctx context.Context, _ uint16, _ capture.RuleHitSink, _ func(error), source func(capture.SourceEvent)) (func(), error) {
	h.count.Add(1)
	r := &logRegistration{ctx: ctx, source: source, reply: make(chan error, 1), stopping: make(chan struct{}), stopped: make(chan struct{})}
	h.calls <- r
	var err error
	select {
	case err = <-r.reply:
	case <-ctx.Done():
		err = ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(r.stopping)
			if h.stopRelease != nil {
				<-h.stopRelease
			}
			close(r.stopped)
		})
	}, err
}

func (h *logRetryHarness) next(t *testing.T) *logRegistration {
	t.Helper()
	select {
	case r := <-h.calls:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("NFLOG registration did not advance")
		return nil
	}
}

func (h *logRetryHarness) assertStoppedRegistering(t *testing.T, count int32) {
	t.Helper()
	select {
	case <-h.calls:
		t.Fatal("registration continued past the retry bound")
	case <-time.After(20 * time.Millisecond):
	}
	if h.count.Load() != count {
		t.Fatalf("registrations=%d, want %d", h.count.Load(), count)
	}
}

func logRetryEngine(t *testing.T, h *logRetryHarness) *Engine {
	t.Helper()
	fastRetry(t, 3)
	old := startNFLog
	startNFLog = h.start
	t.Cleanup(func() { startNFLog = old })
	e := protectionFixture(t, false)
	e.hooks.onSource(capture.SourceEvent{Ready: true})
	e.nflogGroup = 205
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(e.Close)
	t.Cleanup(cancel)
	go func() {
		e.lifecycleMu.Lock()
		defer e.lifecycleMu.Unlock()
		e.startNFLogLocked(ctx)
	}()
	return e
}

func awaitNFLogState(t *testing.T, e *Engine, state string) ProtectionComponent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := protectionComponent(t, e.Protection(), "nflog")
		if c.State == state {
			return c
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("NFLOG did not reach %s: %+v", state, e.Protection())
	return ProtectionComponent{}
}

func TestProtectionNFLogInitialRetryBoundAndNoOperatorRetry(t *testing.T) {
	h := &logRetryHarness{calls: make(chan *logRegistration, 16)}
	e := logRetryEngine(t, h)
	for attempt := 1; attempt <= 3; attempt++ {
		r := h.next(t)
		st := e.Protection()
		c := protectionComponent(t, st, "nflog")
		if c.State != "pending" || c.Attempt != attempt || c.MaxAttempts != 3 {
			t.Fatalf("attempt progression: %+v", c)
		}
		if st.State != "pending" || st.Retryable {
			t.Fatalf("automatic initial-bind budget offered operator retry: %+v", st)
		}
		r.reply <- errBind
	}
	c := awaitNFLogState(t, e, "failed")
	if c.Attempt != 3 || c.MaxAttempts != 3 || e.Protection().State != "degraded" || !e.Protection().Retryable {
		t.Fatalf("exhausted: %+v", e.Protection())
	}
	h.assertStoppedRegistering(t, 3)
}

func TestProtectionNFLogLossResetsBoundedRetryBudget(t *testing.T) {
	h := &logRetryHarness{calls: make(chan *logRegistration, 16)}
	e := logRetryEngine(t, h)
	for range 2 {
		h.next(t).reply <- errBind
	}
	live := h.next(t)
	live.reply <- nil
	awaitNFLogState(t, e, "ready")
	live.source(capture.SourceEvent{Terminal: true, Err: errBind})
	for attempt := 1; attempt <= 3; attempt++ {
		r := h.next(t)
		select {
		case <-live.stopped:
		default:
			t.Fatal("rebind preceded retirement of lost consumer")
		}
		st := e.Protection()
		c := protectionComponent(t, st, "nflog")
		if c.Attempt != attempt || c.MaxAttempts != 3 || st.State != "degraded" || !st.Retryable {
			t.Fatalf("post-loss budget did not reset: %+v", st)
		}
		r.reply <- errBind
	}
	c := awaitNFLogState(t, e, "failed")
	if c.Attempt != 3 || c.MaxAttempts != 3 {
		t.Fatalf("post-loss exhaustion: %+v", c)
	}
	h.assertStoppedRegistering(t, 6)
}

func TestProtectionNFLogStopJoinsConsumerAndRetryWorker(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	h := &logRetryHarness{calls: make(chan *logRegistration, 16), stopRelease: release}
	e := logRetryEngine(t, h)
	t.Cleanup(unblock)
	live := h.next(t)
	live.reply <- nil
	awaitNFLogState(t, e, "ready")
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-live.stopping:
	case <-time.After(time.Second):
		t.Fatal("stop did not reach live consumer")
	}
	if live.ctx.Err() == nil {
		t.Error("stop did not cancel consumer context")
	}
	select {
	case <-done:
		t.Fatal("stop returned before consumer and retry worker joined")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not finish after consumer exited")
	}
	h.assertStoppedRegistering(t, 1)
}
