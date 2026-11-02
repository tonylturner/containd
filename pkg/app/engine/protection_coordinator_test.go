// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

func coordinatedPost(c *protectionCoordinator, h http.Handler, id, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	setProtectionHeaders(r, id, "", "test-running")
	c.mu.Lock()
	r.Header.Set(protection.PreviousApplyIDHeader, c.current)
	c.mu.Unlock()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestProtectionCoordinatorServicesAndSupersession(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	services := servicesHandler(zap.NewNop().Sugar(), dp.Engine, nil, nil, nil, nil, c)
	conf := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine}, c)
	apply := applyRulesHandler(dp.Engine, nil, c, nil)
	if w := coordinatedPost(c, services, "A", `{}`); w.Code != 200 {
		t.Fatalf("services: %d %s", w.Code, w.Body)
	}
	if st := dp.Protection(); st.ApplyID != "A" || st.Installed != nil {
		t.Fatalf("services did not begin: %+v", st)
	}
	if w := coordinatedPost(c, conf, "A", `{}`); w.Code != 200 {
		t.Fatalf("config A: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t)
	if w := coordinatedPost(c, conf, "B", `{}`); w.Code != 200 {
		t.Fatalf("config B: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t)
	if w := coordinatedPost(c, apply, "A", `{}`); w.Code != 409 || !strings.Contains(w.Body.String(), `"apply_superseded"`) {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	if dp.CurrentRules() != nil {
		t.Fatal("superseded rules had side effects")
	}
	if w := coordinatedPost(c, apply, "B", `{}`); w.Code != 200 {
		t.Fatalf("current: %d %s", w.Code, w.Body)
	}
	if st := dp.Protection(); st.State != "disabled" || st.ApplyID != "B" {
		t.Fatalf("disabled: %+v", st)
	}
	if w := coordinatedPost(c, conf, "B", `{"dpiEnabled":true}`); w.Code != 409 {
		t.Fatalf("repeated config: %d %s", w.Code, w.Body)
	}
	if dp.Protection().State != "disabled" {
		t.Fatal("rejected configuration changed installed observation")
	}
	// Missing and oversized identities are rejected on every apply route.
	for _, h := range []http.Handler{services, conf, apply, c.retryHandler(nil)} {
		for _, id := range []string{"", strings.Repeat("x", 65)} {
			if w := coordinatedPost(c, h, id, `{}`); w.Code != 400 {
				t.Fatalf("invalid identity: %d %s", w.Code, w.Body)
			}
		}
	}
	if dp.Protection().ApplyID != "B" {
		t.Fatal("invalid request changed application")
	}
}

type coordinatorFake struct {
	mu      sync.Mutex
	st      engine.ProtectionStatus
	starts  chan context.Context
	exits   atomic.Int32
	closed  atomic.Bool
	retries atomic.Int32
	retired chan struct{}
	release chan struct{}
}

func (f *coordinatorFake) SetProtectionBootID(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.BootID = id
}
func (f *coordinatorFake) BeginProtection(boot, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.BootID = boot
	f.st.ApplyID = id
	f.st.State = "pending"
}
func (f *coordinatorFake) BindProtection(m protection.Metadata) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.BootID, f.st.ApplyID = string(m.BootID), string(m.ApplyID)
	f.st.RunningRevision, f.st.Mode = m.RunningRevision, m.Mode
}
func (f *coordinatorFake) SetProtectionOutcome(protection.Metadata, protection.OwnerOutcome) {}
func (f *coordinatorFake) Protection() engine.ProtectionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}
func (f *coordinatorFake) StartProtection(ctx, lifetime context.Context) error {
	f.starts <- lifetime
	<-ctx.Done()
	f.exits.Add(1)
	return ctx.Err()
}
func (f *coordinatorFake) Close() { f.closed.Store(true) }
func (f *coordinatorFake) RetryProtection(context.Context) error {
	f.retries.Add(1)
	close(f.retired)
	<-f.release
	return nil
}

func waitCoordinatorStart(t *testing.T, f *coordinatorFake) context.Context {
	t.Helper()
	select {
	case ctx := <-f.starts:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("worker not started")
		return nil
	}
}

func TestProtectionCoordinatorReplacementAndShutdownJoin(t *testing.T) {
	f := &coordinatorFake{starts: make(chan context.Context, 2)}
	c := testProtectionCoordinator(t, f)
	h := c.admit("config", func(w http.ResponseWriter, r *http.Request) { c.start(); w.WriteHeader(200) })
	coordinatedPost(c, h, "A", `{}`)
	lifetime := waitCoordinatorStart(t, f)
	coordinatedPost(c, h, "B", `{}`)
	waitCoordinatorStart(t, f)
	if f.exits.Load() != 1 {
		t.Fatal("replacement did not join old worker")
	}
	if lifetime.Err() != nil {
		t.Fatal("replacement canceled adopted run lifetime")
	}
	c.close()
	if f.exits.Load() != 2 || !f.closed.Load() || lifetime.Err() == nil {
		t.Fatal("shutdown did not cancel and join")
	}
}

func TestProtectionCoordinatorRetryCASAndJoin(t *testing.T) {
	f := &coordinatorFake{starts: make(chan context.Context, 2), retired: make(chan struct{}), release: make(chan struct{})}
	c := testProtectionCoordinator(t, f)
	h := c.admit("config", func(w http.ResponseWriter, r *http.Request) { c.start() })
	coordinatedPost(c, h, "A", `{}`)
	waitCoordinatorStart(t, f)
	retry := c.retryHandler(nil)
	if w := coordinatedPost(c, retry, "B", `{"bootId":"wrong"}`); w.Code != 409 || !strings.Contains(w.Body.String(), "protection_superseded") {
		t.Fatalf("CAS: %d %s", w.Code, w.Body)
	}
	body, _ := json.Marshal(map[string]string{"bootId": engineBootID})
	if w := coordinatedPost(c, retry, "A", string(body)); w.Code != 409 || !strings.Contains(w.Body.String(), "protection_not_retryable") {
		t.Fatalf("not retryable: %d %s", w.Code, w.Body)
	}
	f.mu.Lock()
	f.st.State = "failed"
	f.st.Retryable = true
	f.mu.Unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- coordinatedPost(c, retry, "A", string(body)) }()
	select {
	case <-f.retired:
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not retire dead run")
	}
	if f.exits.Load() != 1 {
		t.Fatal("retry did not first join worker")
	}
	select {
	case <-f.starts:
		t.Fatal("new consumer started before join")
	default:
	}
	close(f.release)
	select {
	case w := <-done:
		if w.Code != 202 {
			t.Fatalf("retry: %d %s", w.Code, w.Body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry blocked")
	}
	waitCoordinatorStart(t, f)
	if f.retries.Load() != 1 {
		t.Fatal("duplicate retirement")
	}
}

func TestProtectionCoordinatorAbortedApplyKeepsBindWorker(t *testing.T) {
	f := &coordinatorFake{starts: make(chan context.Context, 2)}
	c := testProtectionCoordinator(t, f)
	start := c.admit("config", func(http.ResponseWriter, *http.Request) { c.start() })
	coordinatedPost(c, start, "A", `{}`)
	waitCoordinatorStart(t, f)
	// Services may precede a rejected or never-arriving configuration. They
	// must adopt the retrying run, not silently terminate its bind budget.
	services := c.admit("config", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	coordinatedPost(c, services, "B", `{}`)
	if f.exits.Load() != 0 {
		t.Fatal("services orphaned a pending initial-bind worker")
	}
}

func TestProtectionCoordinatorFailedConfigureRestartsBindWorker(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine}, c)
	entered := make(chan struct{})
	dp.startFn = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	if w := coordinatedPost(c, h, "A", `{}`); w.Code != 200 {
		t.Fatalf("config A: %d %s", w.Code, w.Body)
	}
	<-entered
	dp.reconfigErr = context.DeadlineExceeded
	if w := coordinatedPost(c, h, "B", `{"dpiEnabled":true}`); w.Code != 500 {
		t.Fatalf("config B: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t) // old worker must have joined
	if err := dp.waitStart(t); err != nil {
		t.Fatalf("failed replacement did not resume the existing run: %v", err)
	}
}

type requestBoundPlane struct {
	*coordinatorFake
	retryContext chan context.Context
}

func (p *requestBoundPlane) RetryProtection(ctx context.Context) error {
	p.retryContext <- ctx
	<-ctx.Done()
	return ctx.Err()
}
func TestProtectionRetryUsesRequestBoundContext(t *testing.T) {
	p := &requestBoundPlane{coordinatorFake: &coordinatorFake{starts: make(chan context.Context, 2)}, retryContext: make(chan context.Context, 1)}
	c := testProtectionCoordinator(t, p)
	h := c.admit("config", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	if w := coordinatedPost(c, h, "request-bound", `{}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	p.mu.Lock()
	p.st.Retryable = true
	p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := protectionRequest(http.MethodPost, "/retry", strings.NewReader(`{"bootId":"`+engineBootID+`"}`)).WithContext(ctx)
	setProtectionHeaders(r, "request-bound", "", "test-running")
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); c.retryHandler(nil).ServeHTTP(w, r); done <- w.Code }()
	select {
	case retryCtx := <-p.retryContext:
		deadline, ok := retryCtx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("retry context is not bounded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not enter owner")
	}
	cancel()
	select {
	case code := <-done:
		if code != 500 {
			t.Fatalf("cancelled retry: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not drain retry")
	}
	if c.ctx.Err() != nil {
		t.Fatal("request cancellation cancelled the adopted run lifetime")
	}
}
