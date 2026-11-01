// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

func coordinatedPost(h http.Handler, id, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set(applyIDHeader, id)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestProtectionCoordinatorServicesAndSupersession(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	services := servicesHandler(zap.NewNop().Sugar(), dp.Engine, nil, nil, nil, nil, c)
	conf := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()}, c)
	apply := applyRulesHandler(dp.Engine, nil, c)
	wantServices := 200
	if runtime.GOOS != "linux" {
		wantServices = 400
	}
	if w := coordinatedPost(services, "A", `{}`); w.Code != wantServices {
		t.Fatalf("services: %d %s", w.Code, w.Body)
	}
	if st := dp.Protection(); st.ApplyID != "A" || st.State != "pending" {
		t.Fatalf("services did not begin: %+v", st)
	}
	if w := coordinatedPost(conf, "A", `{}`); w.Code != 200 {
		t.Fatalf("config A: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t)
	if w := coordinatedPost(conf, "B", `{}`); w.Code != 200 {
		t.Fatalf("config B: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t)
	if w := coordinatedPost(apply, "A", `{}`); w.Code != 409 || !strings.Contains(w.Body.String(), `"apply_superseded"`) {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	if dp.CurrentRules() != nil {
		t.Fatal("superseded rules had side effects")
	}
	if w := coordinatedPost(apply, "B", `{}`); w.Code != 200 {
		t.Fatalf("current: %d %s", w.Code, w.Body)
	}
	if st := dp.Protection(); st.State != "disabled" || st.ApplyID != "B" {
		t.Fatalf("disabled: %+v", st)
	}
	if w := coordinatedPost(conf, "B", `{"dpiEnabled":true}`); w.Code != 200 {
		t.Fatalf("repeated config: %d %s", w.Code, w.Body)
	}
	dp.waitStart(t)
	if dp.Protection().State != "pending" {
		t.Fatal("configuration reused an earlier rules acknowledgement")
	}
	// Missing and oversized identities are rejected on every apply route.
	for _, h := range []http.Handler{services, conf, apply, c.retryHandler(nil)} {
		for _, id := range []string{"", strings.Repeat("x", 65)} {
			if w := coordinatedPost(h, id, `{}`); w.Code != 400 {
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
	h := c.admit(func(w http.ResponseWriter, r *http.Request) { c.start(); w.WriteHeader(200) })
	coordinatedPost(h, "A", `{}`)
	lifetime := waitCoordinatorStart(t, f)
	coordinatedPost(h, "B", `{}`)
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
	h := c.admit(func(w http.ResponseWriter, r *http.Request) { c.start() })
	coordinatedPost(h, "A", `{}`)
	waitCoordinatorStart(t, f)
	retry := c.retryHandler(nil)
	if w := coordinatedPost(retry, "B", `{"bootId":"wrong"}`); w.Code != 409 || !strings.Contains(w.Body.String(), "protection_superseded") {
		t.Fatalf("CAS: %d %s", w.Code, w.Body)
	}
	body, _ := json.Marshal(map[string]string{"bootId": engineBootID})
	if w := coordinatedPost(retry, "A", string(body)); w.Code != 409 || !strings.Contains(w.Body.String(), "protection_not_retryable") {
		t.Fatalf("not retryable: %d %s", w.Code, w.Body)
	}
	f.mu.Lock()
	f.st.State = "failed"
	f.st.Retryable = true
	f.mu.Unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- coordinatedPost(retry, "A", string(body)) }()
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
