// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type commitApplyStore struct {
	config.Store
	commit func() error
}

func (s *commitApplyStore) Commit(context.Context) error { return s.commit() }

type blockingApplyEngine struct {
	*mockEngine
	entered chan struct{}
	release chan struct{}
	applied []rules.Action
}

func (e *blockingApplyEngine) ApplyRules(_ context.Context, snap rules.Snapshot) error {
	e.applied = append(e.applied, snap.Default)
	if len(e.applied) == 1 {
		close(e.entered)
		<-e.release
	}
	return nil
}

func TestApplyRunningConfigSerializesReplayAndCommit(t *testing.T) {
	old := config.DefaultConfig()
	old.Interfaces = nil // No host-dependent auto-binding in this ordering test.
	old.Firewall.DefaultAction = config.ActionDeny
	newer := *old
	newer.Firewall.DefaultAction = config.ActionAllow
	running := old
	loads := 0
	var storeMu sync.Mutex
	committed := make(chan struct{})
	store := &commitApplyStore{
		Store: &mockStore{load: func() (*config.Config, error) {
			storeMu.Lock()
			defer storeMu.Unlock()
			loads++
			return running, nil
		}},
		commit: func() error {
			storeMu.Lock()
			running = &newer
			storeMu.Unlock()
			close(committed)
			return nil
		},
	}
	engine := &blockingApplyEngine{
		mockEngine: &mockEngine{},
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	replayDone := make(chan error, 1)
	go func() {
		_, err := ApplyRunningConfig(context.Background(), store, engine, nil)
		replayDone <- err
	}()
	<-engine.entered
	if runningConfigApplyMu.TryLock() {
		runningConfigApplyMu.Unlock()
		t.Fatal("apply mutex was released before the rule push finished")
	}
	server := NewServerWithEngine(store, nil, engine)
	rec := httptest.NewRecorder()
	commitDone := make(chan struct{})
	go func() {
		defer close(commitDone)
		server.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/config/commit", nil))
	}()
	<-committed
	select {
	case <-commitDone:
		t.Fatal("commit apply completed while replay was still pushing rules")
	case <-time.After(20 * time.Millisecond):
	}
	storeMu.Lock()
	earlyLoads := loads
	storeMu.Unlock()
	if earlyLoads != 1 {
		t.Fatalf("queued commit loaded early: loads=%d", earlyLoads)
	}
	close(engine.release)
	if err := <-replayDone; err != nil {
		t.Fatal(err)
	}
	<-commitDone
	if rec.Code != http.StatusOK {
		t.Fatalf("commit status=%d body=%s", rec.Code, rec.Body)
	}
	if loads != 2 || !reflect.DeepEqual(engine.applied, []rules.Action{rules.ActionDeny, rules.ActionAllow}) {
		t.Fatalf("applied stale config: loads=%d, applied=%v", loads, engine.applied)
	}
}

func TestApplyRunningConfigMissingAndLoadError(t *testing.T) {
	engine := &mockEngine{}
	warnings, err := ApplyRunningConfig(context.Background(), &mockStore{}, engine, nil)
	if err != nil || len(warnings) != 0 || engine.applied {
		t.Fatalf("missing running config must be a no-op: warnings=%v err=%v applied=%v", warnings, err, engine.applied)
	}
	want := errors.New("store unavailable")
	store := &mockStore{load: func() (*config.Config, error) { return nil, want }}
	if _, err := ApplyRunningConfig(context.Background(), store, engine, nil); !errors.Is(err, want) {
		t.Fatalf("load error=%v, want %v", err, want)
	}
}

func TestApplyRunningConfigCanceledWaiterDoesNotLoad(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	loads := 0
	store := &mockStore{load: func() (*config.Config, error) {
		loads++
		return cfg, nil
	}}
	engine := &blockingApplyEngine{
		mockEngine: &mockEngine{},
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	first := make(chan error, 1)
	go func() {
		_, err := applyRunningConfig(context.Background(), store, engine, nil)
		first <- err
	}()
	<-engine.entered
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := ApplyRunningConfig(ctx, store, engine, nil)
		second <- err
	}()
	cancel()
	close(engine.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled apply error=%v", err)
	}
	if loads != 1 {
		t.Fatalf("canceled waiter loaded config: loads=%d", loads)
	}
}
