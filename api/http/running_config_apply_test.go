// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
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
func (s *commitApplyStore) CommitConfirmed(context.Context, time.Duration) error {
	return s.commit()
}
func (s *commitApplyStore) Rollback(context.Context) error { return s.commit() }

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

// The replay has already loaded the old config when the mutation arrives.
// Persistence must wait, not just the subsequent apply: otherwise an auto-bind
// Save of the replay's old snapshot can overwrite the newly committed config.
func TestApplyRunningConfigSerializesReplayAndRunningMutation(t *testing.T) {
	for _, action := range []string{"commit", "commit_confirmed", "rollback"} {
		t.Run(action, func(t *testing.T) {
			old := config.DefaultConfig()
			old.Interfaces = nil // Keep the ordering test independent of host interfaces.
			old.Firewall.DefaultAction = config.ActionDeny
			newer := *old
			newer.Firewall.DefaultAction = config.ActionAllow
			running := old
			loads := 0
			var storeMu sync.Mutex
			committed := make(chan struct{})
			mutationUnlocked := false
			store := &commitApplyStore{
				Store: &mockStore{load: func() (*config.Config, error) {
					storeMu.Lock()
					defer storeMu.Unlock()
					loads++
					return running, nil
				}},
				commit: func() error {
					if runningConfigApplyMu.TryLock() {
						runningConfigApplyMu.Unlock()
						mutationUnlocked = true
					}
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
			var release sync.Once
			unblock := func() { release.Do(func() { close(engine.release) }) }
			defer unblock()
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
			mutationDone := make(chan struct{})
			go func() {
				defer close(mutationDone)
				server.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/config/"+action, http.NoBody))
			}()
			earlyMutation := false
			select {
			case <-committed:
				earlyMutation = true
			case <-time.After(20 * time.Millisecond):
			}
			storeMu.Lock()
			earlyLoads := loads
			storeMu.Unlock()
			unblock()
			if err := <-replayDone; err != nil {
				t.Fatal(err)
			}
			<-mutationDone
			if earlyMutation || mutationUnlocked {
				t.Fatalf("running mutation escaped apply lock: during replay=%v unlocked=%v", earlyMutation, mutationUnlocked)
			}
			if earlyLoads != 1 {
				t.Fatalf("queued mutation loaded early: loads=%d", earlyLoads)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("mutation status=%d body=%s", rec.Code, rec.Body)
			}
			if running != &newer || loads != 3 || !reflect.DeepEqual(engine.applied, []rules.Action{rules.ActionDeny, rules.ActionAllow}) {
				t.Fatalf("lost update: running=%p, want=%p, loads=%d, applied=%v", running, &newer, loads, engine.applied)
			}
		})
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

func TestApplyRunningConfigBindsInterfacesWithoutSaving(t *testing.T) {
	previousBinder := bindDefaultInterfaceDevices
	bindDefaultInterfaceDevices = func(cfg *config.Config) bool {
		cfg.Interfaces[0].Device = "en0"
		return true
	}
	t.Cleanup(func() { bindDefaultInterfaceDevices = previousBinder })

	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "wan", Zone: "wan"}}
	store := &mockStore{
		cfg: cfg,
		load: func() (*config.Config, error) {
			loaded := *cfg
			loaded.Interfaces = append([]config.Interface(nil), cfg.Interfaces...)
			return &loaded, nil
		},
	}
	engine := &mockEngine{}

	warnings, err := ApplyRunningConfig(context.Background(), store, engine, nil)
	if err != nil {
		t.Fatalf("ApplyRunningConfig() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ApplyRunningConfig() warnings = %v", warnings)
	}
	if store.calls != 0 {
		t.Fatalf("apply called Store.Save %d times, want 0", store.calls)
	}
	if cfg.Interfaces[0].Device != "" {
		t.Fatalf("apply modified stored config device to %q", cfg.Interfaces[0].Device)
	}
	if len(engine.lastIf) != 1 || engine.lastIf[0].Device == "" {
		t.Fatalf("engine interfaces = %+v, want the autobound device", engine.lastIf)
	}
	if engine.lastIf[0].Device == cfg.Interfaces[0].Device {
		t.Fatalf("engine interface device was not bound: %+v", engine.lastIf[0])
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

func TestRuntimeMutationsWaitForReplay(t *testing.T) {
	for _, endpoint := range []struct {
		path   string
		body   any
		method string
	}{
		{path: "/pcap/start", body: config.PCAPConfig{Interfaces: []string{"capture"}}},
		{path: "/pcap/stop"},
		{path: "/interfaces/reconcile", body: map[string]string{"confirm": "REPLACE"}},
		{path: "/routing/reconcile", body: map[string]string{"confirm": "REPLACE"}},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			t.Setenv("CONTAIND_OPENVPN_DIR", t.TempDir())
			cfg := config.DefaultConfig()
			cfg.Interfaces = nil
			var loads atomic.Int32
			var loadedUnlocked atomic.Bool
			store := &mockStore{load: func() (*config.Config, error) {
				if runningConfigApplyMu.TryLock() {
					runningConfigApplyMu.Unlock()
					loadedUnlocked.Store(true)
				}
				loads.Add(1)
				return cfg, nil
			}}
			engine := &blockingApplyEngine{
				mockEngine: &mockEngine{},
				entered:    make(chan struct{}),
				release:    make(chan struct{}),
			}
			var release sync.Once
			unblock := func() { release.Do(func() { close(engine.release) }) }
			defer unblock()
			replayDone := make(chan error, 1)
			go func() {
				_, err := ApplyRunningConfig(context.Background(), store, engine, nil)
				replayDone <- err
			}()
			<-engine.entered
			body, err := json.Marshal(endpoint.body)
			if err != nil {
				t.Fatal(err)
			}
			server := NewServerWithEngine(store, nil, engine)
			rec := httptest.NewRecorder()
			mutationDone := make(chan struct{})
			go func() {
				defer close(mutationDone)
				method := endpoint.method
				if method == "" {
					method = http.MethodPost
				}
				req := authedRequest(method, "/api/v1"+endpoint.path, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				server.ServeHTTP(rec, req)
			}()
			earlyMutation := false
			select {
			case <-mutationDone:
				earlyMutation = true
			case <-time.After(20 * time.Millisecond):
			}
			earlyLoads := loads.Load()
			unblock()
			if err := <-replayDone; err != nil {
				t.Fatal(err)
			}
			<-mutationDone
			if earlyMutation || earlyLoads != 1 || loadedUnlocked.Load() {
				t.Fatalf("runtime mutation escaped replay lock: completed=%v loads=%d unlocked=%v", earlyMutation, earlyLoads, loadedUnlocked.Load())
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("mutation status=%d body=%s", rec.Code, rec.Body)
			}
		})
	}
}
