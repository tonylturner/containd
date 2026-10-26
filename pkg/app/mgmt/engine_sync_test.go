// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type syncHealthFunc func(context.Context) (engineapi.RuntimeHealth, error)

func (f syncHealthFunc) RuntimeHealth(ctx context.Context) (engineapi.RuntimeHealth, error) {
	return f(ctx)
}

func TestEngineSyncTransitions(t *testing.T) {
	tests := []struct {
		name        string
		bootIDs     []string // "down" simulates unreachable health.
		failApply   int
		wantApplies []int
	}{
		{name: "first contact", bootIDs: []string{"a"}, wantApplies: []int{1}},
		{name: "same boot ID", bootIDs: []string{"a", "a", "a"}, wantApplies: []int{1, 1, 1}},
		{name: "changed boot ID", bootIDs: []string{"a", "b", "b"}, wantApplies: []int{1, 2, 2}},
		{name: "apply error retries", bootIDs: []string{"a", "a", "a"}, failApply: 1, wantApplies: []int{1, 2, 2}},
		{name: "restart apply error retries", bootIDs: []string{"a", "b", "b", "b"}, failApply: 2, wantApplies: []int{1, 2, 3, 3}},
		{name: "unreachable then up", bootIDs: []string{"down", "down", "a", "a"}, wantApplies: []int{0, 0, 1, 1}},
		{name: "known boot network flap", bootIDs: []string{"a", "down", "a"}, wantApplies: []int{1, 1, 1}},
		{name: "unknown once per reachable transition", bootIDs: []string{"", "", "down", "", ""}, wantApplies: []int{1, 1, 1, 2, 2}},
		{name: "unknown apply error retries", bootIDs: []string{"", "", ""}, failApply: 1, wantApplies: []int{1, 2, 2}},
		{name: "old to new engine", bootIDs: []string{"", "a", "a"}, wantApplies: []int{1, 2, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			var bootID string
			calls := 0
			s := engineSync{
				health: syncHealthFunc(func(context.Context) (engineapi.RuntimeHealth, error) {
					if bootID == "down" {
						return engineapi.RuntimeHealth{}, errors.New("connection refused")
					}
					return engineapi.RuntimeHealth{BootID: bootID}, nil
				}),
				apply: func(context.Context) ([]string, error) {
					calls++
					if calls == tt.failApply {
						return nil, errors.New("apply failed")
					}
					return []string{"interfaces: permission denied"}, nil
				},
				logger: zap.New(core).Sugar(),
			}
			for i, id := range tt.bootIDs {
				bootID = id
				before := calls
				reachable := s.poll(context.Background())
				wantReachable := id != "down" && !(calls > before && calls == tt.failApply)
				if reachable != wantReachable {
					t.Fatalf("poll %d reachable = %v", i, reachable)
				}
				if calls != tt.wantApplies[i] {
					t.Fatalf("poll %d applies = %d, want %d", i, calls, tt.wantApplies[i])
				}
			}
			if logs.FilterMessage("engine sync: interfaces: permission denied").Len() == 0 {
				t.Fatal("apply warnings not logged")
			}
		})
	}
}

func TestEngineSyncBackoffAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls []time.Time
		up := false
		var mu sync.Mutex
		healthTimes := func() []time.Time {
			mu.Lock()
			defer mu.Unlock()
			return append([]time.Time(nil), calls...)
		}
		s := engineSync{
			health: syncHealthFunc(func(context.Context) (engineapi.RuntimeHealth, error) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, time.Now())
				if !up {
					return engineapi.RuntimeHealth{}, errors.New("down")
				}
				return engineapi.RuntimeHealth{BootID: "a"}, nil
			}),
			apply:  func(context.Context) ([]string, error) { return nil, nil },
			logger: zap.NewNop().Sugar(),
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.run(ctx)
		}()
		synctest.Wait()
		if got := healthTimes(); len(got) != 1 {
			t.Fatalf("initial health calls = %d", len(got))
		}
		for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second} {
			before := len(healthTimes())
			time.Sleep(delay)
			synctest.Wait()
			got := healthTimes()
			if len(got) != before+1 || got[before].Sub(got[before-1]) != delay {
				t.Fatalf("health calls did not back off by %v: %v", delay, got)
			}
		}
		mu.Lock()
		up = true
		mu.Unlock()
		time.Sleep(engineSyncMaxBackoff)
		synctest.Wait()
		before := len(healthTimes())
		time.Sleep(engineSyncInterval)
		synctest.Wait()
		if len(healthTimes()) != before+1 {
			t.Fatal("successful health did not reset backoff")
		}
		cancel()
		<-done
	})
}

func TestEngineSyncCancellationDuringHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := engineSync{
			health: syncHealthFunc(func(ctx context.Context) (engineapi.RuntimeHealth, error) {
				<-ctx.Done()
				return engineapi.RuntimeHealth{}, ctx.Err()
			}),
			apply: func(context.Context) ([]string, error) {
				t.Error("must not apply after canceled health")
				return nil, nil
			},
			logger: zap.NewNop().Sugar(),
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.run(ctx)
		}()
		synctest.Wait()
		cancel()
		<-done
	})
}

func TestStartEngineSyncReplaysStoredRunningConfig(t *testing.T) {
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	cfg.Firewall.DefaultAction = config.ActionAllow
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	paths := make(chan string, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record the path only after the body is read: the test stops the
		// sync loop as soon as it sees the last path, which cancels any
		// request still in flight.
		if r.URL.Path == "/internal/apply_rules" {
			var snap rules.Snapshot
			if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
				t.Error(err)
			} else if snap.Default != rules.ActionAllow {
				t.Errorf("replayed rule default=%q, want stored ALLOW", snap.Default)
			}
		}
		paths <- r.URL.Path
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"bootId":"boot-1","iec104Enforcement":{"healthy":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	stop := startEngineSync(context.Background(), zap.NewNop().Sugar(), store, engineapi.NewHTTPClient(srv.URL), nil)
	defer stop()
	want := []string{
		"/health", "/internal/interfaces", "/internal/routing",
		"/internal/services", "/internal/config", "/internal/pcap/config",
		"/internal/pcap/stop", "/internal/apply_rules",
	}
	var got []string
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for len(got) < len(want) {
		select {
		case path := <-paths:
			got = append(got, path)
		case <-timer.C:
			t.Fatalf("timed out waiting for startup replay: %v", got)
		}
	}
	stop()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replay push sequence=%v, want %v", got, want)
	}
}

func TestStartEngineSyncWithoutEngine(t *testing.T) {
	stop := startEngineSync(context.Background(), zap.NewNop().Sugar(), nil, nil, nil)
	stop()
}

func TestEngineSyncForcedReplayRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		replay := make(chan struct{}, 1)
		var up, fail atomic.Bool
		up.Store(true)
		var calls atomic.Int32
		s := engineSync{
			health: syncHealthFunc(func(context.Context) (engineapi.RuntimeHealth, error) {
				if !up.Load() {
					return engineapi.RuntimeHealth{}, errors.New("down")
				}
				return engineapi.RuntimeHealth{BootID: "same"}, nil
			}),
			apply: func(context.Context) ([]string, error) {
				calls.Add(1)
				if fail.Load() {
					return nil, errors.New("apply failed")
				}
				return nil, nil
			},
			logger: zap.NewNop().Sugar(),
			replay: replay,
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.run(ctx)
		}()
		synctest.Wait()
		up.Store(false)
		replay <- struct{}{}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("unreachable engine applied: %d", calls.Load())
		}
		up.Store(true)
		fail.Store(true)
		time.Sleep(engineSyncInterval)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("forced replay lost during outage: %d", calls.Load())
		}
		fail.Store(false)
		time.Sleep(2 * engineSyncInterval) // failed applies now share outage backoff
		synctest.Wait()
		if calls.Load() != 3 {
			t.Fatalf("forced replay did not retry apply failure: %d", calls.Load())
		}
		time.Sleep(2 * engineSyncInterval)
		synctest.Wait()
		if calls.Load() != 3 {
			t.Fatalf("successful forced replay repeated: %d", calls.Load())
		}
		cancel()
		<-done
	})
}

func TestAutoRollbackReplaysPreviousConfig(t *testing.T) {
	for _, timing := range []string{"before startup", "after startup", "during replay"} {
		t.Run(timing, func(t *testing.T) {
			store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			ctx := context.Background()
			previous := config.DefaultConfig()
			previous.Interfaces = nil
			previous.Firewall.DefaultAction = config.ActionAllow
			pending := *previous
			pending.Firewall.DefaultAction = config.ActionDeny
			if err := store.Save(ctx, previous); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveCandidate(ctx, &pending); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if timing == "before startup" {
				ttl = time.Millisecond
			}
			if err := store.CommitConfirmed(ctx, ttl); err != nil {
				t.Fatal(err)
			}
			// Wait for expiry before registering management's hook to verify
			// that the unconditional boot replay covers the startup gap.
			if timing == "before startup" {
				waitForRollback(t, store)
			}
			applied := make(chan rules.Action, 8)
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					_, _ = w.Write([]byte(`{"bootId":"same","iec104Enforcement":{"healthy":true}}`))
					return
				}
				if r.URL.Path == "/internal/apply_rules" {
					var snap rules.Snapshot
					if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if timing == "during replay" && snap.Default == rules.ActionDeny {
						close(entered)
						<-release
					}
					applied <- snap.Default
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			stop := startEngineSync(ctx, zap.NewNop().Sugar(), store, engineapi.NewHTTPClient(srv.URL), nil)
			defer func() {
				unblock()
				stop()
			}()
			awaitApply := func(want rules.Action) {
				t.Helper()
				select {
				case got := <-applied:
					if got != want {
						t.Fatalf("engine rules=%s, want %s", got, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("timed out waiting for rules=%s", want)
				}
			}
			if timing != "before startup" {
				if timing == "during replay" {
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("replay never reached engine")
					}
				} else {
					awaitApply(rules.ActionDeny)
				}
				// Re-arm the still-pending commit with a short deadline.
				// Seed the candidate with pending, but preserve previous by
				// restoring it before CommitConfirmed snapshots running.
				if err := store.Save(ctx, previous); err != nil {
					t.Fatal(err)
				}
				if err := store.SaveCandidate(ctx, &pending); err != nil {
					t.Fatal(err)
				}
				if err := store.CommitConfirmed(ctx, time.Millisecond); err != nil {
					t.Fatal(err)
				}
				waitForRollback(t, store)
				if timing == "during replay" {
					unblock()
					awaitApply(rules.ActionDeny)
				}
			}
			awaitApply(rules.ActionAllow)
			// The boot ID is unchanged: the next normal tick must not push
			// a second rollback replay.
			select {
			case got := <-applied:
				t.Fatalf("unexpected extra replay: %s", got)
			case <-time.After(1100 * time.Millisecond):
			}
			stop()
		})
	}
}

func waitForRollback(t *testing.T, store config.Store) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		cfg, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Firewall.DefaultAction == config.ActionAllow {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("store did not auto-rollback")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestEngineSyncBootFaultAppliesRecoveryWithoutSpam(t *testing.T) {
	ctx := context.Background()
	r := &mgmtpath.Reservation{Device: "fixture", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"), config.WithManagementReservation(r))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "custom", Device: r.Device, Zone: "lan"}}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.SetManagementBootFault(ctx, "stored conflict"); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.InfoLevel)
	calls := 0
	s := engineSync{store: store, logger: zap.New(core).Sugar(), health: syncHealthFunc(func(context.Context) (engineapi.RuntimeHealth, error) {
		return engineapi.RuntimeHealth{BootID: "a"}, nil
	}), apply: func(context.Context) ([]string, error) { calls++; return nil, nil }}
	for range 3 {
		s.poll(ctx)
	}
	if calls != 1 || logs.Len() != 1 || !s.recovery {
		t.Fatalf("fault retried/logged: %d %v", calls, logs.All())
	}
	if err := store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.poll(ctx)
	if calls != 2 || !s.applied || s.recovery {
		t.Fatal("recovery did not resume replay")
	}
	if err := store.SetManagementBootFault(ctx, "another boot fault"); err != nil {
		t.Fatal(err)
	}
	s.poll(ctx)
	s.lastBootID = "old-boot"
	s.poll(ctx)
	s.poll(ctx)
	if calls != 4 {
		t.Fatal("recovery not applied exactly once per engine boot")
	}
}

func TestEngineSyncRepeatedApplyErrorLogsOnce(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	s := engineSync{
		logger: zap.New(core).Sugar(),
		health: syncHealthFunc(func(context.Context) (engineapi.RuntimeHealth, error) {
			return engineapi.RuntimeHealth{BootID: "a"}, nil
		}),
		apply: func(context.Context) ([]string, error) {
			return nil, errors.New("recovery ruleset: nft apply failed")
		},
	}
	for range 3 {
		if s.poll(context.Background()) {
			t.Fatal("apply failure must back off")
		}
	}
	if logs.Len() != 1 || s.applied {
		t.Fatalf("repeated apply failure: %v applied=%v", logs.All(), s.applied)
	}
}
