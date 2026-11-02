// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	engineclient "github.com/tonylturner/containd/api/engine"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/demo"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
	"go.uber.org/zap"
)

type demoEngine struct {
	mu               sync.Mutex
	boot             string
	running          bool
	err              error
	actions          []string
	entered, release chan struct{}
}

func (e *demoEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return engineclient.RuntimeHealth{BootID: e.boot}, e.err
}
func (e *demoEngine) SimulationStatus(context.Context) (engineclient.SimulationStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return engineclient.SimulationStatus{Running: e.running, Loops: 3, CaptureSet: "containd-demo/1", Capture: "modbus/operations.pcap"}, e.err
}
func (e *demoEngine) SimulationControl(ctx context.Context, action string) (engineclient.SimulationStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return engineclient.SimulationStatus{}, e.err
	}
	if action == "start" && e.entered != nil {
		close(e.entered)
		select {
		case <-e.release:
		case <-ctx.Done():
			return engineclient.SimulationStatus{}, ctx.Err()
		}
		e.entered = nil
	}
	e.actions = append(e.actions, action)
	e.running = action == "start"
	return engineclient.SimulationStatus{Running: e.running}, nil
}
func (e *demoEngine) reboot(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.boot, e.running = id, false
}
func (e *demoEngine) assertStopped(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		t.Fatal("demo running")
	}
}

type demoCounter struct{ value uint64 }

func (r *demoCounter) TelemetryCounters(context.Context) (wire.CounterSnapshot, error) {
	return wire.CounterSnapshot{Samples: []wire.CounterSample{{Metric: wire.IfaceRxBytes, Origin: wire.OriginReal, Epoch: "kernel", Value: r.value}}}, nil
}

func TestDemoAutoSamplerAndUpgrade(t *testing.T) {
	for _, upgraded := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgraded"}[upgraded], func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			e := &demoEngine{boot: "a"}
			r := loadDemoReconciler(filepath.Join(dir, "demo.json"), e)
			store, err := history.Open(filepath.Join(dir, "telemetry.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			r.history = store
			counters := &demoCounter{value: 100}
			sampler := history.NewSampler(store, counters)
			sampler.AfterTick = r.Reconcile
			r.EngineSynced(ctx, "a")
			start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC).Add(time.Second)
			tick := func(n int) {
				t.Helper()
				if err := sampler.Tick(ctx, start.Add(time.Duration(n)*10*time.Second), time.Duration(n)*10*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			tick(0)
			e.assertStopped(t)
			if upgraded {
				counters.value++
			}
			tick(1)
			st, err := r.SimulationStatus(ctx)
			if err != nil || st.Preference != demo.Auto || st.Running == upgraded {
				t.Fatal(st, err)
			}
			counters.value++
			tick(2)
			st, _ = r.SimulationStatus(ctx)
			if st.Running || st.Reason != "real traffic observed" {
				t.Fatal(st)
			}
			tick(3)
			e.reboot("b")
			r.EngineSynced(ctx, "b")
			r = loadDemoReconciler(r.path, e)
			r.history = store
			r.EngineSynced(ctx, "b")
			st, _ = r.SimulationStatus(ctx)
			if st.Running || st.Reason != "real traffic observed" {
				t.Fatal(st)
			}
			if upgraded {
				for _, action := range e.actions {
					if action == "start" {
						t.Fatal("upgraded real appliance started demo")
					}
				}
			}
		})
	}
}

func TestDemoStopPersistsAndDeliveryRetries(t *testing.T) {
	ctx := context.Background()
	e := &demoEngine{boot: "a"}
	path := filepath.Join(t.TempDir(), "demo.json")
	r := loadDemoReconciler(path, e)
	r.EngineSynced(ctx, "a")
	if st, err := r.SimulationControl(ctx, "start"); err != nil || !st.Running || st.Preference != demo.On {
		t.Fatal(st, err)
	}
	e.mu.Lock()
	e.err = errors.New("offline")
	e.mu.Unlock()
	st, err := r.SimulationControl(ctx, "stop")
	if err != nil || st.Preference != demo.Off || st.Error != "engine unreachable: offline" {
		t.Fatal(st, err)
	}
	if p, err := demo.Load(path); err != nil || p != demo.Off {
		t.Fatal(p, err)
	}
	e.mu.Lock()
	e.err = nil
	e.mu.Unlock()
	r.Reconcile(ctx)
	e.assertStopped(t)
	r = loadDemoReconciler(path, e)
	e.reboot("b")
	r.EngineSynced(ctx, "b")
	e.assertStopped(t)
	if st, _ := r.SimulationStatus(ctx); st.Preference != demo.Off {
		t.Fatal(st)
	}
	// A new engine boot is never started until its config was applied.
	if _, err := r.SimulationControl(ctx, "start"); err != nil {
		t.Fatal(err)
	}
	e.reboot("c")
	r.Reconcile(ctx)
	e.assertStopped(t)
	r.EngineSynced(ctx, "c")
	if st, _ := r.SimulationStatus(ctx); !st.Running {
		t.Fatal(st)
	}
}

func TestDemoStaleReconcileCannotOverrideStop(t *testing.T) {
	ctx := context.Background()
	e := &demoEngine{boot: "a"}
	r := loadDemoReconciler(filepath.Join(t.TempDir(), "demo.json"), e)
	r.EngineSynced(ctx, "a")
	if _, err := r.SimulationControl(ctx, "start"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	e.mu.Lock()
	e.entered, e.release = entered, release
	e.mu.Unlock()
	done := make(chan struct{})
	go func() { defer close(done); r.Reconcile(ctx) }()
	<-entered
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		st, err := r.SimulationControl(ctx, "stop")
		if err != nil || st.Preference != demo.Off || st.Running {
			t.Errorf("%+v %v", st, err)
		}
	}()
	close(release)
	<-done
	<-stopped
	r.Reconcile(ctx)
	e.assertStopped(t)
	if p, err := demo.Load(r.path); err != nil || p != demo.Off {
		t.Fatal(p, err)
	}
}

func TestDemoUnreadablePreferenceStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	e := &demoEngine{boot: "a", running: true}
	r := loadDemoReconciler(path, e)
	r.EngineSynced(context.Background(), "a")
	st, _ := r.SimulationStatus(context.Background())
	if st.Preference != demo.Off || st.Running || st.Error == "" {
		t.Fatal(st)
	}
}

func TestDemoEngineSyncRetriesWithoutConfigReplay(t *testing.T) {
	ctx := context.Background()
	e := &demoEngine{boot: "a"}
	r := loadDemoReconciler(filepath.Join(t.TempDir(), "demo.json"), e)
	if err := demo.Save(r.path, demo.On); err != nil {
		t.Fatal(err)
	}
	r.preference = demo.On
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applies := 0
	syncer := &engineSync{store: store, health: e, apply: func(context.Context) ([]string, error) { applies++; return nil, nil }, logger: zap.NewNop().Sugar(), demo: r}
	if !syncer.poll(ctx) {
		t.Fatal("initial sync")
	}
	e.mu.Lock()
	e.err = errors.New("offline")
	e.mu.Unlock()
	if st, err := r.SimulationControl(ctx, "stop"); err != nil || st.Error == "" {
		t.Fatal(st, err)
	}
	e.mu.Lock()
	e.err = nil
	e.mu.Unlock()
	if !syncer.poll(ctx) {
		t.Fatal("retry")
	}
	e.assertStopped(t)
	if applies != 1 {
		t.Fatal("unnecessary config apply", applies)
	}
}
