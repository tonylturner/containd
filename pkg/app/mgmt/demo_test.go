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
	"github.com/tonylturner/containd/pkg/cp/demo"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
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

type demoCounter struct {
	sample     wire.CounterSample
	background uint64
}

func (r *demoCounter) TelemetryCounters(context.Context) (wire.CounterSnapshot, error) {
	return wire.CounterSnapshot{Samples: []wire.CounterSample{
		r.sample,
		{Metric: wire.IfaceRxBytes, Origin: wire.OriginReal, Epoch: "kernel", Value: r.background},
		{Metric: wire.EventsClass, Origin: wire.OriginReal, Epoch: "engine", Dims: map[string]string{"source": "engine", "class": "modbus_write"}, Value: r.background},
		{Metric: wire.EventsTotal, Origin: wire.OriginReal, Epoch: "engine", Dims: map[string]string{"source": "engine"}, Value: r.background},
		{Metric: wire.EventsClass, Origin: wire.OriginReal, Epoch: "mgmt", Dims: map[string]string{"source": "services", "class": "ids_alert"}, Value: r.background},
	}}, nil
}

func TestDemoAutoSamplerAndUpgrade(t *testing.T) {
	for _, sample := range []wire.CounterSample{
		{Metric: wire.ConduitBytes},
		{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "ids_alert"}},
		{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "av_detection"}},
		{Metric: wire.EventsClass, Dims: map[string]string{"source": "engine", "class": "av_block"}},
	} {
		t.Run(string(sample.Metric)+"/"+sample.Dims["class"], func(t *testing.T) {
			testDemoAutoSamplerAndRestart(t, sample)
		})
	}
}

func testDemoAutoSamplerAndRestart(t *testing.T, sample wire.CounterSample) {
	t.Helper()
	for _, upgraded := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgraded"}[upgraded], func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			e := &demoEngine{boot: "a"}
			r := loadDemoReconciler(filepath.Join(dir, "demo.json"), e)
			storePath := filepath.Join(dir, "telemetry.db")
			store, err := history.Open(storePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			r.history = store
			sample.Origin, sample.Epoch, sample.Value = wire.OriginReal, "engine", 100
			counters := &demoCounter{sample: sample}
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
			counters.background++
			if upgraded {
				counters.sample.Value++
			}
			tick(1)
			st, err := r.SimulationStatus(ctx)
			if err != nil || st.Preference != demo.Auto || st.Running == upgraded {
				t.Fatal(st, err)
			}
			counters.sample.Value++
			counters.background++
			tick(2)
			st, _ = r.SimulationStatus(ctx)
			if st.Running || st.Reason != "real traffic observed" {
				t.Fatal(st)
			}
			tick(3)
			e.reboot("b")
			r.EngineSynced(ctx, "b")
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = history.Open(storePath)
			if err != nil {
				t.Fatal(err)
			}
			r = loadDemoReconciler(r.path, e)
			r.history = store
			r.EngineSynced(ctx, "b")
			st, _ = r.SimulationStatus(ctx)
			if st.Running || st.Reason != "real traffic observed" {
				t.Fatal(st)
			}
			// A new sampler has no observed interval yet. Once it is ready,
			// retained activity still prevents auto from restarting.
			sampler = history.NewSampler(store, counters)
			sampler.AfterTick = r.Reconcile
			tick(4)
			tick(5)
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

func TestDemoReconcileRetainsStoppedPreferenceAcrossReset(t *testing.T) {
	ctx := context.Background()
	e := &demoEngine{boot: "a"}
	r := loadDemoReconciler(filepath.Join(t.TempDir(), "demo.json"), e)
	if err := demo.Save(r.path, demo.On); err != nil {
		t.Fatal(err)
	}
	r.preference = demo.On
	r.EngineSynced(ctx, "a")
	e.mu.Lock()
	e.err = errors.New("offline")
	e.mu.Unlock()
	if st, err := r.SimulationControl(ctx, "stop"); err != nil || st.Error == "" {
		t.Fatal(st, err)
	}
	e.mu.Lock()
	e.err = nil
	e.mu.Unlock()
	r.Reconcile(ctx)
	e.assertStopped(t)
	r.Reset(ctx)
	if r.synced {
		t.Fatal("reset retained stale demo eligibility")
	}
}
