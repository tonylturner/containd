// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	engineclient "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/demo"
)

type demoHistory interface {
	DemoState(context.Context) (bool, bool, error)
}

// demoReconciler owns all intent and delivery under one lock. A delayed tick
// never carries a desired state computed before a newer operator Stop.
type demoReconciler struct {
	mu              sync.Mutex
	path            string
	preference      demo.Preference
	preferenceError error
	engine          httpapi.SimulationClient
	health          httpapi.RuntimeHealthClient
	history         demoHistory
	synced          bool
	bootID          string
}

func newDemoReconciler(engine httpapi.EngineClient) *demoReconciler {
	return loadDemoReconciler(filepath.Join(filepath.Dir(configDBPath()), "demo.json"), engine)
}

func loadDemoReconciler(path string, engine any) *demoReconciler {
	p, err := demo.Load(path)
	r := &demoReconciler{path: path, preference: p, preferenceError: err}
	r.engine, _ = engine.(httpapi.SimulationClient)
	r.health, _ = engine.(httpapi.RuntimeHealthClient)
	return r
}

func (r *demoReconciler) SimulationStatus(ctx context.Context) (demo.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked(ctx), nil
}

func (r *demoReconciler) SimulationControl(ctx context.Context, action string) (demo.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := demo.Off
	if action == "start" {
		p = demo.On
	} else if action != "stop" {
		return demo.Status{}, fmt.Errorf("invalid demo action %q", action)
	}
	if err := demo.Save(r.path, p); err != nil {
		return demo.Status{}, err
	}
	r.preference, r.preferenceError = p, nil
	return r.reconcileLocked(ctx), nil
}

func (r *demoReconciler) Reconcile(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.reconcileLocked(ctx)
}

// EngineSynced is called only after the running configuration was applied.
func (r *demoReconciler) EngineSynced(ctx context.Context, bootID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.synced, r.bootID = true, bootID
	_ = r.reconcileLocked(ctx)
}

func (r *demoReconciler) desiredLocked(ctx context.Context) (bool, string, error) {
	if r.preferenceError != nil {
		return false, "", r.preferenceError
	}
	switch r.preference {
	case demo.On:
		return true, "", nil
	case demo.Off:
		return false, "", nil
	}
	if r.history == nil {
		return false, "", fmt.Errorf("telemetry store unavailable")
	}
	observed, active, err := r.history.DemoState(ctx)
	if err != nil {
		return false, "", fmt.Errorf("telemetry unavailable: %w", err)
	}
	if active {
		return false, "real traffic observed", nil
	}
	if !observed {
		return false, "waiting for telemetry interval", nil
	}
	return true, "", nil
}

func (r *demoReconciler) baseLocked(ctx context.Context) (demo.Status, bool) {
	desired, reason, err := r.desiredLocked(ctx)
	st := demo.Status{Preference: r.preference, Reason: reason}
	if err != nil {
		st.Error = err.Error()
	}
	return st, desired
}

func engineDemoStatus(st demo.Status, actual engineclient.SimulationStatus) demo.Status {
	st.Running, st.Loops, st.CaptureSet, st.Capture = actual.Running, actual.Loops, actual.CaptureSet, actual.Capture
	if actual.Error != "" {
		if st.Error != "" {
			st.Error += "; "
		}
		st.Error += actual.Error
	}
	return st
}

func unreachable(st demo.Status, err error) demo.Status {
	st.Reason = "engine unreachable"
	if st.Error != "" {
		st.Error += "; "
	}
	st.Error += "engine unreachable: " + err.Error()
	return st
}

func (r *demoReconciler) statusLocked(ctx context.Context) demo.Status {
	st, _ := r.baseLocked(ctx)
	if r.engine == nil {
		return unreachable(st, fmt.Errorf("simulation unavailable"))
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	actual, err := r.engine.SimulationStatus(ctx)
	if err != nil {
		return unreachable(st, err)
	}
	return engineDemoStatus(st, actual)
}

func (r *demoReconciler) reconcileLocked(ctx context.Context) demo.Status {
	st, desired := r.baseLocked(ctx)
	if r.engine == nil {
		return unreachable(st, fmt.Errorf("simulation unavailable"))
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Detect a new boot even if a sampler tick wins the race with engine sync.
	// No Start is delivered until that boot has received running configuration.
	if r.health != nil {
		health, err := r.health.RuntimeHealth(ctx)
		if err != nil {
			return unreachable(st, err)
		}
		if !r.synced || health.BootID != r.bootID {
			st.Reason = "waiting for engine config sync"
			actual, err := r.engine.SimulationStatus(ctx)
			if err != nil {
				return unreachable(st, err)
			}
			return engineDemoStatus(st, actual)
		}
	}
	if !r.synced {
		st.Reason = "waiting for engine config sync"
		return st
	}
	action := "stop"
	if desired {
		action = "start"
	}
	actual, err := r.engine.SimulationControl(ctx, action)
	if err != nil {
		return unreachable(st, err)
	}
	return engineDemoStatus(st, actual)
}
