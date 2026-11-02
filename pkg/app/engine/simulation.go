// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/replay"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

type simulationStatus struct {
	Running    bool   `json:"running"`
	RunID      string `json:"runId"`
	Loops      uint64 `json:"loops"`
	CaptureSet string `json:"captureSet"`
	Capture    string `json:"capture"`
	Error      string `json:"error"`
}

// simulationManager serializes replay lifecycle and policy updates. Workers
// never acquire mu, so cancellation and joins never wait under live policy
// locks (nor require a worker to acquire the coordinator lock).
type simulationManager struct {
	dpEngine *engine.Engine

	mu     sync.Mutex
	wanted bool
	policy *rules.Snapshot
	config config.DataPlaneConfig
	active *simulationWorker
	state  simulationStatus
}

type simulationWorker struct {
	detached *engine.Detached
	counters *replay.Counters
	cancel   context.CancelFunc
	done     chan struct{}
	expired  chan struct{}
	err      error // published by closing done
	baseline wire.EventCounts
}

func (sm *simulationManager) start() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.refreshLocked()
	if sm.active != nil {
		return
	}
	sm.wanted = true
	sm.startLocked()
}

func (sm *simulationManager) startLocked() {
	sm.state = simulationStatus{RunID: rand.Text()}
	if sm.policy == nil {
		sm.state.Error = "waiting for policy"
		return
	}
	dir := os.Getenv("CONTAIND_DEMO_CAPTURES")
	if dir == "" {
		dir = replay.DefaultCaptureDir
	}
	set, err := replay.LoadCaptureSet(dir)
	if err != nil {
		sm.state.Error = "demo captures unavailable: " + err.Error()
		return
	}
	sm.state.CaptureSet = fmt.Sprintf("containd-demo/%d", set.Version)
	topo := replay.NewTopology(sm.policy.Zones)
	// Validate before reporting running; Run also checks its own inputs.
	for _, cap := range set.Captures {
		from, to := topo.ResolveZones(cap.Family)
		if from == "" || to == "" {
			sm.state.Error = "demo topology unavailable: no non-mgmt zones"
			return
		}
		for _, zone := range []string{from, to} {
			if _, err := topo.ZoneAddresses(topo.Interface(zone)); err != nil {
				sm.state.Error = "demo topology unavailable: " + err.Error()
				return
			}
		}
	}
	var exclusions []engine.DPIExclusion
	for _, ex := range sm.config.DPIExclusions {
		exclusions = append(exclusions, engine.DPIExclusion{Value: ex.Value, Type: ex.Type})
	}
	detached, err := engine.NewDetached(engine.DetachedConfig{
		Events:       sm.dpEngine.Events().Writer(wire.OriginDemo),
		DPIProtocols: sm.config.DPIProtocols, DPIICSProtocols: sm.config.DPIICSProtocols,
		DPIICSParsing: sm.config.DPIICSParsing, DPIExclusions: exclusions,
		ZoneAddresses: topo.ZoneAddresses,
	})
	if err != nil {
		sm.state.Error = err.Error()
		return
	}
	detached.LoadRules(replay.DeriveDemoSnapshot(sm.policy, sm.policy.Zones))
	detached.SetSignatures(sm.dpEngine.SignatureEngine().List())
	ctx, cancel := context.WithCancel(context.Background())
	w := &simulationWorker{
		detached: detached, counters: &replay.Counters{}, cancel: cancel,
		done: make(chan struct{}), expired: make(chan struct{}), baseline: sm.demoEvents(),
	}
	sm.active = w
	sm.state.Running = true
	go func() {
		defer close(w.expired)
		detached.Run(ctx)
	}()
	go func() {
		defer close(w.done)
		defer cancel()
		w.err = replay.Run(ctx, set, topo, detached, w.counters)
	}()
}

// joinLocked is the publication barrier: both Run calls have returned and
// Close has joined any detached work before Stop or a replacement returns.
func (sm *simulationManager) joinLocked() {
	w := sm.active
	if w == nil {
		return
	}
	w.cancel()
	<-w.done
	<-w.expired
	w.detached.Close()
	progress := w.counters.Status()
	sm.state.Loops, sm.state.Capture = progress.Loops, progress.Capture
	sm.state.Running = false
	if w.err != nil && !errors.Is(w.err, context.Canceled) {
		sm.state.Error = w.err.Error()
	}
	sm.active = nil
}

func (sm *simulationManager) refreshLocked() {
	if sm.active != nil {
		select {
		case <-sm.active.done:
			sm.joinLocked()
		default:
		}
	}
}

func (sm *simulationManager) stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.wanted = false
	sm.joinLocked()
	sm.state.Error = ""
}

func (sm *simulationManager) status() simulationStatus {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.refreshLocked()
	if sm.active != nil {
		progress := sm.active.counters.Status()
		sm.state.Loops, sm.state.Capture = progress.Loops, progress.Capture
	}
	return sm.state
}

func (sm *simulationManager) reconfigure(cfg config.DataPlaneConfig, apply func() error) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	// Serialize live signature-engine replacement with Start and CRUD, but
	// wait for replay only after apply has released the live engine's locks.
	if err := apply(); err != nil {
		return err
	}
	sm.config = cfg
	sm.joinLocked()
	if sm.wanted {
		sm.startLocked()
	}
	return nil
}

func (sm *simulationManager) loadRules(snap rules.Snapshot) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.refreshLocked()
	changed := sm.policy != nil && !slices.Equal(sm.policy.Zones, snap.Zones)
	sm.policy = &snap
	if changed {
		sm.joinLocked()
	}
	if sm.active != nil {
		sm.active.detached.LoadRules(replay.DeriveDemoSnapshot(&snap, snap.Zones))
	} else if sm.wanted {
		sm.startLocked()
	}
}

func (sm *simulationManager) setParsing(modes map[string]string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.config.DPIICSParsing = maps.Clone(modes)
	if sm.active != nil {
		sm.active.detached.SetICSParsing(modes)
	}
}

// Caller holds mu across the live CRUD and the detached publication.
func (sm *simulationManager) setSignaturesLocked(defs []signatures.Signature) {
	if sm.active != nil {
		sm.active.detached.SetSignatures(defs)
	}
}

func (sm *simulationManager) demoEvents() wire.EventCounts {
	for _, counts := range sm.dpEngine.Events().TelemetryCounts() {
		if counts.Origin == wire.OriginDemo {
			return counts
		}
	}
	return wire.EventCounts{}
}

func (sm *simulationManager) samples() []wire.CounterSample {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.refreshLocked()
	w := sm.active
	if w == nil {
		return nil
	}
	out := w.counters.Samples(sm.state.RunID)
	add := func(metric wire.Metric, dims map[string]string, value uint64) {
		out = append(out, wire.CounterSample{Metric: metric, Dims: dims, Value: value, Epoch: sm.state.RunID, Origin: wire.OriginDemo})
	}
	for _, p := range w.detached.Stats().Stats() {
		dims := map[string]string{"protocol": p.Protocol}
		if p.PacketCount < 0 || p.ByteCount < 0 {
			sm.joinLocked()
			sm.state.Error = "demo protocol counter overflow"
			return nil
		}
		add(wire.ProtoPackets, dims, uint64(p.PacketCount))
		add(wire.ProtoBytes, dims, uint64(p.ByteCount))
	}
	counts := sm.demoEvents()
	add(wire.EventsTotal, map[string]string{"source": "engine"}, counts.Total-w.baseline.Total)
	for _, class := range []wire.EventClass{wire.ClassIDSAlert, wire.ClassAVDetection, wire.ClassAVBlock, wire.ClassModbusWrite} {
		add(wire.EventsClass, map[string]string{"source": "engine", "class": string(class)}, counts.Classes[class]-w.baseline.Classes[class])
	}
	return out
}

func simulationHandler(sm *simulationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
			var req struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			switch req.Action {
			case "start":
				sm.start()
			case "stop":
				sm.stop()
			default:
				http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, sm.status())
	}
}
