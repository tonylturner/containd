// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

const dpiEnforceBlockTTL = 10 * time.Minute

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	capture         *capture.Manager
	ruleSnap        atomic.Pointer[rules.Snapshot]
	started         atomic.Bool
	compiler        *enforce.Compiler
	applier         enforce.Applier
	updater         enforce.Updater
	dpiMgr          *dpi.Manager
	eventStore      *events.Store
	rulesetStatus   atomic.Pointer[RulesetStatus]
	avSink          AVSink
	inspectAll      bool
	dpiEnabled      bool           // master DPI on/off
	dpiMode         string         // "learn" or "enforce"
	dpiExclusions   []DPIExclusion // IPs/domains excluded from DPI
	flowMu          sync.Mutex
	flows           map[string]*flow.State
	lastSweep       time.Time
	verdictCache    *VerdictCache
	inventory       *inventory.Inventory
	anomalyDetector *anomaly.Detector
	learner         *learn.Learner
	sigEngine       *signatures.Engine
	stats           *stats.Tracker
}

// RulesetStatus captures the last compiled/applied ruleset and any error.
type RulesetStatus struct {
	Ruleset   string    `json:"ruleset"`
	AppliedAt time.Time `json:"appliedAt"`
	Error     string    `json:"error,omitempty"`
}

type EnforceConfig struct {
	Enabled   bool
	TableName string
	Applier   enforce.Applier
	Updater   enforce.Updater
}

type Config struct {
	Capture         capture.Config
	Enforce         EnforceConfig
	InspectAll      bool
	DPIEnabled      bool            // master DPI toggle
	DPIMode         string          // "learn" or "enforce"
	DPIProtocols    map[string]bool // per-IT-protocol enable/disable
	DPIICSProtocols map[string]bool // per-ICS-protocol enable/disable
	DPIExclusions   []DPIExclusion  // IPs/domains excluded from DPI
}

// DPIExclusion represents an IP, CIDR, or domain excluded from DPI.
type DPIExclusion struct {
	Value string
	Type  string // "ip", "cidr", "domain"
}

func New(cfg Config) (*Engine, error) {
	capManager, err := capture.NewManager(cfg.Capture)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		capture:       capManager,
		inspectAll:    cfg.InspectAll,
		dpiEnabled:    cfg.DPIEnabled,
		dpiMode:       cfg.DPIMode,
		dpiExclusions: cfg.DPIExclusions,
		flows:         make(map[string]*flow.State),
		verdictCache:  NewVerdictCache(30*time.Second, 65536),
	}
	e.inventory = inventory.New()
	e.anomalyDetector = anomaly.New()
	e.learner = learn.New()
	e.sigEngine = signatures.New()
	e.sigEngine.LoadBuiltins()
	e.stats = stats.New()
	e.eventStore = events.NewStore(4096)
	e.dpiMgr = dpi.NewManager(FilterDecoders(cfg.DPIProtocols, cfg.DPIICSProtocols)...)
	if cfg.Enforce.Enabled {
		comp := enforce.NewCompiler()
		if cfg.Enforce.TableName != "" {
			comp.TableName = cfg.Enforce.TableName
		}
		e.compiler = comp
		if cfg.Enforce.Applier != nil {
			e.applier = cfg.Enforce.Applier
		} else {
			e.applier = enforce.NewNftApplier()
		}
		if cfg.Enforce.Updater != nil {
			e.updater = cfg.Enforce.Updater
		} else {
			e.updater = enforce.NewNftUpdater(comp.TableName)
		}
	}
	return e, nil
}

// Reconfigure replaces the engine's internal state from a freshly created
// engine without copying atomic or mutex fields (which are not safe to copy).
func (e *Engine) Reconfigure(fresh *Engine) {
	e.flowMu.Lock()
	e.capture = fresh.capture
	e.compiler = fresh.compiler
	e.applier = fresh.applier
	e.updater = fresh.updater
	e.dpiMgr = fresh.dpiMgr
	e.eventStore = fresh.eventStore
	e.inventory = fresh.inventory
	e.anomalyDetector = fresh.anomalyDetector
	e.sigEngine = fresh.sigEngine
	e.stats = fresh.stats
	e.avSink = fresh.avSink
	e.inspectAll = fresh.inspectAll
	e.dpiEnabled = fresh.dpiEnabled
	e.dpiMode = fresh.dpiMode
	e.dpiExclusions = fresh.dpiExclusions
	e.flows = fresh.flows
	e.lastSweep = fresh.lastSweep
	e.verdictCache = fresh.verdictCache
	e.flowMu.Unlock()
	e.started.Store(false)
}

func (e *Engine) Start(ctx context.Context) error {
	if e.started.Swap(true) {
		return nil
	}
	if err := e.capture.Start(ctx, e.handlePacket); err != nil {
		return err
	}
	// Periodically update the active goroutine gauge.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics.GoroutinesActive.Set(float64(runtime.NumGoroutine()))
			}
		}
	}()
	return nil
}

func (e *Engine) LoadRules(snap rules.Snapshot) {
	e.ruleSnap.Store(&snap)
}

// ApplyRules compiles and applies a snapshot to nftables (when enabled) and atomically swaps it.
// If enforcement is disabled, it simply swaps the snapshot.
func (e *Engine) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	var compiled string
	var applyErr error

	if e.compiler != nil {
		start := time.Now()
		compiled, applyErr = e.compiler.CompileFirewall(&snap)
		if applyErr != nil {
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
		if e.applier == nil {
			applyErr = errors.New("no applier configured")
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
		if applyErr = e.applier.Apply(ctx, compiled); applyErr != nil {
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
		metrics.NFTablesApplyDuration.Observe(time.Since(start).Seconds())
	}

	e.ruleSnap.Store(&snap)
	metrics.RulesCount.Set(float64(len(snap.Firewall)))
	e.setRulesetStatus(compiled, nil)
	return nil
}

func (e *Engine) CurrentRules() *rules.Snapshot {
	return e.ruleSnap.Load()
}

func (e *Engine) Interfaces() []string {
	return e.capture.Interfaces()
}

// DPI returns the selective DPI manager.
func (e *Engine) DPI() *dpi.Manager {
	return e.dpiMgr
}

// ShouldInspect returns true if this packet/flow should be sent through selective DPI.
// Phase-2 policy: any flow matching an ICS predicate or when native IDS is enabled.
// Steering is a no-op for now (capture always userspace in mock), but this keeps the hook stable.
func (e *Engine) ShouldInspect(state *flow.State, pkt *dpi.ParsedPacket) bool {
	if e == nil || pkt == nil {
		return false
	}
	if !e.dpiInspectionEnabled(state) {
		return false
	}
	if e.inspectAll {
		return true
	}
	snap := e.ruleSnap.Load()
	if !shouldInspectWithSnapshot(snap) {
		return false
	}
	if snap.IDS.Enabled {
		return true
	}
	for _, entry := range snap.Firewall {
		if shouldInspectFirewallEntry(entry, state, pkt) {
			return true
		}
	}
	return false
}

func (e *Engine) dpiInspectionEnabled(state *flow.State) bool {
	// Master DPI toggle — when explicitly disabled, skip DPI entirely.
	// Note: inspectAll (DPIMock/lab mode) overrides this for testing.
	if !e.dpiEnabled && !e.inspectAll {
		return false
	}
	if len(e.dpiExclusions) > 0 && state != nil && e.isExcluded(state) {
		return false
	}
	return true
}

func shouldInspectWithSnapshot(snap *rules.Snapshot) bool {
	return snap != nil && len(snap.Firewall) > 0 || (snap != nil && snap.IDS.Enabled)
}

func shouldInspectFirewallEntry(entry rules.Entry, state *flow.State, pkt *dpi.ParsedPacket) bool {
	if entry.ICS.Protocol == "" {
		return false
	}
	if len(entry.Protocols) > 0 {
		return entryMatchesProtocolPorts(entry, state, pkt)
	}
	return matchesICSDefaultPort(entry.ICS.Protocol, servicePort(state, pkt))
}

func entryMatchesProtocolPorts(entry rules.Entry, state *flow.State, pkt *dpi.ParsedPacket) bool {
	for _, p := range entry.Protocols {
		if protocolPortMatches(entry, p, state, pkt) {
			return true
		}
	}
	return false
}

func matchesICSDefaultPort(proto string, port uint16) bool {
	switch strings.ToLower(proto) {
	case "modbus":
		return port == 502
	case "dnp3":
		return port == 20000
	case "cip":
		return port == 44818 || port == 2222
	case "s7comm", "mms":
		return port == 102
	case "bacnet":
		return port == 47808
	case "opcua":
		return port == 4840
	default:
		return false
	}
}

func (e *Engine) handlePacket(pkt capture.Packet) {
	if e == nil {
		return
	}
	metrics.PacketsTotal.Inc()
	metrics.BytesTotal.Add(float64(len(pkt.Payload)))
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state := e.trackFlow(pkt, now)
	if state == nil {
		return
	}

	parsed := dpi.ParsedPacket{
		Payload: pkt.Payload,
		Proto:   pkt.Transport,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
	}

	flowHash := state.Key.Hash()
	shouldInspect := e.ShouldInspect(state, &parsed)
	if cached, ok := e.verdictCache.Get(flowHash); ok {
		// Permanent or temporary enforcement verdicts can short-circuit the flow.
		if cached.Action != verdict.AllowContinue {
			return
		}
		// For non-inspected flows we cache ALLOW to avoid re-checking every packet.
		// Inspectable flows must continue through DPI so later payload-bearing
		// packets are decoded; otherwise a SYN/ACK can suppress the whole flow.
		if !shouldInspect {
			return
		}
	}

	if !shouldInspect {
		// Cache an ALLOW verdict for non-inspected flows so we don't
		// re-evaluate ShouldInspect on every packet.
		e.verdictCache.Put(flowHash, verdict.Verdict{Action: verdict.AllowContinue})
		return
	}
	events, err := e.dpiMgr.OnPacket(state, &parsed)
	if err != nil {
		return
	}
	e.RecordDPIEvents(state, &parsed, events)

	if v, enforced := e.enforceDPIEvents(state, &parsed, events); enforced {
		e.verdictCache.Put(flowHash, v)
		return
	}
}

func (e *Engine) trackFlow(pkt capture.Packet, now time.Time) *flow.State {
	key := flow.Key{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
		Dir:     flow.DirForward,
	}
	hash := key.Hash()
	e.flowMu.Lock()
	state, ok := e.flows[hash]
	if !ok {
		state = flow.NewState(key, now)
		state.IdleTimeout = 5 * time.Minute
		e.flows[hash] = state
		metrics.FlowsActive.Inc()
	}
	state.Touch(uint64(len(pkt.Payload)), now)
	// Only check if sweep is due under the existing lock; do the actual
	// sweep outside the critical path if needed.
	needsSweep := now.Sub(e.lastSweep) >= 30*time.Second
	if needsSweep {
		e.lastSweep = now
	}
	e.flowMu.Unlock()

	if needsSweep {
		e.sweepFlows(now)
	}
	return state
}

func (e *Engine) sweepFlows(now time.Time) {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	for k, st := range e.flows {
		if st == nil || st.Expired(now) {
			delete(e.flows, k)
			metrics.FlowsActive.Dec()
		}
	}
}
