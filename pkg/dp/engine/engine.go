// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"runtime"
	"strconv"
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
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/bacnet"
	"github.com/tonylturner/containd/pkg/dp/ics/iec61850"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/ics/opcua"
	"github.com/tonylturner/containd/pkg/dp/ics/s7comm"
	"github.com/tonylturner/containd/pkg/dp/ids"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	capture       *capture.Manager
	ruleSnap      atomic.Pointer[rules.Snapshot]
	started       atomic.Bool
	compiler      *enforce.Compiler
	applier       enforce.Applier
	updater       enforce.Updater
	dpiMgr        *dpi.Manager
	eventStore    *events.Store
	rulesetStatus atomic.Pointer[RulesetStatus]
	avSink        AVSink
	inspectAll    bool
	flowMu        sync.Mutex
	flows         map[string]*flow.State
	lastSweep     time.Time
	verdictCache     *VerdictCache
	inventory        *inventory.Inventory
	anomalyDetector  *anomaly.Detector
	learner          *learn.Learner
	sigEngine        *signatures.Engine
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
	Capture    capture.Config
	Enforce    EnforceConfig
	InspectAll bool
}

func New(cfg Config) (*Engine, error) {
	capManager, err := capture.NewManager(cfg.Capture)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		capture:      capManager,
		inspectAll:   cfg.InspectAll,
		flows:        make(map[string]*flow.State),
		verdictCache: NewVerdictCache(30*time.Second, 65536),
	}
	e.inventory = inventory.New()
	e.anomalyDetector = anomaly.New()
	e.learner = learn.New()
	e.sigEngine = signatures.New()
	e.sigEngine.LoadBuiltins()
	e.eventStore = events.NewStore(4096)
	e.dpiMgr = dpi.NewManager(
		modbus.NewDecoder(),
		dnp3.NewDecoder(),
		cip.NewDecoder(),
		iec61850.NewMMSDecoder(),   // MMS before S7comm: both use port 102, MMS returns nil for S7comm traffic
		s7comm.NewDecoder(),
		bacnet.NewDecoder(),
		opcua.NewDecoder(),
		iec61850.NewGOOSEDecoder(), // GOOSE: Layer 2 placeholder, Supports returns false until raw Ethernet capture
		itdpi.NewDNSDecoder(),
		itdpi.NewTLSDecoder(),
		itdpi.NewHTTPDecoder(),
		itdpi.NewSSHDecoder(),
		itdpi.NewSMBDecoder(),
		itdpi.NewICSMarker(),
		itdpi.NewPortDetector(),
	)
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
	e.avSink = fresh.avSink
	e.inspectAll = fresh.inspectAll
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
	if e.inspectAll {
		return true
	}
	snap := e.ruleSnap.Load()
	if snap == nil {
		return false
	}
	// If IDS is enabled, inspect everything for now (future: selective per IDS rule proto).
	if snap.IDS.Enabled {
		return true
	}
	if len(snap.Firewall) == 0 {
		return false
	}
	for _, entry := range snap.Firewall {
		if entry.ICS.Protocol == "" {
			continue
		}
		// If explicit protocols exist, require port match.
		if len(entry.Protocols) > 0 {
			for _, p := range entry.Protocols {
				if protocolPortMatches(entry, p, state, pkt) {
					return true
				}
			}
			continue
		}
		// Default port heuristics by ICS protocol.
		switch strings.ToLower(entry.ICS.Protocol) {
		case "modbus":
			if servicePort(state, pkt) == 502 {
				return true
			}
		case "dnp3":
			if servicePort(state, pkt) == 20000 {
				return true
			}
		case "cip":
			port := servicePort(state, pkt)
			if port == 44818 || port == 2222 {
				return true
			}
		case "s7comm", "mms":
			if servicePort(state, pkt) == 102 {
				return true
			}
		case "bacnet":
			if servicePort(state, pkt) == 47808 {
				return true
			}
		case "opcua":
			if servicePort(state, pkt) == 4840 {
				return true
			}
		}
	}
	return false
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

	// Check verdict cache — if this flow already has a cached verdict,
	// skip DPI re-inspection. This is critical for NFQUEUE performance.
	flowHash := state.Key.Hash()
	if _, cached := e.verdictCache.Get(flowHash); cached {
		return
	}

	parsed := dpi.ParsedPacket{
		Payload: pkt.Payload,
		Proto:   pkt.Transport,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
	}
	if !e.ShouldInspect(state, &parsed) {
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

	// Cache the inspected verdict. For now we ACCEPT after inspection;
	// the DPI/IDS path may override via dynamic enforcement (nftables sets).
	e.verdictCache.Put(flowHash, verdict.Verdict{Action: verdict.AllowContinue, Reason: "inspected"})
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

func protocolPortMatches(entry rules.Entry, p rules.Protocol, state *flow.State, pkt *dpi.ParsedPacket) bool {
	if p.Name != "" && !strings.EqualFold(p.Name, pkt.Proto) {
		return false
	}
	port := servicePort(state, pkt)
	if p.Port == "" {
		// Any port for that transport.
		return true
	}
	min, max, ok := parsePortRange(p.Port)
	if !ok {
		return false
	}
	return port >= min && port <= max
}

func servicePort(state *flow.State, pkt *dpi.ParsedPacket) uint16 {
	if state != nil && state.Key.Dir == flow.DirReverse {
		return pkt.SrcPort
	}
	return pkt.DstPort
}

func parsePortRange(s string) (uint16, uint16, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	if !strings.Contains(s, "-") {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 65535 {
			return 0, 0, false
		}
		u := uint16(v)
		return u, u, true
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 0 || hi < 0 || lo > 65535 || hi > 65535 {
		return 0, 0, false
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return uint16(lo), uint16(hi), true
}

// RecordDPIEvents appends events to the telemetry store.
func (e *Engine) RecordDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil || e.eventStore == nil {
		return
	}
	metrics.DPIEventsTotal.Add(float64(len(evs)))
	for i := range evs {
		evs[i] = itdpi.MarkICS(evs[i])
	}
	// Record ICS events into the asset inventory.
	if e.inventory != nil && state != nil {
		srcIP := state.Key.SrcIP.String()
		dstIP := state.Key.DstIP.String()
		for _, ev := range evs {
			if isICSEvent(ev.Proto, ev.Kind) {
				e.inventory.RecordEvent(srcIP, dstIP, ev)
			}
		}
	}
	// Record ICS events into the learner when learn mode is active.
	if e.learner != nil && state != nil && e.hasLearnMode() {
		srcIP := state.Key.SrcIP.String()
		dstIP := state.Key.DstIP.String()
		for _, ev := range evs {
			if isICSEvent(ev.Proto, ev.Kind) {
				e.learner.RecordEvent(srcIP, dstIP, ev)
			}
		}
	}
	// Run anomaly detection on ICS events.
	if e.anomalyDetector != nil && state != nil {
		srcIP := state.Key.SrcIP.String()
		dstIP := state.Key.DstIP.String()
		for _, ev := range evs {
			if !isICSEvent(ev.Proto, ev.Kind) {
				continue
			}
			anomalies := e.anomalyDetector.Check(srcIP, dstIP, ev)
			for _, a := range anomalies {
				alert := dpi.Event{
					FlowID: ev.FlowID,
					Proto:  "ids",
					Kind:   "anomaly",
					Attributes: map[string]any{
						"anomaly_type": a.Type,
						"protocol":     a.Protocol,
						"severity":     a.Severity,
						"message":      a.Message,
						"source_ip":    a.SourceIP,
						"dest_ip":      a.DestIP,
					},
					Timestamp: a.Timestamp,
				}
				e.eventStore.Record(state, pkt, []dpi.Event{alert})
			}
		}
	}
	// Check signature engine for known ICS attack patterns.
	if e.sigEngine != nil {
		for _, ev := range evs {
			matches := e.sigEngine.Match(ev)
			for _, m := range matches {
				alert := dpi.Event{
					FlowID: ev.FlowID,
					Proto:  "ids",
					Kind:   "signature_match",
					Attributes: map[string]any{
						"signature_id": m.Signature.ID,
						"name":         m.Signature.Name,
						"severity":     m.Signature.Severity,
						"description":  m.Signature.Description,
					},
					Timestamp: m.Timestamp,
				}
				e.eventStore.Record(state, pkt, []dpi.Event{alert})
			}
		}
	}
	// Push HTTP previews to AV sink (if configured).
	if e.avSink != nil {
		src, dst := srcDestStrings(state)
		for _, ev := range evs {
			if ev.Proto != "http" {
				continue
			}
			if ev.Kind != "request" && ev.Kind != "response" {
				continue
			}
			preview, _ := ev.Attributes["preview"].([]byte)
			hash, _ := ev.Attributes["hash"].(string)
			if len(preview) == 0 {
				continue
			}
			ics := isICSEvent(ev.Proto, ev.Kind)
			task := AVScanTask{
				Hash:      hash,
				Direction: ev.Kind,
				Proto:     "http",
				Source:    src,
				Dest:      dst,
				FlowID:    ev.FlowID,
				Preview:   preview,
				ICS:       ics,
			}
			e.avSink.EnqueueAVScan(context.Background(), task)
			// Drop preview from telemetry to avoid large payloads.
			delete(ev.Attributes, "preview")
		}
	}
	e.eventStore.Record(state, pkt, evs)
	// Evaluate IDS rules over DPI events and record alerts.
	snap := e.ruleSnap.Load()
	if snap != nil && snap.IDS.Enabled && len(snap.IDS.Rules) > 0 {
		eval := ids.New(snap.IDS)
		var alerts []dpi.Event
		for _, ev := range evs {
			alerts = append(alerts, eval.Evaluate(ev)...)
		}
		if len(alerts) > 0 {
			metrics.IDSAlertsTotal.Add(float64(len(alerts)))
			e.eventStore.Record(state, pkt, alerts)
		}
	}
}

// VerdictCache returns the flow verdict cache.
func (e *Engine) VerdictCache() *VerdictCache {
	if e == nil {
		return nil
	}
	return e.verdictCache
}

// Events returns the telemetry event store.
func (e *Engine) Events() *events.Store {
	return e.eventStore
}

// Inventory returns the ICS asset inventory.
func (e *Engine) Inventory() *inventory.Inventory {
	if e == nil {
		return nil
	}
	return e.inventory
}

// AnomalyDetector returns the protocol anomaly detector.
func (e *Engine) AnomalyDetector() *anomaly.Detector {
	if e == nil {
		return nil
	}
	return e.anomalyDetector
}

// AVSink returns the currently configured AV sink, if any.
func (e *Engine) AVSink() AVSink {
	if e == nil {
		return nil
	}
	return e.avSink
}

// Updater returns the dynamic nftables updater when enforcement is enabled.
func (e *Engine) Updater() enforce.Updater {
	if e == nil {
		return nil
	}
	return e.updater
}

// Learner returns the ICS traffic learner.
func (e *Engine) Learner() *learn.Learner {
	if e == nil {
		return nil
	}
	return e.learner
}

// SignatureEngine returns the ICS signature matching engine.
func (e *Engine) SignatureEngine() *signatures.Engine {
	if e == nil {
		return nil
	}
	return e.sigEngine
}

// hasLearnMode returns true if any firewall entry has Mode == "learn".
func (e *Engine) hasLearnMode() bool {
	snap := e.ruleSnap.Load()
	if snap == nil {
		return false
	}
	for _, entry := range snap.Firewall {
		if strings.EqualFold(entry.ICS.Mode, "learn") {
			return true
		}
	}
	return false
}

func isICSEvent(proto, kind string) bool {
	switch strings.ToLower(proto) {
	case "modbus", "dnp3", "iec104", "s7", "s7comm", "cip", "bacnet", "opcua", "mms", "goose", "ics":
		return true
	}
	_ = kind
	return false
}

// Evaluate applies the current rule snapshot to a simple context.
func (e *Engine) Evaluate(ctx rules.EvalContext) rules.Action {
	snap := e.ruleSnap.Load()
	ev := rules.NewEvaluator(snap)
	return ev.Evaluate(ctx)
}

// EvaluateVerdict returns a baseline verdict for the current snapshot.
// DPI/IDS paths will later override this for selective inspection policies.
func (e *Engine) EvaluateVerdict(ctx rules.EvalContext) verdict.Verdict {
	start := time.Now()
	v := verdict.FromRulesAction(e.Evaluate(ctx))
	metrics.RuleEvalDuration.Observe(time.Since(start).Seconds())
	metrics.VerdictsTotal.WithLabelValues(string(v.Action)).Inc()
	return v
}

// ApplyVerdict applies a verdict to dynamic enforcement primitives when enabled.
// It is safe to call even when enforcement is disabled.
func (e *Engine) ApplyVerdict(ctx context.Context, v verdict.Verdict, flow rules.EvalContext) error {
	if e.updater == nil {
		return nil
	}
	switch v.Action {
	case verdict.BlockHostTemp:
		ip := flow.SrcIP
		if ip == nil {
			ip = flow.DstIP
		}
		return e.updater.BlockHostTemp(ctx, ip, v.TTL)
	case verdict.BlockFlowTemp:
		return e.updater.BlockFlowTemp(ctx, flow.SrcIP, flow.DstIP, flow.Proto, flow.Port, v.TTL)
	default:
		return nil
	}
}

// RulesetStatus returns the last compiled/applied nftables ruleset snapshot.
func (e *Engine) RulesetStatus() RulesetStatus {
	if e == nil {
		return RulesetStatus{}
	}
	ptr := e.rulesetStatus.Load()
	if ptr == nil {
		return RulesetStatus{}
	}
	return *ptr
}

func (e *Engine) setRulesetStatus(ruleset string, err error) {
	st := &RulesetStatus{
		Ruleset:   ruleset,
		AppliedAt: time.Now().UTC(),
	}
	if err != nil {
		st.Error = err.Error()
	}
	e.rulesetStatus.Store(st)
}
