// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ids"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// RecordDPIEvents records semantic counters and appends events to telemetry.
// It does not charge packets or bytes; flow-end events use this path too.
func (e *Engine) RecordDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil {
		return
	}
	e.recordProtoStats(evs)
	if e.eventStore == nil {
		return
	}
	metrics.DPIEventsTotal.Add(float64(len(evs)))
	evs = normalizeDPIEvents(evs)
	bindEventConnections(state, evs)
	for _, ev := range evs {
		if c := ev.Connection; c != nil && c.Evidence != nil && !c.Verified() {
			c.LoseCorrelation(ev.Timestamp, anomaly.ModbusPairingTimeout)
		}
	}
	srcIP, dstIP := stateIPs(state)
	e.recordInventoryEvents(srcIP, dstIP, evs)
	e.recordLearnEvents(srcIP, dstIP, evs)
	e.recordAnomalyAlerts(state, pkt, srcIP, dstIP, evs)
	e.recordSignatureAlerts(state, pkt, evs)
	e.eventStore.Record(state, pkt, evs)
	e.recordEvaluatedIDSAlerts(state, pkt, evs)
}

func normalizeDPIEvents(evs []dpi.Event) []dpi.Event {
	for i := range evs {
		evs[i] = itdpi.MarkICS(evs[i])
	}
	return evs
}

func stateIPs(state *flow.State) (string, string) {
	if state == nil {
		return "", ""
	}
	return state.Key.SrcIP.String(), state.Key.DstIP.String()
}

func (e *Engine) recordInventoryEvents(srcIP, dstIP string, evs []dpi.Event) {
	if e == nil || e.inventory == nil || srcIP == "" || dstIP == "" {
		return
	}
	for _, ev := range evs {
		if learnableICSEvent(ev) {
			e.inventory.RecordEvent(srcIP, dstIP, ev)
		}
	}
}

func (e *Engine) recordLearnEvents(srcIP, dstIP string, evs []dpi.Event) {
	if e == nil || e.learner == nil || srcIP == "" || dstIP == "" || !e.hasLearnMode() {
		return
	}
	for _, ev := range evs {
		if learnableICSEvent(ev) && !hasInspectionFindings(ev) {
			e.learner.RecordEvent(srcIP, dstIP, ev)
		}
	}
}

func (e *Engine) recordAnomalyAlerts(state *flow.State, pkt *dpi.ParsedPacket, srcIP, dstIP string, evs []dpi.Event) {
	if e == nil || e.anomalyDetector == nil || srcIP == "" || dstIP == "" {
		return
	}
	for _, ev := range evs {
		if !isICSEvent(ev.Proto, ev.Kind) {
			continue
		}
		for _, a := range e.anomalyDetector.Check(srcIP, dstIP, ev) {
			if a.Type == "correlation_unavailable" && e.transport != nil {
				e.transport.authority.count("correlation_unavailable")
			}
			e.eventStore.Record(state, pkt, []dpi.Event{anomalyAlertFromEvent(ev, a)})
		}
	}
}

func anomalyAlertFromEvent(ev dpi.Event, a anomaly.Anomaly) dpi.Event {
	return dpi.Event{
		FlowID:     ev.FlowID,
		Connection: ev.Connection,
		Proto:      "ids",
		Kind:       "anomaly",
		Attributes: withDerivedIdentity(ev, map[string]any{
			"anomaly_type":       a.Type,
			"protocol":           a.Protocol,
			"severity":           a.Severity,
			"message":            a.Message,
			"source_ip":          a.SourceIP,
			"dest_ip":            a.DestIP,
			"correlation_status": a.Attributes["correlation_status"],
		}),
		Timestamp: a.Timestamp,
	}
}

func (e *Engine) recordSignatureAlerts(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil || e.sigEngine == nil {
		return
	}
	for _, ev := range evs {
		for _, m := range e.sigEngine.Match(ev) {
			e.eventStore.Record(state, pkt, []dpi.Event{signatureAlertFromMatch(ev, m)})
		}
	}
}

func signatureAlertFromMatch(ev dpi.Event, m signatures.Match) dpi.Event {
	return dpi.Event{
		FlowID:     ev.FlowID,
		Connection: ev.Connection,
		Proto:      "ids",
		Kind:       "signature_match",
		Attributes: withDerivedIdentity(ev, map[string]any{
			"signature_id": m.Signature.ID,
			"name":         m.Signature.Name,
			"severity":     m.Signature.Severity,
			"description":  m.Signature.Description,
		}),
		Timestamp: m.Timestamp,
	}
}

func (e *Engine) recordProtoStats(evs []dpi.Event) {
	if e == nil || e.stats == nil {
		return
	}
	for _, ev := range evs {
		e.stats.RecordEvent(ev)
	}
}

func (e *Engine) recordEvaluatedIDSAlerts(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	snap := e.ruleSnap.Load()
	if snap == nil || !snap.IDS.Enabled || len(snap.IDS.Rules) == 0 {
		return
	}
	eval := ids.New(snap.IDS)
	var alerts []dpi.Event
	for _, ev := range evs {
		alerts = append(alerts, eval.Evaluate(ev)...)
	}
	if len(alerts) == 0 {
		return
	}
	metrics.IDSAlertsTotal.Add(float64(len(alerts)))
	e.eventStore.Record(state, pkt, alerts)
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

// ProtoStats returns independent transport and DPI event counters per protocol.
func (e *Engine) ProtoStats() []stats.ProtoStats {
	if e == nil || e.stats == nil {
		return nil
	}
	return e.stats.Stats()
}

// TopTalkers returns the top N observed flows by byte count.
func (e *Engine) TopTalkers(n int) []stats.FlowStats {
	if e == nil || e.stats == nil {
		return nil
	}
	return e.stats.TopTalkers(n)
}

// AnomalyDetector returns the protocol anomaly detector.
func (e *Engine) AnomalyDetector() *anomaly.Detector {
	if e == nil {
		return nil
	}
	return e.anomalyDetector
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

func isICSEvent(proto, _ string) bool {
	proto = strings.ToLower(proto)
	return proto == "ics" || ics.Supported(proto)
}

// Evaluate applies the current rule snapshot to a simple context.
func (e *Engine) Evaluate(ctx rules.EvalContext) rules.Action {
	ev := e.ruleSnap.Evaluator()
	return ev.Evaluate(ctx)
}

// EvaluateVerdict returns a baseline verdict for the current snapshot.
// Callers that need access to the matched rule (e.g. to consult its
// per-rule Mode) should use EvaluateVerdictMatch directly.
func (e *Engine) EvaluateVerdict(ctx rules.EvalContext) verdict.Verdict {
	v, _ := e.EvaluateVerdictMatch(ctx)
	return v
}

// EvaluateVerdictMatch returns the baseline verdict and the matched rule
// entry (may be nil if no rule matched and the default action applies).
// Side-effect: appends a firewall.rule.hit event to the event store when
// the matched rule has Log:true.
func (e *Engine) EvaluateVerdictMatch(ctx rules.EvalContext) (verdict.Verdict, *rules.Entry) {
	return e.evaluateVerdictMatch(ctx, true)
}

// evaluateVerdictMatch is EvaluateVerdictMatch with the default action
// optional: when applyDefault is false, a context that matches no rule
// gets AllowContinue instead of the snapshot's default.
func (e *Engine) evaluateVerdictMatch(ctx rules.EvalContext, applyDefault bool) (verdict.Verdict, *rules.Entry) {
	start := time.Now()
	ev := e.ruleSnap.Evaluator()
	action, matched := ev.EvaluateMatch(ctx)
	if matched == nil && !applyDefault {
		action = rules.ActionAllow
	}
	v := verdict.FromRulesAction(action)
	metrics.RuleEvalDuration.Observe(time.Since(start).Seconds())
	metrics.VerdictsTotal.WithLabelValues(string(v.Action)).Inc()

	if matched != nil && matched.Log && e.eventStore != nil {
		attrs := map[string]any{
			"ruleId": matched.ID,
			"action": string(matched.Action),
		}
		if ctx.Proto != "" {
			attrs["proto"] = ctx.Proto
		}
		if ctx.Port != "" {
			attrs["port"] = ctx.Port
		}
		if ctx.SrcZone != "" {
			attrs["srcZone"] = ctx.SrcZone
		}
		if ctx.DstZone != "" {
			attrs["dstZone"] = ctx.DstZone
		}
		attrs = events.WithTags(attrs, ev.Tags(ctx))
		logEvent := events.Event{
			Kind:       "firewall.rule.hit",
			Timestamp:  time.Now().UTC(),
			Transport:  ctx.Proto,
			Attributes: attrs,
		}
		if ctx.SrcIP != nil {
			logEvent.SrcIP = ctx.SrcIP.String()
		}
		if ctx.DstIP != nil {
			logEvent.DstIP = ctx.DstIP.String()
		}
		if ctx.Port != "" {
			p, err := strconv.ParseUint(ctx.Port, 10, 16)
			if err == nil {
				logEvent.DstPort = uint16(p)
			}
		}
		e.eventStore.Append(logEvent)
	}
	return v, matched
}

// effectiveMode returns the mode that should govern verdict application
// for the matched rule, following the 3-tier resolution:
//
//	per-rule ICSPredicate.Mode > global Engine.dpiMode > "learn" (safe default)
//
// The safe default makes new deployments operate in monitor-only mode
// unless an operator explicitly opts into enforce — a real OT environment
// should never silently start blocking traffic just because containd is
// installed.
func (e *Engine) effectiveMode(matched *rules.Entry) string {
	ruleMode, globalMode := "", ""
	if matched != nil {
		ruleMode = matched.ICS.Mode
	}
	if e != nil {
		globalMode = e.dpiMode
	}
	return rules.EffectiveMode(ruleMode, globalMode)
}

// ApplyVerdict applies a verdict to dynamic enforcement primitives when
// enabled. A temporary block also resets the gated connections it covers.
func (e *Engine) ApplyVerdict(ctx context.Context, v verdict.Verdict, flow rules.EvalContext) error {
	if err := applyVerdict(ctx, e.updater, v, flow); err != nil || e.updater == nil {
		return err
	}
	if req, ok := gateCloseForVerdict(v, flow); ok {
		closeGated([]GateCloseRequest{req})
	}
	return nil
}

func applyVerdict(ctx context.Context, updater enforce.Updater, v verdict.Verdict, flow rules.EvalContext) error {
	if updater == nil {
		return nil
	}
	switch v.Action {
	case verdict.BlockHostTemp:
		ip := flow.SrcIP
		if ip == nil {
			ip = flow.DstIP
		}
		return updater.BlockHostTemp(ctx, ip, v.TTL)
	case verdict.BlockFlowTemp:
		return updater.BlockFlowTemp(ctx, flow.SrcIP, flow.DstIP, flow.Proto, flow.Port, v.TTL)
	default:
		return nil
	}
}

// RulesetStatus returns the status of the installed nftables ruleset with
// the live ICS coverage of its rules and its schedule planner's state.
func (e *Engine) RulesetStatus() RulesetStatus {
	if e == nil {
		return RulesetStatus{}
	}
	var st RulesetStatus
	if ptr := e.rulesetStatus.Load(); ptr != nil {
		st = *ptr
	}
	st.ICSCoverage = e.ICSCoverage()
	st.SchedulePlanner = e.gate.schedulePlanAt(e.gate.now())
	e.lifecycleMu.Lock()
	transport := e.transport
	detector := e.anomalyDetector
	e.lifecycleMu.Unlock()
	if transport != nil {
		status := transport.authority.snapshot()
		status.Modbus = detector.PairingStats()
		st.TransportIdentity = &status
	}
	return st
}

// recordApplyFailure adds a failed apply of the snapshot version to the
// status of the installed ruleset, which the failure left in place.
// Callers hold lifecycleMu.
func (e *Engine) recordApplyFailure(version string, err error) {
	var st RulesetStatus
	if prev := e.rulesetStatus.Load(); prev != nil {
		st = *prev
	}
	at := time.Now().UTC()
	st.Error, st.FailedSnapshotVersion, st.FailedAt = err.Error(), version, &at
	e.rulesetStatus.Store(&st)
}

// releaseRulesetStatus records that no ruleset is installed after the
// tables were deleted. The loaded snapshot stays, so the status is the one
// an engine without enforcement reports for it. Callers hold lifecycleMu.
func (e *Engine) releaseRulesetStatus() {
	prev := e.rulesetStatus.Load()
	if prev == nil {
		return
	}
	e.rulesetStatus.Store(&RulesetStatus{SnapshotVersion: prev.SnapshotVersion, AppliedAt: prev.AppliedAt})
}

// RevokeConnections installs operator revocations through the active enforcement
// backend and resets the gated connections they cover. Unsupported or
// disabled backends cannot report a successful kill.
func (e *Engine) RevokeConnections(ctx context.Context, entries []conntrack.Entry, scope string, ttl time.Duration) error {
	revoker, ok := e.Updater().(enforce.ConnectionRevoker)
	if !ok {
		return fmt.Errorf("connection revocation unavailable: nftables enforcement is not active")
	}
	if err := revoker.RevokeConnections(ctx, entries, scope, ttl); err != nil {
		return err
	}
	closeGated(gateCloseRequests(entries, scope))
	return nil
}
