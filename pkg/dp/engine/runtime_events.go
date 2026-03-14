// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ids"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// RecordDPIEvents appends events to the telemetry store.
func (e *Engine) RecordDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil || e.eventStore == nil {
		return
	}
	metrics.DPIEventsTotal.Add(float64(len(evs)))
	evs = normalizeDPIEvents(evs)
	srcIP, dstIP := stateIPs(state)
	e.recordInventoryEvents(srcIP, dstIP, evs)
	e.recordLearnEvents(srcIP, dstIP, evs)
	e.recordAnomalyAlerts(state, pkt, srcIP, dstIP, evs)
	e.recordSignatureAlerts(state, pkt, evs)
	e.enqueueAVTasks(state, evs)
	e.recordProtoStats(srcIP, dstIP, pkt, evs)
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
		if isICSEvent(ev.Proto, ev.Kind) {
			e.inventory.RecordEvent(srcIP, dstIP, ev)
		}
	}
}

func (e *Engine) recordLearnEvents(srcIP, dstIP string, evs []dpi.Event) {
	if e == nil || e.learner == nil || srcIP == "" || dstIP == "" || !e.hasLearnMode() {
		return
	}
	for _, ev := range evs {
		if isICSEvent(ev.Proto, ev.Kind) {
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
			e.eventStore.Record(state, pkt, []dpi.Event{anomalyAlertFromEvent(ev, a)})
		}
	}
}

func anomalyAlertFromEvent(ev dpi.Event, a anomaly.Anomaly) dpi.Event {
	return dpi.Event{
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
}

func (e *Engine) enqueueAVTasks(state *flow.State, evs []dpi.Event) {
	if e == nil || e.avSink == nil {
		return
	}
	src, dst := srcDestStrings(state)
	for _, ev := range evs {
		if !isAVScanCandidate(ev) {
			continue
		}
		preview, _ := ev.Attributes["preview"].([]byte)
		hash, _ := ev.Attributes["hash"].(string)
		if len(preview) == 0 {
			continue
		}
		e.avSink.EnqueueAVScan(context.Background(), AVScanTask{
			Hash:      hash,
			Direction: ev.Kind,
			Proto:     "http",
			Source:    src,
			Dest:      dst,
			FlowID:    ev.FlowID,
			Preview:   preview,
			ICS:       isICSEvent(ev.Proto, ev.Kind),
		})
		delete(ev.Attributes, "preview")
	}
}

func isAVScanCandidate(ev dpi.Event) bool {
	if ev.Proto != "http" {
		return false
	}
	return ev.Kind == "request" || ev.Kind == "response"
}

func (e *Engine) recordProtoStats(srcIP, dstIP string, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil || e.stats == nil || pkt == nil || srcIP == "" || dstIP == "" {
		return
	}
	payloadLen := len(pkt.Payload)
	for _, ev := range evs {
		e.stats.Record(ev, payloadLen)
		e.stats.RecordFlow(srcIP, dstIP, ev.Proto, 1, int64(payloadLen))
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

// ProtoStats returns current per-protocol statistics derived from DPI events.
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
	case "modbus", "dnp3", "iec104", "s7", "s7comm", "cip", "bacnet", "opcua", "mms", "ics":
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
func (e *Engine) EvaluateVerdict(ctx rules.EvalContext) verdict.Verdict {
	start := time.Now()
	snap := e.ruleSnap.Load()
	ev := rules.NewEvaluator(snap)
	action, matched := ev.EvaluateMatch(ctx)
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
	return v
}

// ApplyVerdict applies a verdict to dynamic enforcement primitives when enabled.
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
