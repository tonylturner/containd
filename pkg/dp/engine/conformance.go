// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const reasonNonconformant = "nonconformant"

// inspectionFindingKeys share policy arbitration, but retain separate alert
// identities and evidence: undecoded content is not a conformance violation.
var inspectionFindingKeys = []string{eventfields.KeyConformance, eventfields.KeyUndecoded}

func hasInspectionFindings(ev dpi.Event) bool {
	for _, key := range inspectionFindingKeys {
		if codes, _ := eventfields.Strings(ev.Attributes, key); len(codes) > 0 {
			return true
		}
	}
	return false
}

// SetICSParsing atomically changes subsequent decisions without retiring
// sessions. The caller's map is never retained.
func (e *Engine) SetICSParsing(modes map[string]string) {
	copy := maps.Clone(modes)
	e.icsParsing.Store(&copy)
}

// ICSParsing returns the effective mode for a protocol at decision time.
func (e *Engine) ICSParsing(proto string) ics.Parsing {
	if modes := e.icsParsing.Load(); modes != nil {
		return ics.EffectiveParsing(*modes, strings.ToLower(proto))
	}
	return ics.Tolerant
}

// conformanceScope uses the same L3/L4 scope as fail-closed inspection, but
// includes learn/non-inline observations and only the event's protocol.
// Any enforcing scope wins over a learn ALLOW's payload predicates.
func (e *Engine) conformanceScope(state *flow.State, pkt *dpi.ParsedPacket, proto string) *rules.Entry {
	p := e.ruleSnap.current.Load()
	if p == nil || p.snapshot == nil {
		return nil
	}
	ctx := rules.EvalContext{SrcIP: state.Key.OpenerIP(), DstIP: state.Key.ServerIP()}
	ctx.SrcZone, ctx.DstZone = e.zones.resolve(p.snapshot, ctx.SrcIP, ctx.DstIP)
	var learn *rules.Entry
	for i := range p.snapshot.Firewall {
		entry := &p.snapshot.Firewall[i]
		if !strings.EqualFold(entry.ICS.Protocol, proto) ||
			!shouldInspectFirewallEntry(*entry, state, pkt) || !p.evaluator.AddressScopeMatch(i, ctx) {
			continue
		}
		if e.effectiveMode(entry) == "enforce" {
			return entry
		}
		if learn == nil {
			learn = entry
		}
	}
	return learn
}

// recordConformanceDecision is shared with the APDU verdict path. Call only
// after decoded-deny precedence is resolved; it records evidence, not delivery.
func (e *Engine) recordConformanceDecision(state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, scope *rules.Entry, mode, decision, reason string) {
	attrs := withDerivedIdentity(ev, map[string]any{
		eventfields.KeyMode:     mode,
		eventfields.KeyDecision: decision,
		eventfields.KeyReason:   reason,
	})
	for _, key := range inspectionFindingKeys {
		if codes, _ := eventfields.Strings(ev.Attributes, key); len(codes) > 0 {
			attrs[key] = codes
		}
	}
	if scope != nil {
		attrs[eventfields.KeyRuleID] = scope.ID
	}
	e.eventStore.Record(state, pkt, []dpi.Event{{
		FlowID: conformanceFlowID(state, ev), Proto: ev.Proto, Kind: eventfields.KindDecision,
		Timestamp: time.Now().UTC(), Attributes: attrs,
	}})
}

const (
	conformanceMaxConnections = 65536
	conformanceMaxCodes       = 64
)

type conformanceConnection struct {
	codes map[inspectionFinding]uint64
	fin   [2]bool
}

type inspectionFinding struct {
	field string
	code  string
}

// Saturation suppresses new alert identities rather than evicting live ones
// and allowing repeated alerts to flood the store. Verdicts are unaffected.
type conformanceAlerts struct {
	mu         sync.Mutex
	conns      map[string]*conformanceConnection
	suppressed uint64
}

func conformanceKey(state *flow.State) string {
	if c := state.Connection.Load(); c != nil {
		return c.Key
	}
	key := state.Key
	if key.Dir == flow.DirReverse {
		key = key.Reversed()
	}
	return key.Hash()
}

func (a *conformanceAlerts) fresh(state *flow.State, field string, codes []string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := conformanceKey(state)
	conn := a.conns[key]
	if conn == nil {
		if len(a.conns) >= conformanceMaxConnections {
			a.suppressed += uint64(len(codes))
			return nil
		}
		if a.conns == nil {
			a.conns = make(map[string]*conformanceConnection)
		}
		conn = &conformanceConnection{codes: make(map[inspectionFinding]uint64)}
		a.conns[key] = conn
	}
	var fresh []string
	for _, code := range codes {
		id := inspectionFinding{field: field, code: code}
		if _, seen := conn.codes[id]; seen {
			conn.codes[id]++
		} else if len(conn.codes) < conformanceMaxCodes {
			conn.codes[id] = 1
			fresh = append(fresh, code)
		} else {
			a.suppressed++
		}
	}
	return fresh
}

func (a *conformanceAlerts) end(state *flow.State, reset bool) {
	if state == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := conformanceKey(state)
	if conn := a.conns[key]; conn != nil {
		direction := state.Key.Dir
		if c := state.Connection.Load(); c != nil {
			direction = c.Direction(state.Key)
		}
		conn.fin[direction] = true
		if reset || conn.fin[0] && conn.fin[1] {
			delete(a.conns, key)
		}
	}
}

func (a *conformanceAlerts) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.conns = nil
	a.suppressed = 0
}

// recordConformanceAlert uses the IDS alert store/export path. action is
// "passed", "dropped and reset", or "would drop", after packet/APDU arbitration.
// IEC callers can reuse this after their delivery decision, with session/APDU
// identity on ev. Repeated codes count but do not emit another alert.
func (e *Engine) recordConformanceAlert(state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, action string) {
	if state == nil || e.eventStore == nil {
		return
	}
	for _, key := range inspectionFindingKeys {
		codes, _ := eventfields.Strings(ev.Attributes, key)
		if len(codes) == 0 {
			continue
		}
		fresh := e.conformance.fresh(state, key, codes)
		if len(fresh) == 0 {
			continue
		}
		attrs := withDerivedIdentity(ev, map[string]any{
			"rule_id": "ics-" + key, "severity": "medium",
			"message":  fmt.Sprintf("%s %s %s: %s", ev.Proto, key, strings.Join(fresh, ", "), action),
			"protocol": ev.Proto, "action": action, key: fresh,
		})
		metrics.IDSAlertsTotal.Inc()
		e.eventStore.Record(state, pkt, []dpi.Event{{
			FlowID: conformanceFlowID(state, ev), Proto: "ids", Kind: "alert", Timestamp: time.Now().UTC(), Attributes: attrs,
		}})
	}
}

func conformanceFlowID(state *flow.State, ev dpi.Event) string {
	if ev.FlowID != "" {
		return ev.FlowID
	}
	return state.ID()
}
