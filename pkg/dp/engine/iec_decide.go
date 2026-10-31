// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const iecBroadcastCA = 65535

// iecDecision is the rule decision for one IEC104 event (object, S/U frame
// or error APDU).
type iecDecision struct {
	decision string // allow | deny | would_drop
	ruleID   string
	scopeID  string
	action   string
	mode     string
	reason   string
	log      bool // emit an ics.decision for an allow
}

// enforced reports a decision that aborts the session.
func (d iecDecision) enforced() bool { return d.decision == decisionDeny }

// decideLocked judges one decoded event of session s. Broadcast objects
// and unframeable bytes are denied without a rule; everything else is
// matched against the IEC104 rules only, with whatever fields the decoder
// read, and no match is DENY in the envelope mode. Under strict parsing an
// event with conformance or undecoded findings is denied before rule
// arbitration, with reason nonconformant and scope attribution. In a monitor
// envelope a deny is would_drop; monitor rules never arbitrate a verdict.
func (t *iecTable) decideLocked(s *iecSession, ev dpi.Event) iecDecision {
	d := iecDecision{action: string(rules.ActionDeny), mode: s.mode, reason: iecEventDenialReason(ev)}
	if iecStrictPreempts(ev, t.parsing) {
		d.reason, d.action = reasonNonconformant, ""
		if t.policy != nil {
			if scope := t.policy.IEC104Scope(s.ctx, t.globalMode); scope != nil {
				d.scopeID = scope.ID
			}
		}
	} else if d.reason == "" {
		ctx := s.ctx
		ctx.ICS = t.iecContext(ev)
		action, entry := rules.ActionDeny, (*rules.Entry)(nil)
		if t.policy != nil {
			action, entry = t.policy.EvaluateIEC104(ctx)
		}
		d.reason = reasonDefault
		if entry != nil {
			d.reason, d.ruleID, d.action, d.log = reasonRule, entry.ID, string(entry.Action), entry.Log
			d.mode = rules.EffectiveMode(entry.ICS.Mode, t.globalMode)
		}
		if action == rules.ActionAllow {
			d.decision = decisionAllow
			return d
		}
	}
	if s.mode == "enforce" && d.mode == "enforce" {
		d.decision = decisionDeny
	} else {
		d.decision = decisionWouldDrop
	}
	return d
}

// iecEventDenialReason is the pre-rule fail-closed gate shared with preview.
// Such events are denied by the envelope, not matched by a candidate rule:
// broadcast objects, and a malformed event without findings, which is the
// evidence of a lost frame boundary or a stream fault rather than content.
func iecEventDenialReason(ev dpi.Event) string {
	switch {
	case ev.Kind == iecKindMalformed && !hasInspectionFindings(ev):
		return reasonMalformed
	case iecBroadcast(ev.Attributes):
		return reasonBroadcast
	default:
		return ""
	}
}

// iecStrictPreempts reports content that strict parsing denies before any
// ALLOW: an event with conformance or undecoded findings. Shared with preview,
// where a candidate ALLOW can therefore never match it, while a candidate DENY
// still does.
func iecStrictPreempts(ev dpi.Event, parsing ics.Parsing) bool {
	return parsing == ics.Strict && hasInspectionFindings(ev)
}

// iecContext builds the rule context of one IEC104 event.
func (t *iecTable) iecContext(ev dpi.Event) *rules.ICSContext {
	return iecContextFromDPIEvent(ev, t.safeRead)
}

func iecContextFromDPIEvent(ev dpi.Event, safeRead func(map[string]any) bool) *rules.ICSContext {
	contexts := icsContextsFromDPIEvent(nil, ev, safeRead)
	return &contexts[0]
}

func iecBroadcast(a map[string]any) bool {
	apci, _ := eventfields.String(a, eventfields.KeyAPCIType)
	ca, ok := eventfields.Uint16(a, eventfields.KeyCA)
	return apci == "I" && ok && ca == iecBroadcastCA
}

// iecFinding is one judged event with conformance findings and its
// decision, for the conformance alert the engine raises once the packet's
// outcome is known.
type iecFinding struct {
	ev       dpi.Event
	decision string
}

// iecJudgement is the outcome of judging the events of newly framed APDUs:
// whether any decision is an enforced deny, the apdu_id of the first one,
// the decision events, and the events that carry findings.
type iecJudgement struct {
	denied   bool
	trigger  string
	events   []iecTelemetry
	findings []iecFinding
}

// judgeLocked decides the events of newly framed APDUs; every event is
// judged, even after a deny.
func (t *iecTable) judgeLocked(s *iecSession, evs []dpi.Event, now time.Time) iecJudgement {
	var j iecJudgement
	seen := map[string]map[string]bool{}
	for _, ev := range evs {
		if !strings.EqualFold(ev.Proto, iecProtocol) {
			continue
		}
		if t.policy != nil {
			ctx := s.ctx
			ctx.ICS = t.iecContext(ev)
			apdu, _ := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
			if seen[apdu] == nil {
				seen[apdu] = map[string]bool{}
			}
			for _, entry := range t.policy.MonitorMatches(ctx) {
				if seen[apdu][entry.ID] {
					continue
				}
				seen[apdu][entry.ID] = true
				if t.shadow != nil {
					t.shadow(t.snap, entry)
				}
				j.events = append(j.events, s.decisionEvent(ev, iecDecision{decision: shadowDecision(entry), ruleID: entry.ID, action: string(entry.Action), mode: "monitor", reason: reasonRule}, now))
			}
		}
		d := t.decideLocked(s, ev)
		s.inventoryDecisionLocked(ev, d)
		if d.enforced() && !j.denied {
			j.denied = true
			j.trigger, _ = eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
		}
		if d.decision != decisionAllow || d.log {
			j.events = append(j.events, s.decisionEvent(ev, d, now))
		}
		if hasInspectionFindings(ev) {
			j.findings = append(j.findings, iecFinding{ev: ev, decision: d.decision})
		}
		if t.reconnectLocked(s, ev) {
			j.events = append(j.events, s.sessionEvent(outcomeReconnected, nil, now))
		}
	}
	return j
}

// reconnectLocked reports the first STARTDT con of a new incarnation of a
// client/server pair after an abort.
func (t *iecTable) reconnectLocked(s *iecSession, ev dpi.Event) bool {
	if !s.reconnects {
		return false
	}
	if fn, _ := eventfields.String(ev.Attributes, eventfields.KeyUFunction); fn != "startdt_con" {
		return false
	}
	s.reconnects = false
	delete(t.reconnect, pairKey(s.client, s.server))
	return true
}
