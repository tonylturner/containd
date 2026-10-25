// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const iecBroadcastCA = 65535

// iecDecision is the rule decision for one IEC104 event (object, S/U frame
// or error APDU).
type iecDecision struct {
	decision string // allow | deny | would_drop
	ruleID   string
	action   string
	mode     string
	reason   string
	log      bool // emit an ics.decision for an allow
}

// enforced reports a decision that aborts the session.
func (d iecDecision) enforced() bool { return d.decision == decisionDeny }

// decideLocked judges one decoded event of session s (spec §6.5). Broadcast
// objects, malformed, role-invalid and unsupported APDUs are denied without
// a rule; everything else is matched against the IEC104 rules only, and no
// match is DENY in the envelope mode. In a learn envelope, or under a
// learn-mode rule, a deny is would_drop.
func (t *iecTable) decideLocked(s *iecSession, ev dpi.Event) iecDecision {
	d := iecDecision{action: string(rules.ActionDeny), mode: s.mode}
	d.reason = iecEventDenialReason(ev)
	if d.reason == "" {
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
// Such events are denied by the envelope, not matched by a candidate rule.
func iecEventDenialReason(ev dpi.Event) string {
	switch {
	case ev.Kind == iecKindMalformed && anomaly.IEC104RoleViolation(ev.Attributes):
		return reasonRole
	case ev.Kind == iecKindMalformed:
		return reasonMalformed
	case ev.Kind == iecKindUnsupported:
		return reasonUnsupported
	case iecBroadcast(ev.Attributes):
		return reasonBroadcast
	default:
		return ""
	}
}

// iecContext builds the rule context of one IEC104 event.
func (t *iecTable) iecContext(ev dpi.Event) *rules.ICSContext {
	return iecContextFromDPIEvent(ev, t.safeRead)
}

func iecContextFromDPIEvent(ev dpi.Event, safeRead func(map[string]any) bool) *rules.ICSContext {
	a := ev.Attributes
	c := &rules.IEC104Context{Malformed: ev.Kind == iecKindMalformed, Unsupported: ev.Kind == iecKindUnsupported}
	c.APCIType, _ = eventfields.String(a, eventfields.KeyAPCIType)
	c.Class, _ = eventfields.String(a, eventfields.KeyClass)
	if v, ok := eventfields.Uint8(a, eventfields.KeyTypeID); ok {
		c.TypeID = &v
	}
	if v, ok := eventfields.Uint16(a, eventfields.KeyCA); ok {
		c.CA = &v
	}
	if v, ok := eventfields.Uint32(a, eventfields.KeyIOA); ok {
		c.IOA = &v
	}
	c.Broadcast = iecBroadcast(a)
	c.SafeRead = safeRead(a)
	dir, _ := eventfields.String(a, eventfields.KeyDirection)
	return &rules.ICSContext{Protocol: iecProtocol, Direction: dir, IEC104: c}
}

func iecBroadcast(a map[string]any) bool {
	apci, _ := eventfields.String(a, eventfields.KeyAPCIType)
	ca, ok := eventfields.Uint16(a, eventfields.KeyCA)
	return apci == "I" && ok && ca == iecBroadcastCA
}

// judgeLocked decides the events of newly framed APDUs. It reports whether
// any decision is an enforced deny, the apdu_id of the first one, and the
// decision events; every event is judged, even after a deny (spec §6.3).
func (t *iecTable) judgeLocked(s *iecSession, evs []dpi.Event, now time.Time) (denied bool, trigger string, out []events.Event) {
	for _, ev := range evs {
		if !strings.EqualFold(ev.Proto, iecProtocol) {
			continue
		}
		d := t.decideLocked(s, ev)
		if d.enforced() && !denied {
			denied = true
			trigger, _ = eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
		}
		if d.decision != decisionAllow || d.log {
			out = append(out, s.decisionEvent(ev, d, now))
		}
		if t.reconnectLocked(s, ev) {
			out = append(out, s.sessionEvent(outcomeReconnected, nil, now))
		}
	}
	return denied, trigger, out
}

// reconnectLocked reports the first STARTDT con of a new incarnation of a
// client/server pair after an abort (spec §8.4).
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
