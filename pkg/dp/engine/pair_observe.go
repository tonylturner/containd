// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func sessionProtocol(s *flow.State) string {
	switch servicePort(s, nil) {
	case ics.ModbusPort:
		return "modbus"
	case ics.DNP3Port:
		return "dnp3"
	case iec104Port:
		return iecProtocol
	default:
		return ""
	}
}

// observePairingLocked accounts for observed compatible exchanges. It never
// changes a packet verdict, and its grants cannot authorize another session.
func (t *sessionTable) observePairingLocked(s *trackedSession, dir int, f dpi.DecodedFrame, now time.Time) {
	if s.mode != "monitor" || s.pairing == nil || f.Pending {
		return
	}
	class, reason := s.pairing.inspect(f, dpiDir(dir), now)
	evaluator := rules.NewEvaluator(t.snap)
	var contexts []rules.EvalContext
	allowed := true
	for _, ev := range f.Events {
		for _, obj := range icsContextsFromDPIEvent(s.flow, ev, t.safeRead) {
			ctx := s.ctx
			ctx.ICS = &obj
			ctx.ICS.MessageClass = class
			contexts = append(contexts, ctx)
			entry := evaluator.AnyMatch(ctx)
			if entry == nil || entry.Action != rules.ActionAllow {
				allowed = false
			}
		}
	}
	if allowed && reason == pairOK {
		reason = s.pairing.apply(f, dpiDir(dir), requestPermit{Contexts: contexts}, now)
	}
	if !allowed && class == rules.ClassAutonomous {
		reason = autonomousRequired
	}
	if !allowed && class == rules.ClassSession {
		reason = sessionRequired
	}
	for i := range f.Events {
		if f.Events[i].Attributes == nil {
			f.Events[i].Attributes = map[string]any{}
		}
		f.Events[i].Attributes["message_class"] = string(class)
		f.Events[i].Attributes["pairing_outcome"] = pairOutcome(reason)
		f.Events[i].Attributes["pairing_reason"] = string(reason)
	}
}

func pairOutcome(reason pairReason) string {
	switch reason {
	case pairOK:
		return "paired"
	case pairUnpaired, pairMismatch, autonomousRequired, sessionRequired:
		return "unpaired"
	case pairExpired:
		return "expired"
	case pairAmbiguous:
		return "ambiguous"
	case pairUnsupported:
		return "unsupported"
	case pairUnknown, messageTimeout, stateLimit:
		return "unknown"
	default:
		return "unknown"
	}
}
