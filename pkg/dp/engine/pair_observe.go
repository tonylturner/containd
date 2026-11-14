// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func sessionProtocol(s *flow.State) string {
	if s == nil {
		return ""
	}
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

// Observe uses the same typed units and ledger as enforcement, but never holds
// tokens or changes delivery. Only allowed observed requests mint authority;
// response-rule defaults do not erase the request's structural pairing outcome.
func (t *sessionTable) observePairingLocked(s *trackedSession, dir int, f dpi.DecodedFrame, now time.Time) {
	if s.mode != "monitor" || s.pairing == nil || f.Pending {
		return
	}
	class, reason := s.pairing.inspect(f, dpiDir(dir), now)
	compiled := t.ruleOwner.current.Load()
	permit := requestPermit{}
	allowed := compiled != nil
	objects, err := project.UnitObjects(f.Unit, class, dpiDir(dir))
	if err != nil || len(objects) == 0 {
		reason = pairUnsupported
		allowed = false
	}
	if compiled != nil {
		permit.Epoch = compiled.epoch
		for i := range objects {
			ctx := s.ctx
			ctx.Now, ctx.ICS = now, &objects[i]
			entry := compiled.evaluator.AnyMatch(ctx)
			if entry == nil || entry.Action != rules.ActionAllow || entry.ICS.Protocol != objects[i].Protocol ||
				(class == rules.ClassAutonomous || class == rules.ClassSession) && entry.ICS.MessageClass != string(class) {
				allowed = false
			}
			permit.Contexts = append(permit.Contexts, ctx)
		}
	}
	if reason == pairOK {
		switch {
		case class == rules.ClassAutonomous && !allowed:
			reason = autonomousRequired
		case class == rules.ClassSession && !allowed:
			reason = sessionRequired
		case class == rules.ClassRequest && !allowed: // non-admission creates no grant
			reason = pairUnpaired
		default:
			reason = s.pairing.transact([]pairOperation{{frame: f, dir: dpiDir(dir), permit: permit}}, now)
		}
	}
	stampPairing(f.Events, class, reason)
}

func stampPairing(events []dpi.Event, class rules.MessageClass, reason pairReason) {
	for i := range events {
		if events[i].Attributes == nil {
			events[i].Attributes = map[string]any{}
		}
		events[i].Attributes["message_class"] = string(class)
		events[i].Attributes["pairing_outcome"] = pairOutcome(reason)
		events[i].Attributes["pairing_reason"] = string(reason)
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
