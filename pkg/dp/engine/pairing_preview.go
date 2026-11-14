// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"

	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// PairingPreview summarizes retained runtime observations, not candidate
// admission or delivery. Predicate matches remain a separate measurement.
type PairingPreview struct {
	Paired      int      `json:"paired"`
	Unpaired    int      `json:"unpaired"`
	Expired     int      `json:"expired"`
	Ambiguous   int      `json:"ambiguous"`
	Unsupported int      `json:"unsupported"`
	Unknown     int      `json:"unknown"`
	Reasons     []string `json:"reasons"`
}

func newPairingPreview() *PairingPreview {
	return &PairingPreview{Reasons: []string{}}
}

func (p *PairingPreview) add(ev events.Event) {
	switch ev.Proto {
	case "modbus", "dnp3", "iec104":
	default:
		return
	}
	switch ev.Kind {
	case "request", "response", "exception", "apci", "session", "malformed", "unsupported":
	default:
		return
	}
	outcome, _ := eventfields.String(ev.Attributes, "pairing_outcome")
	reason, _ := eventfields.String(ev.Attributes, "pairing_reason")
	// Only the bounded runtime vocabulary is exposed. An unstamped historical
	// event cannot gain authority from decoded FC/COT or a nearby request.
	valid := false
	switch pairReason(reason) {
	case pairOK, pairUnpaired, pairExpired, pairAmbiguous, pairUnsupported,
		pairUnknown, pairMismatch, autonomousRequired, sessionRequired, messageTimeout, stateLimit:
		valid = outcome == pairOutcome(pairReason(reason))
	}
	class, _ := eventfields.String(ev.Attributes, "message_class")
	switch rules.MessageClass(class) {
	case rules.ClassRequest, rules.ClassSolicited, rules.ClassAutonomous, rules.ClassSession:
	case rules.ClassUnknown:
		valid = valid && outcome != "paired"
	default:
		valid = false
	}
	if !valid {
		outcome, reason = "unknown", string(pairUnknown)
	}
	switch outcome {
	case "paired":
		p.Paired++
	case "unpaired":
		p.Unpaired++
	case "expired":
		p.Expired++
	case "ambiguous":
		p.Ambiguous++
	case "unsupported":
		p.Unsupported++
	default:
		p.Unknown++
	}
	if !slices.Contains(p.Reasons, reason) {
		p.Reasons = append(p.Reasons, reason)
		slices.Sort(p.Reasons)
	}
}

func previewEventMatches(evaluator *rules.Evaluator, snap *rules.Snapshot, entry rules.Entry, ev events.Event, resolve zoneResolver, parsing ics.Parsing) bool {
	contexts := previewEventContexts(snap, entry, ev, resolve, parsing)
	if len(contexts) == 0 {
		return false
	}
	for _, ctx := range contexts {
		matched := evaluator.AnyMatch(ctx) != nil
		if entry.Action == rules.ActionAllow && !matched {
			return false
		}
		if entry.Action != rules.ActionAllow && matched {
			return true
		}
	}
	return entry.Action == rules.ActionAllow
}

// PreviewPairing selects retained events by candidate predicates independently
// of kernel compilation, including when candidate enforcement is disabled.
func (e *Engine) PreviewPairing(snap *rules.Snapshot) *PairingPreview {
	out := newPairingPreview()
	type predicate struct {
		entry     rules.Entry
		evaluator *rules.Evaluator
		parsing   ics.Parsing
	}
	var predicates []predicate
	for _, entry := range snap.Firewall {
		if entry.ICS.Protocol == "" || len(entry.ViaForwards) > 0 {
			continue
		}
		candidate := *snap
		candidate.Firewall = []rules.Entry{entry}
		predicates = append(predicates, predicate{entry, rules.NewEvaluator(&candidate), e.ICSParsing(entry.ICS.Protocol)})
	}
	for _, ev := range e.Events().ListTelemetry(5000) {
		for _, p := range predicates {
			if previewEventMatches(p.evaluator, snap, p.entry, ev, e.zones.resolve, p.parsing) {
				out.add(ev)
				break // overlapping predicates never count one event twice
			}
		}
	}
	return out
}
