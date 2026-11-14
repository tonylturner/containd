// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// These are transient facts of the one typed policy evaluation, not retained
// request authority. Event recording happens after the session lock is released.
type sessionMessageDecision struct {
	compiled *compiledRules
	events   []dpi.Event
	contexts []rules.EvalContext
	entries  []*rules.Entry
	scope    *rules.Entry
	strict   bool
	denied   bool
	matched  *rules.Entry
	nonAdmit bool
}

func (t *sessionTable) genericScopeLocked(s *trackedSession, compiled *compiledRules) *rules.Entry {
	var monitor *rules.Entry
	for i := range compiled.snapshot.Firewall {
		entry := &compiled.snapshot.Firewall[i]
		if entry.ICS.Protocol != sessionProtocol(s.flow) || !compiled.evaluator.TransportScopeMatch(i, s.ctx) {
			continue
		}
		if !rules.MonitorICS(*entry, compiled.snapshot.DPIMode) {
			return entry
		}
		if monitor == nil {
			monitor = entry
		}
	}
	return monitor
}

func (t *sessionTable) genericUnitPolicyLocked(s *trackedSession, dir int, f dpi.DecodedFrame, class rules.MessageClass, paired bool, compiled *compiledRules, now time.Time, res *sessionResult) (requestPermit, bool, pairReason) {
	permit := requestPermit{Epoch: compiled.epoch}
	j := sessionMessageDecision{compiled: compiled, events: f.Events, scope: t.genericScopeLocked(s, compiled)}
	for _, ev := range f.Events {
		j.strict = j.strict || t.parsing == ics.Strict && hasInspectionFindings(ev) && j.scope != nil
	}
	var objects []rules.ICSContext
	var err error
	if s.mode == "monitor" {
		// Decode-and-decide covers every decoded message, including procedures
		// unsupported by the pairing table. This projection is observational:
		// observePairingLocked independently requires typed request authority.
		objects = observedPolicyObjects(s, dir, f.Events)
	} else {
		objects, err = project.UnitObjects(f.Unit, class, dpiDir(dir))
	}
	if err == nil {
		for i := range objects {
			ctx := s.ctx
			ctx.Now, ctx.ICS = now, &objects[i]
			j.contexts = append(j.contexts, ctx)
		}
	}
	// Strict scope preempts every decoded ALLOW or DENY; it does not run a
	// second evaluator to obtain attribution.
	if j.strict && s.mode == "enforce" {
		res.policyReason = reasonNonconformant
		res.messages = append(res.messages, j)
		return permit, false, pairMismatch
	}
	if err != nil || len(objects) == 0 {
		// Decoded facts may attribute a winning explicit veto, never authorize
		// unsupported content. Typed classification remains unknown here.
		for _, object := range observedPolicyObjects(s, dir, f.Events) {
			object.MessageClass = rules.ClassUnknown
			ctx := s.ctx
			ctx.Now, ctx.ICS = now, &object
			action, entry := compiled.evaluator.EvaluateMessage(ctx, false)
			if entry != nil && entry.ICS.Protocol == object.Protocol && action != rules.ActionAllow {
				j.contexts, j.entries = append(j.contexts, ctx), append(j.entries, entry)
				j.denied, j.matched, res.policyReason = true, entry, reasonDPIDeny
			}
		}
		res.messages = append(res.messages, j)
		return permit, false, pairUnsupported
	}
	why := pairOK
	for _, ctx := range j.contexts {
		action, entry := compiled.evaluator.EvaluateMessage(ctx, class == rules.ClassSolicited && paired)
		j.entries = append(j.entries, entry)
		explicit := entry != nil && entry.ICS.Protocol == ctx.ICS.Protocol
		if action != rules.ActionAllow {
			j.denied, j.matched = true, entry
		}
		switch {
		case class == rules.ClassAutonomous && (action != rules.ActionAllow || !explicit || entry.ICS.MessageClass != string(class)):
			why = autonomousRequired
		case class == rules.ClassSession && (action != rules.ActionAllow || !explicit || entry.ICS.MessageClass != string(class)):
			why = sessionRequired
		case action != rules.ActionAllow && explicit:
			if res.policyReason != reasonNonconformant {
				res.policyReason = reasonDPIDeny
			}
			why = pairMismatch
		case action != rules.ActionAllow || s.mode == "enforce" && class == rules.ClassRequest && !explicit:
			j.nonAdmit = true
		}
		permit.Contexts = append(permit.Contexts, ctx)
	}
	res.messages = append(res.messages, j)
	return permit, j.nonAdmit, why
}

func observedPolicyObjects(s *trackedSession, dir int, events []dpi.Event) []rules.ICSContext {
	state := &flow.State{Key: s.flow.ServiceKey()}
	if (state.Key.Dir == flow.DirReverse) != (dir == sessionDirSrv) {
		state.Key = state.Key.Reversed()
	}
	var objects []rules.ICSContext
	for _, ev := range events {
		objects = append(objects, project.Objects(state, ev, nil)...)
	}
	return objects
}

func (e *Engine) recordSessionMessages(state *flow.State, pkt *dpi.ParsedPacket, res sessionResult) {
	for _, j := range res.messages {
		for i, entry := range j.entries {
			e.recordRuleHit(j.compiled.evaluator, j.contexts[i], entry, state)
		}
		for _, ev := range j.events {
			e.observeMonitor(j.compiled.snapshot, j.compiled.evaluator, state, pkt, ev, j.contexts)
			if j.strict && hasInspectionFindings(ev) {
				decision := decisionWouldDrop
				mode := rules.EffectiveMode(j.scope.ICS.Mode, j.compiled.snapshot.DPIMode)
				if mode == "enforce" {
					decision = decisionDeny
				}
				e.recordConformanceDecision(state, pkt, ev, j.scope, mode, decision, reasonNonconformant)
			} else if j.denied && !e.detached {
				// Live non-admission can report ordinary transport denial.
				// Detached replay has no such authority, only would-decisions.
				reason := reasonDefault
				if j.matched != nil {
					reason = reasonRule
				}
				e.recordConformanceDecision(state, pkt, ev, j.matched, "enforce", decisionDeny, reason)
			}
			action := "passed"
			switch {
			case res.decision.Action == capture.Drop:
				action = "dropped and reset"
			case res.decision.Reason == reasonPolicyNonAdmit:
				action = "non-admitting continuation"
			case j.strict:
				action = "would drop"
			}
			e.recordConformanceAlert(state, pkt, ev, action)
		}
	}
}
