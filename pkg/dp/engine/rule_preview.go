// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"strconv"
	"time"

	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// PreviewRuleResponse is the stable public rule-impact response, also used on
// the internal engine API. Samples retain their original wire orientation.
type PreviewRuleResponse struct {
	MatchCount    int               `json:"match_count"`
	SampleMatches []events.Event    `json:"sample_matches"`
	TimeRange     *PreviewTimeRange `json:"time_range"`
	TotalEvents   int               `json:"total_events"`
	// Warnings lists the candidate's predicates that resolve toward denial
	// under the running enforcement, which explains an inactive ALLOW rule's
	// zero matches; omitted when there are none.
	Warnings []enforce.RuleWarning `json:"warnings,omitempty"`
	// ICSCoverage is the candidate's coverage under the running settings
	// and runtime state; omitted for a rule without an ICS protocol.
	ICSCoverage *coverage.Rule `json:"icsCoverage,omitempty"`
}

type PreviewTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// PreviewRule tests a candidate in isolation, not against preceding rules or
// default actions. It does not apply rules, log decisions or enforce verdicts.
// Predicates the running enforcement cannot evaluate resolve toward denial,
// as they do when the rule is applied.
func (e *Engine) PreviewRule(entry rules.Entry) PreviewRuleResponse {
	return e.previewRule(entry, resolveZonesForFlow)
}

func (e *Engine) previewRule(entry rules.Entry, resolve zoneResolver) PreviewRuleResponse {
	const maxSamples = 50
	result := PreviewRuleResponse{SampleMatches: []events.Event{}}
	// Use the same retained evidence window as GET /internal/events, including
	// protected incidents and DENYs, deduplicated before counting.
	evs := e.eventStore.ListTelemetry(5000)
	result.TotalEvents = len(evs)
	snap := e.ruleSnap.Load()
	queueID := e.enforcedQueueID()
	effective, active := enforcedCandidate(entry, queueID)
	result.Warnings = (&enforce.Compiler{QueueID: queueID}).RuleWarnings(&rules.Snapshot{Firewall: []rules.Entry{entry}})
	if cov := e.coverageOf(&rules.Snapshot{Firewall: []rules.Entry{entry}}); len(cov) == 1 {
		result.ICSCoverage = &cov[0]
	}
	evaluator := rules.NewEvaluator(&rules.Snapshot{Firewall: []rules.Entry{effective}})
	for _, ev := range evs {
		if result.TimeRange == nil {
			result.TimeRange = &PreviewTimeRange{Start: ev.Timestamp, End: ev.Timestamp}
		} else {
			if ev.Timestamp.Before(result.TimeRange.Start) {
				result.TimeRange.Start = ev.Timestamp
			}
			if ev.Timestamp.After(result.TimeRange.End) {
				result.TimeRange.End = ev.Timestamp
			}
		}
		if !active {
			continue
		}
		ctx, ok := previewEventContext(snap, entry, ev, resolve)
		if !ok {
			continue
		}
		var matched *rules.Entry
		if entry.ICS.Protocol == rules.ProtocolIEC104 {
			_, matched = evaluator.EvaluateIEC104(ctx)
		} else {
			_, matched = evaluator.EvaluateMatch(ctx)
		}
		if matched == nil {
			continue
		}
		result.MatchCount++
		if len(result.SampleMatches) < maxSamples {
			result.SampleMatches = append(result.SampleMatches, ev)
		}
	}
	return result
}

// enforcedCandidate returns entry as enforcement decides it when the engine
// queues ICS rules to queueID, and false when it can never match: an ALLOW
// rule with an unenforced predicate is inactive, and a DENY rule applies as
// if each unenforced predicate always matched.
func enforcedCandidate(entry rules.Entry, queueID int) (rules.Entry, bool) {
	for _, p := range enforce.UnenforcedPredicates(entry, queueID) {
		if entry.Action == rules.ActionAllow {
			return entry, false
		}
		switch p {
		case enforce.PredicateIdentity:
			entry.Identities = nil
		case enforce.PredicateSchedule:
			entry.Schedule = rules.SchedulePredicate{}
		}
	}
	return entry, true
}

// enforcedQueueID is the NFQUEUE group the running compiler steers ICS rules
// to; 0 when enforcement is disabled or no queue is configured.
func (e *Engine) enforcedQueueID() int {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	if e.compiler == nil {
		return 0
	}
	return e.compiler.QueueID
}

func previewEventContext(snap *rules.Snapshot, entry rules.Entry, ev events.Event, resolve zoneResolver) (rules.EvalContext, bool) {
	decoded := dpi.Event{FlowID: ev.FlowID, Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes, Timestamp: ev.Timestamp}
	src, dst := net.ParseIP(ev.SrcIP), net.ParseIP(ev.DstIP)
	if src == nil || dst == nil {
		return rules.EvalContext{}, false
	}
	if entry.ICS.Protocol == rules.ProtocolIEC104 {
		if ev.Proto != iecProtocol || ev.Transport != "tcp" || !iecWireEvent(ev.Kind) || iecEventDenialReason(decoded) != "" {
			return rules.EvalContext{}, false
		}
		from, okFrom := addrPort(src, ev.SrcPort)
		to, okTo := addrPort(dst, ev.DstPort)
		if !okFrom || !okTo {
			return rules.EvalContext{}, false // IEC runtime is IPv4 only
		}
		// Decoder direction is authoritative, including when both endpoints
		// use port 2404. Port heuristics cannot recover that session tuple.
		client, server := from, to
		direction, _ := eventfields.String(ev.Attributes, eventfields.KeyDirection)
		switch direction {
		case "response":
			client, server = to, from
		case "request":
		default:
			return rules.EvalContext{}, false
		}
		if server.Port() != iec104Port {
			return rules.EvalContext{}, false
		}
		ctx := iecSessionContext(snap, client, server, resolve)
		ctx.ICS = iecContextFromDPIEvent(decoded, iec104.SafeRead)
		ctx.Now = ev.Timestamp
		return ctx, true
	}

	if entry.ICS.Protocol == "" {
		srcZone, dstZone := resolve(snap, src, dst)
		return rules.EvalContext{SrcIP: src, DstIP: dst, SrcZone: srcZone, DstZone: dstZone,
			Proto: ev.Transport, Port: strconv.Itoa(int(ev.DstPort)), Now: ev.Timestamp}, true
	}
	// DPI events retain the directional flow.Key.Hash. Use its direction,
	// not the message kind (unsolicited server messages can be requests).
	key := flow.Key{SrcIP: src, DstIP: dst, SrcPort: ev.SrcPort, DstPort: ev.DstPort, Dir: flow.DirReverse}
	switch ev.Transport {
	case "tcp":
		key.Proto = 6
	case "udp":
		key.Proto = 17
	}
	if ev.FlowID != key.Hash() {
		key.Dir = flow.DirForward
		if ev.FlowID != key.Hash() {
			return rules.EvalContext{}, false // not a retained runtime DPI flow
		}
	}
	state := &flow.State{Key: key}
	srcZone, dstZone := resolve(snap, key.OpenerIP(), key.ServerIP())
	pkt := &dpi.ParsedPacket{Proto: ev.Transport, SrcPort: ev.SrcPort, DstPort: ev.DstPort}
	ctx, ok := evalContextFromDPIEvent(snap, state, pkt, decoded, srcZone, dstZone)
	ctx.Now = ev.Timestamp
	return ctx, ok
}

func iecWireEvent(kind string) bool {
	switch kind {
	case "request", "response", "apci", "malformed", "unsupported":
		return true
	default:
		return false
	}
}
