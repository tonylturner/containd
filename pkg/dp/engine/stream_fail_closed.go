// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// An inline flow in the scope of an enforce ICS rule fails closed when its
// stream cannot be inspected: a conflicting overlap, a rewritten
// retransmission, framing the decoder rejects, a SYN with a new sequence
// number on its live stream, or a recovered decoder panic drops the packet
// and denies the flow like a decoded denial. The flow's stream stays
// failed instead of restarting at a later segment, so a sender cannot
// choose where framing resumes; only a FIN or RST in window ends it
// before the flow does. Learn-only flows, packets that are not inline and
// the IEC104 path keep passing such packets.
//
// A decoded denial of such a flow fails its stream too (dpi.StreamDenied):
// the denied bytes were consumed, so without it their retransmission would
// pass as a duplicate once the cached denial expired, if the dynamic block
// failed or stalled. Every later packet of the connection drops until the
// flow ends.
//
// A stream picked up mid-connection fails the same way, as an IEC104
// session not observed from its SYN does: after an engine restart, after
// the engine forgot an idle flow, or after the reassembly sweep dropped a
// partial frame, framing could start inside a message. Its connection's
// packets drop until the flow ends, but no flow block is installed: the
// client's next connection anchors at its SYN and is inspected from its
// first byte.

const (
	// reasonStreamFailClosed is the decision reason (logs and metrics).
	reasonStreamFailClosed = "stream_fail_closed"

	// ics.decision reasons of a fail-closed denial.
	failClosedStream    = "stream_error"
	failClosedResync    = "stream_resync"
	failClosedMidStream = "stream_midstream"
	failClosedPanic     = "decoder_panic"
)

// failClosedRule returns the first ICS rule, IEC104 rules aside, whose
// effective mode is enforce and whose L3/L4 scope holds the flow of an
// inline packet, or nil. The scope is the rule's zones, CIDRs, protocol
// and port (the protocol's default port when the rule names none),
// oriented from the connection's opener; ICS predicates, identities and
// schedules do not narrow it.
func (e *Engine) failClosedRule(pkt capture.Packet, state *flow.State, parsed *dpi.ParsedPacket) *rules.Entry {
	if !pkt.Token.Inline() {
		return nil
	}
	p := e.ruleSnap.current.Load()
	if p == nil || p.snapshot == nil {
		return nil
	}
	snap := p.snapshot
	ctx := rules.EvalContext{SrcIP: state.Key.OpenerIP(), DstIP: state.Key.ServerIP()}
	zoned := false
	for i := range snap.Firewall {
		entry := &snap.Firewall[i]
		if entry.ICS.Protocol == "" || strings.EqualFold(entry.ICS.Protocol, rules.ProtocolIEC104) ||
			e.effectiveMode(entry) != "enforce" || !shouldInspectFirewallEntry(*entry, state, parsed) {
			continue
		}
		if !zoned && (len(entry.SourceZones) > 0 || len(entry.DestZones) > 0) {
			ctx.SrcZone, ctx.DstZone = resolveZonesForFlow(snap, ctx.SrcIP, ctx.DstIP)
			zoned = true
		}
		if p.evaluator.AddressScopeMatch(i, ctx) {
			return entry
		}
	}
	return nil
}

// inspectFlow runs DPI on one packet. A panic while inspecting a
// fail-closed packet is recovered, reported like any packet-path panic and
// returned; other panics reach HandlePacket.
func (e *Engine) inspectFlow(state *flow.State, parsed *dpi.ParsedPacket) (res dpi.InspectResult, panicErr error) {
	if parsed.FailClosed {
		defer func() {
			if r := recover(); r != nil {
				res, panicErr = dpi.InspectResult{}, packetPanic(r)
				e.reportPacketPanic(panicErr)
			}
		}()
	}
	return e.dpiMgr.Inspect(state, parsed), nil
}

// isStreamFailure reports a framed stream's error: a *dpi.StreamError or
// the framing decoder's *dpi.FrameError.
func isStreamFailure(res dpi.InspectResult) bool {
	var se *dpi.StreamError
	var fe *dpi.FrameError
	return res.Framed && (errors.As(res.Err, &se) || errors.As(res.Err, &fe))
}

// failClosedReason is the ics.decision reason of a stream failure; a
// failed stream keeps the reason it failed with.
func failClosedReason(err error) string {
	var se *dpi.StreamError
	if errors.As(err, &se) {
		switch se.Kind {
		case dpi.StreamResync:
			return failClosedResync
		case dpi.StreamDecoderPanic:
			return failClosedPanic
		case dpi.StreamMidStream:
			return failClosedMidStream
		}
	}
	return failClosedStream
}

// failClosed drops the packet and denies its flow as a decoded denial does:
// a cached deny, the dynamic flow block once the drop verdict is submitted,
// and an ics.decision event naming the rule whose scope holds the flow and
// the cause. A mid-stream pickup gets no flow block, which would also stop
// the client's next connection.
func (e *Engine) failClosed(tok capture.Token, state *flow.State, parsed *dpi.ParsedPacket, scope *rules.Entry, reason, proto string, cause error) capture.Decision {
	e.denyFlow(tok, state, parsed, reason, reason != failClosedMidStream)
	if proto == "" {
		proto = strings.ToLower(scope.ICS.Protocol)
	}
	e.eventStore.Append(events.Event{
		FlowID:    state.Key.Hash(),
		Proto:     proto,
		Kind:      eventfields.KindDecision,
		Timestamp: time.Now().UTC(),
		SrcIP:     state.Key.SrcIP.String(),
		DstIP:     state.Key.DstIP.String(),
		SrcPort:   state.Key.SrcPort,
		DstPort:   state.Key.DstPort,
		Transport: parsed.Proto,
		Attributes: map[string]any{
			eventfields.KeyDecision: decisionDeny,
			eventfields.KeyRuleID:   scope.ID,
			eventfields.KeyMode:     "enforce",
			eventfields.KeyReason:   reason,
			eventfields.KeyError:    cause.Error(),
		},
	})
	return capture.Decision{Action: capture.Drop, Reason: reasonStreamFailClosed}
}

// stillDenied drops a packet of a connection the policy denied earlier.
// Its stream stays failed (dpi.StreamDenied), so the retransmitted denied
// command drops even after the cached denial expired, whatever the dynamic
// block did. The denial was reported once; this renews the cached deny and
// retries the flow block, without another event.
func (e *Engine) stillDenied(tok capture.Token, state *flow.State, parsed *dpi.ParsedPacket) capture.Decision {
	e.denyFlow(tok, state, parsed, reasonDPIDeny, true)
	return capture.Decision{Action: capture.Drop, Reason: reasonDPIDeny}
}

// denyFlow caches the denial of the flow and, with block, installs the
// dynamic flow block once the drop verdict is submitted.
func (e *Engine) denyFlow(tok capture.Token, state *flow.State, parsed *dpi.ParsedPacket, reason string, block bool) {
	v := verdict.Verdict{Action: verdict.BlockFlowTemp, Reason: reason, TTL: dpiEnforceBlockTTL}
	e.verdictCache.Put(state.Key.Hash(), v)
	if !block {
		return
	}
	e.afterDrop(tok, e.dynamicBlockJob(v, rules.EvalContext{
		SrcIP: state.Key.OpenerIP(),
		DstIP: state.Key.ServerIP(),
		Proto: strings.ToLower(parsed.Proto),
		Port:  strconv.Itoa(int(servicePort(state, parsed))),
	}))
}

// deniedStream reports the error of a stream whose connection the policy
// denied.
func deniedStream(err error) bool {
	var se *dpi.StreamError
	return errors.As(err, &se) && se.Kind == dpi.StreamDenied
}
