// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"errors"
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

// Inline generic ICS streams in an enforce scope fail closed on the existing
// framing, reassembly and decoder faults. Denied bytes must never become a
// harmless duplicate after cache expiry: the tuple tombstone drops the old
// incarnation and a fresh kernel-tracked handshake retires it. Decoded denies,
// stream failures and midstream pickups all use the same session-only reset.
// Learn-only flows, non-inline packets and the IEC104 path retain their own
// behavior. No DPI failure installs a host or service block.

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
	ctx := stateAddressContext(snap, state, &e.zones)
	for i := range snap.Firewall {
		entry := &snap.Firewall[i]
		if entry.ICS.Protocol == "" || strings.EqualFold(entry.ICS.Protocol, rules.ProtocolIEC104) ||
			e.effectiveMode(entry) != "enforce" || !shouldInspectFirewallEntry(*entry, state, parsed) {
			continue
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

// failClosed drops the packet, resets only its TCP session after completion,
// and records the rule scope and cause. It never installs a kernel block.
func (e *Engine) failClosed(pkt capture.Packet, state *flow.State, parsed *dpi.ParsedPacket, scope *rules.Entry, reason, proto string, cause error) capture.Decision {
	e.denyFlow(state, reason)
	if proto == "" {
		proto = strings.ToLower(scope.ICS.Protocol)
	}
	e.closeDeniedTCP(pkt, state, proto, reason)
	e.eventStore.Append(events.Event{
		FlowID:    state.ID(),
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

// stillDenied keeps a failed stream denied without retrying any block.
func (e *Engine) stillDenied(pkt capture.Packet, state *flow.State) capture.Decision {
	e.denyFlow(state, reasonDPIDeny)
	e.closeDeniedTCP(pkt, state, "", reasonDPIDeny)
	return capture.Decision{Action: capture.Drop, Reason: reasonDPIDeny}
}

// denyFlow caches a denial without installing a kernel block.
func (e *Engine) denyFlow(state *flow.State, reason string) {
	e.verdictCache.Put(state.ID(), verdict.Verdict{Action: verdict.DenyDrop, Reason: reason})
}

// deniedStream reports the error of a stream whose connection the policy
// denied.
func deniedStream(err error) bool {
	var se *dpi.StreamError
	return errors.As(err, &se) && se.Kind == dpi.StreamDenied
}
