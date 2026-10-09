// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// Decision reasons (logs and metrics only).
const (
	reasonCachedDeny    = "cached_deny"
	reasonDPIDeny       = "dpi_deny"
	reasonInvalidMarked = "invalid_in_envelope"
)

var acceptDecision = capture.Decision{Action: capture.Accept}

// envelopeMark is the skb mark value nft sets on packets steered by an
// IEC104 envelope rule, within the mask containd reserves (contracts K1).
const (
	envelopeMarkMask  = 0x0f000000
	envelopeMarkValue = 0x01000000
)

// invalidPacketDecision decides a packet whose tuple cannot be trusted.
// Inside an IEC104 envelope (the nft envelope mark is set) it is dropped
// (fragments, IPv6 extension headers and truncated packets, spec §8.1);
// everything else passes as before.
func invalidPacketDecision(pkt capture.Packet) capture.Decision {
	if pkt.HasMark && pkt.Mark&envelopeMarkMask == envelopeMarkValue {
		return capture.Decision{Action: capture.Drop, Reason: reasonInvalidMarked + ":" + pkt.Invalid}
	}
	return acceptDecision
}

// handleFlowPacket is the wire-oriented path for every protocol except
// IEC104 sessions. A denied ICS message drops the current packet (spec §4.1
// #1) and installs the existing dynamic flow block once the drop verdict is
// submitted; a cached denial drops later packets of the same flow.
func (e *Engine) handleFlowPacket(pkt capture.Packet, state *flow.State) capture.Decision {
	parsed := dpi.ParsedPacket{
		Payload:     pkt.Payload,
		Proto:       pkt.Transport,
		SrcPort:     pkt.SrcPort,
		DstPort:     pkt.DstPort,
		TCPSeq:      pkt.TCP.Seq,
		TCPSeqValid: pkt.TCP.Valid,
	}
	defer e.endStreamsOnClose(state, &parsed, pkt.TCP)

	flowHash := state.Key.Hash()
	shouldInspect := e.ShouldInspect(state, &parsed)
	if cached, ok := e.verdictCache.Get(flowHash); ok {
		if cached.Action != verdict.AllowContinue {
			return capture.Decision{Action: capture.Drop, Reason: reasonCachedDeny}
		}
		// Inspectable flows must continue through DPI so later
		// payload-bearing packets are decoded; otherwise a SYN/ACK
		// could suppress the whole flow.
		if !shouldInspect {
			return acceptDecision
		}
	}
	if !shouldInspect {
		// Cache an ALLOW verdict for non-inspected flows so we don't
		// re-evaluate ShouldInspect on every packet.
		e.verdictCache.Put(flowHash, verdict.Verdict{Action: verdict.AllowContinue})
		return acceptDecision
	}
	if isIECPort(pkt) {
		// IEC104 is parsed only on a session tracked from its SYN
		// (HasOffset, contracts K2); outside every envelope it passes
		// unparsed, as before.
		return acceptDecision
	}
	// Events come before the error: a stream error's malformed event is
	// already among them, and the packet itself passes (spec §4.2).
	evs, _ := e.dpiMgr.OnPacket(state, &parsed)
	e.RecordDPIEvents(state, &parsed, evs)
	v, evalCtx, enforced := e.enforceDPIEvents(state, &parsed, evs)
	if !enforced {
		return acceptDecision
	}
	e.verdictCache.Put(flowHash, v)
	e.afterDrop(pkt.Token, e.dynamicBlockJob(v, evalCtx))
	return capture.Decision{Action: capture.Drop, Reason: reasonDPIDeny}
}

// dynamicBlockJob installs the existing US dynamic block for a denied flow.
// It runs on the block worker, never on the packet path, so an updater
// failure cannot turn the drop into an accept.
func (e *Engine) dynamicBlockJob(v verdict.Verdict, evalCtx rules.EvalContext) func() {
	updater := e.updater
	onError := e.onError
	return func() {
		if updater == nil {
			return
		}
		if err := applyVerdict(context.Background(), updater, v, evalCtx); err != nil && onError != nil {
			onError(fmt.Errorf("dynamic block %s: %w", v.Action, err))
		}
	}
}

// afterDrop runs job once the drop verdict of tok is submitted. A packet that
// is not inline has no verdict, so the job is queued at once.
func (e *Engine) afterDrop(tok capture.Token, job func()) {
	if tok.Inline() {
		if e.hooks.after.add(tok, job) {
			return
		}
		e.hooks.reportWorkerOverflow("verdict follow-up set full")
		return
	}
	if !e.hooks.blocks.submit(job) {
		e.hooks.reportWorkerOverflow("block worker queue full")
	}
}

// endStreamsOnClose drops the stream buffers of a flow that sent FIN or RST;
// a RST also ends the reverse direction.
func (e *Engine) endStreamsOnClose(state *flow.State, pkt *dpi.ParsedPacket, tcp capture.TCPMeta) {
	if !tcp.Valid || tcp.Flags&(capture.TCPFlagFIN|capture.TCPFlagRST) == 0 {
		return
	}
	e.endFlowStream(state, pkt)
	if tcp.Flags&capture.TCPFlagRST == 0 {
		return
	}
	rev := state.Key
	rev.SrcIP, rev.DstIP = state.Key.DstIP, state.Key.SrcIP
	rev.SrcPort, rev.DstPort = state.Key.DstPort, state.Key.SrcPort
	e.flowMu.Lock()
	revState := e.flows[rev.Hash()]
	e.flowMu.Unlock()
	if revState != nil {
		e.endFlowStream(revState, pkt)
	}
}

// endFlowStream ends one directional legacy stream and records any events
// the decoders emit at flow end.
func (e *Engine) endFlowStream(state *flow.State, pkt *dpi.ParsedPacket) {
	evs, _ := e.dpiMgr.OnFlowEnd(state)
	if len(evs) > 0 {
		e.RecordDPIEvents(state, pkt, evs)
	}
}

func isIECPort(pkt capture.Packet) bool {
	return pkt.Proto == 6 && (pkt.SrcPort == iec104Port || pkt.DstPort == iec104Port)
}
