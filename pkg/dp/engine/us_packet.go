// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// Decision reasons (logs and metrics only).
const (
	reasonCachedDeny     = "cached_deny"
	reasonDPIDeny        = "dpi_deny"
	reasonInvalidMarked  = "invalid_in_envelope"
	reasonPolicyNonAdmit = "policy_non_admit"
)

var acceptDecision = capture.Decision{Action: capture.Accept}

// invalidPacketDecision decides a packet whose tuple cannot be trusted.
// An enforcing scope or IEC104 envelope vetoes an unreconstructable packet.
// Other inline invalid packets continue to kernel admission, never NF_ACCEPT.
func invalidPacketDecision(pkt capture.Packet) capture.Decision {
	if envelopeMarked(pkt) || pkt.HasMark && pkt.Mark&markabi.EnforceScopeMark != 0 {
		return capture.Decision{Action: capture.Drop, Reason: reasonInvalidMarked + ":" + pkt.Invalid}
	}
	if pkt.Token.Inline() {
		return observedDecision(pkt, acceptDecision)
	}
	return acceptDecision
}

// handleFlowPacket is the wire-oriented path for every protocol except
// IEC104 sessions. Explicit ICS denials and scoped stream failures drop
// directly; decoded default/plain-rule denials repeat with a non-admitting
// mark for ordered kernel admission. Both close a scoped TCP stream and
// schedule best-effort peer resets after verdict completion. Failed streams
// retain their respective denial until a new handshake or scope removal.
func (e *Engine) handleFlowPacket(pkt capture.Packet, state *flow.State, correlationAdmitted, decodingStopped, observeOnly bool) (d capture.Decision) {
	e.recordPacketStats(pkt, state)
	e.iec.answerPickupChallenge(pkt)
	if e.isDeniedTCP(state) {
		// A retained denial from a removed enforce scope owns no admission.
		if observeOnly {
			return acceptDecision
		}
		noteCorrelationInspection(state, pkt, false)
		return capture.Decision{Action: capture.Drop, Reason: reasonCachedDeny}
	}
	parsed := dpi.ParsedPacket{
		Timestamp:    pkt.Timestamp,
		Payload:      pkt.Payload,
		Proto:        pkt.Transport,
		SrcPort:      pkt.SrcPort,
		DstPort:      pkt.DstPort,
		TCPSeq:       pkt.TCP.Seq,
		TCPSeqValid:  pkt.TCP.Valid,
		TCPSyn:       pkt.TCP.Flags&capture.TCPFlagSYN != 0,
		TCPHandshake: handshakeMarked(pkt),
		TCPFin:       pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagFIN != 0,
		TCPRst:       pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagRST != 0,
	}
	if parsed.TCPSyn {
		parsed.TCPSeq++
	}
	defer func() { e.endStreamsOnClose(state, &parsed, d.Action == capture.Accept) }()

	flowHash := state.ID()
	if !decodingStopped {
		e.observeDomainExclusions(state, &parsed)
	}
	shouldInspect := e.ShouldInspect(state, &parsed)
	if !shouldInspect {
		noteCorrelationInspection(state, pkt, false)
	}
	if cached, ok := e.verdictCache.Get(flowHash); ok {
		switch {
		case cached.Action == verdict.AllowContinue:
			// Inspectable flows must continue through DPI so later
			// payload-bearing packets are decoded; otherwise a SYN/ACK
			// could suppress the whole flow.
			if !shouldInspect {
				return acceptDecision
			}
		default:
			if !observeOnly {
				noteCorrelationInspection(state, pkt, false)
				return capture.Decision{Action: capture.Drop, Reason: reasonCachedDeny}
			}
		}
	}
	if !shouldInspect {
		// Cache an ALLOW verdict for non-inspected flows so we don't
		// re-evaluate ShouldInspect on every packet.
		e.verdictCache.Put(flowHash, verdict.Verdict{Action: verdict.AllowContinue})
		return acceptDecision
	}
	if isIECFlow(state) {
		// IEC104 is parsed only on a session tracked from its SYN
		// (HasOffset); outside every envelope it passes
		// unparsed, as before.
		return acceptDecision
	}
	if decodingStopped {
		noteCorrelationInspection(state, pkt, false)
		return acceptDecision
	}
	noteCorrelationInspection(state, pkt, correlationAdmitted)
	scope := e.failClosedRule(pkt, state, &parsed)
	parsed.FailClosed = scope != nil
	res, panicErr := e.inspectFlow(state, &parsed)
	if panicErr != nil {
		e.dpiMgr.FailStream(state, &parsed, dpi.StreamDecoderPanic)
		return e.failClosed(pkt, state, &parsed, scope, failClosedPanic, "", panicErr)
	}
	var streamErr *dpi.StreamError
	if scope != nil && errors.As(res.Err, &streamErr) && streamErr.Kind == dpi.StreamNonAdmit {
		return nonAdmitDecision(pkt)
	}
	// Events come before the error: a stream error's malformed event is
	// already among them. Outside an enforce scope the packet itself passes.
	e.RecordDPIEvents(state, &parsed, res.Events)
	v, evalCtx, enforced := e.enforceDPIEvents(state, &parsed, res.Events, scope != nil && (deniedStream(res.Err) || isStreamFailure(res)))
	if enforced && v.Reason != reasonPolicyNonAdmit {
		if pkt.Proto != 17 {
			e.verdictCache.Put(flowHash, v)
		}
		if scope != nil {
			e.dpiMgr.FailStream(state, &parsed, dpi.StreamDenied)
		}
		reason := reasonDPIDeny
		if v.Reason == reasonNonconformant {
			reason = reasonNonconformant
		}
		e.closeDeniedTCP(pkt, state, evalCtx.ICS.Protocol, reason)
		return capture.Decision{Action: capture.Drop, Reason: reason}
	}
	if scope != nil && deniedStream(res.Err) {
		return e.stillDenied(pkt, state)
	}
	if scope != nil && isStreamFailure(res) {
		reason := failClosedReason(res.Err)
		denied := e.failClosed(pkt, state, &parsed, scope, reason, res.Proto, res.Err)
		return denied
	}
	if enforced {
		d := nonAdmitDecision(pkt)
		if scope != nil {
			// DPI has consumed these bytes, not delivered them. Preserve the
			// denial in stream state so a TCP retry cannot become an admitting
			// duplicate, including after verdict-cache expiry. Kernel admission
			// still owns DROP versus RESET on every repeated traversal.
			e.dpiMgr.FailStream(state, &parsed, dpi.StreamNonAdmit)
			if pkt.Token.Inline() && pkt.Proto == 6 {
				if guard := e.rememberDeniedTCP(state.Key, state.ServiceKey(), true); guard != nil {
					e.resetDeniedTCP(pkt, state, evalCtx.ICS.Protocol, reasonPolicyNonAdmit, guard)
					// Repeat normally has no completion callback. Request one
					// so reset I/O follows submission of this continuation.
					d.Notify = true
				}
			}
		}
		return d
	}
	return acceptDecision
}

func nonAdmitDecision(pkt capture.Packet) capture.Decision {
	return capture.Decision{Action: capture.Repeat, Mark: markabi.Continue(pkt.Mark, true), Reason: reasonPolicyNonAdmit}
}

// afterPacketVerdict runs job once tok's verdict completes. Non-Drop callers
// must request capture notification. A non-inline job is queued at once.
func (e *Engine) afterPacketVerdict(tok capture.Token, job func()) {
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

// endStreamsOnClose ends the stream of a flow direction that sent FIN or
// RST; a RST also ends the reverse direction. A fail-closed packet ends
// streams only when it was accepted, since a dropped segment never reaches
// the receiver, and only when it is in window (dpi.Manager.CloseStream).
// No close ends a failed stream.
func (e *Engine) endStreamsOnClose(state *flow.State, pkt *dpi.ParsedPacket, accepted bool) {
	if !pkt.TCPFin && !pkt.TCPRst || pkt.FailClosed && !accepted {
		return
	}
	ended, evs, _ := e.dpiMgr.CloseStream(state, pkt)
	e.recordFlowEndEvents(state, pkt, evs)
	if ended {
		e.conformance.end(state, pkt.TCPRst)
		e.closeCorrelation(state, pkt.TCPRst, false)
	}
	if !ended || !pkt.TCPRst {
		return
	}
	revState := e.peerFlow(state)
	if revState != nil {
		evs, _ := e.dpiMgr.ResetStream(revState, pkt)
		e.recordFlowEndEvents(revState, pkt, evs)
	}
}

// endFlowStream ends one directional legacy stream at its flow's end and
// records any events the decoders emit.
func (e *Engine) endFlowStream(state *flow.State, pkt *dpi.ParsedPacket) {
	evs, _ := e.dpiMgr.OnFlowEnd(state)
	e.recordFlowEndEvents(state, pkt, evs)
	reverse := e.peerFlow(state)
	e.conformance.end(state, reverse == nil)
	e.closeCorrelation(state, false, true)
}

func (e *Engine) recordFlowEndEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if len(evs) > 0 && !e.decodingStopped(state) {
		e.RecordDPIEvents(state, pkt, evs)
	}
}

// packetPanic is the error of a recovered packet-path panic.
func packetPanic(r any) error {
	return fmt.Errorf("engine: packet handler panic: %v", r)
}

// reportPacketPanic logs a recovered packet-path panic and reports it as a
// worker health fault.
func (e *Engine) reportPacketPanic(err error) {
	if e.onError != nil {
		e.onError(err)
	}
	e.iec.health.fault(faultWorker, err.Error())
}

func isIECPort(pkt capture.Packet) bool {
	return pkt.Proto == 6 && (pkt.SrcPort == iec104Port || pkt.DstPort == iec104Port)
}

// envelopeMarked reports a packet nft steered to the queue under an IEC104
// envelope rule (the nft envelope mark).
func envelopeMarked(pkt capture.Packet) bool {
	return pkt.HasMark && enforce.EnvelopeMarked(pkt.Mark)
}

// handshakeMarked reports a packet that nft queued under a generic ICS
// rule in a connection whose handshake connection tracking has not seen
// complete (enforce.HandshakeMark).
func handshakeMarked(pkt capture.Packet) bool {
	return pkt.HasMark && enforce.HandshakeMarked(pkt.Mark)
}

// HandlePacket is the handler given to capture; offline replays and tests
// may call it too. A panic in packet
// handling must not crash the process from the capture goroutine: it is
// recovered, logged and reported as a worker health fault. The packet is
// dropped when nft marked it as IEC104 envelope traffic (fail closed) and
// accepted otherwise, as 0.1.31 always did. A decoder panic on an inline
// flow in an enforce ICS scope is recovered earlier and drops the flow
// (inspectFlow).
func (e *Engine) HandlePacket(pkt capture.Packet) (d capture.Decision) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		e.reportPacketPanic(packetPanic(r))
		d = acceptDecision
		if pkt.Token.Inline() {
			d = observedDecision(pkt, acceptDecision)
		}
		if envelopeMarked(pkt) {
			d = capture.Decision{Action: capture.Drop, Reason: reasonIECFailClose}
		}
	}()
	// Invalid packets never reach either flow handler; their tuple is untrusted.
	if pkt.Invalid != "" {
		e.recordPacketStats(pkt, nil)
		if pkt.CaptureIncomplete || pkt.Invalid == capture.InvalidTruncated {
			e.recordLearnPacketLoss(pkt)
		}
	}
	return e.handlePacket(pkt)
}
