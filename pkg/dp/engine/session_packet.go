// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// IEC104 decision reasons (logs and metrics only).
const (
	reasonIECAccept         = "iec104"
	reasonIECHold           = "iec104_hold"
	reasonIECAbort          = "iec104_abort"
	reasonIECTombstone      = "iec104_tombstone"
	reasonIECClosed         = "iec104_closed"
	reasonIECFailClose      = "iec104_fail_closed"
	reasonIECInvalid        = "iec104_invalid"
	reasonIECUntracked      = "iec104_untracked"
	reasonIECEstablishedSYN = "iec104_established_syn"
)

// sessionResult is the outcome of one session envelope packet. Its actions are
// carried out after the session lock is released; drops of held tokens are
// already in decision.Resolved.
type sessionResult struct {
	decision     capture.Decision
	inspect      []dpi.Event  // decoder events, recorded like any DPI events
	findings     []iecFinding // judged events with conformance findings
	acts         sessionActions
	stateLimit   bool
	failure      pairReason
	messages     []sessionMessageDecision
	policyReason string
	streamErr    error
	streamScope  *rules.Entry
	packetPanic  error
	trigger      string
}

func accepted(reason string) sessionResult {
	return sessionResult{decision: capture.Decision{Action: capture.Accept, Reason: reason}}
}

func dropped(reason string) sessionResult {
	return sessionResult{decision: capture.Decision{Action: capture.Drop, Reason: reason}}
}

// Invalid transport input cannot change delivery in an observation session.
func invalidSession(mode string) sessionResult {
	if mode == "enforce" {
		return dropped(reasonIECInvalid)
	}
	return accepted(reasonIECInvalid)
}

// droppedWith drops the current packet and every held token of acts.
func droppedWith(reason string, acts sessionActions) sessionResult {
	res := dropped(reason)
	res.decision.Resolved = acts.drops
	acts.drops = nil
	res.acts = acts
	return res
}

func (res sessionResult) aborting(reason string, acts sessionActions) sessionResult {
	res.decision = capture.Decision{Action: capture.Drop, Reason: reason, Resolved: acts.drops}
	acts.drops = nil
	res.acts.merge(acts)
	return res
}

func dpiDir(dir int) dpi.StreamDir {
	if dir == sessionDirClient {
		return dpi.ClientToServer
	}
	return dpi.ServerToClient
}

func dirName(dir int) string {
	if dir == sessionDirClient {
		return "request"
	}
	return "response"
}

// handleSessionPacket decides a TCP packet to or from port 2404 when an IEC104
// envelope may apply. ok is false for packets outside every envelope; they
// take the flow path unchanged. The packet is judged in the IEC104 parsing
// mode in force now; conformance alerts and the connection's alert identity
// are the engine's, so they are settled here, after the table decided.
func (e *Engine) handleSessionPacket(pkt capture.Packet, state *flow.State, stopped bool) (capture.Decision, bool) {
	t := e.sessions
	if t == nil || sessionProtocol(state) == "" && !e.sessionOwnsState(pkt, state) {
		return capture.Decision{}, false
	}
	if e.bypassObservedSession(pkt, state, stopped) {
		return acceptDecision, true
	}
	res, ok := t.packet(pkt, state, e.ICSParsing(sessionProtocol(state)))
	if !ok {
		t.finish(res.acts)
		if envelopeMarked(pkt) {
			// nft steered this packet as IEC104 envelope traffic, but the
			// engine finds no envelope for it: fail closed rather than let
			// it through uninspected.
			e.recordPacketStats(pkt, state)
			t.countAbort(abortFailClose)
			t.health.fault(faultEnvelope, "nft steering and the engine envelope disagree")
			return capture.Decision{Action: capture.Drop, Reason: reasonIECFailClose}, true
		}
		return capture.Decision{}, false
	}
	e.recordPacketStats(pkt, state)
	if res.packetPanic != nil {
		e.reportPacketPanic(res.packetPanic)
	}
	noteCorrelationInspection(state, pkt, !res.stateLimit && res.failure == "")
	if res.stateLimit {
		e.recordLearnPacketLoss(pkt)
	}
	parsed := dpi.ParsedPacket{Payload: pkt.Payload, Proto: pkt.Transport, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	if len(res.inspect) > 0 {
		e.RecordDPIEvents(state, &parsed, res.inspect)
	}
	e.recordSessionMessages(state, &parsed, res)
	if res.streamErr != nil && res.streamScope != nil {
		e.recordFailClosedDecision(state, &parsed, res.streamScope, failClosedReason(res.streamErr), sessionProtocol(state), res.streamErr)
	}
	for _, f := range res.findings {
		e.recordConformanceAlert(state, &parsed, f.ev, iecConformanceAction(res.decision, f.decision))
	}
	if res.acts.retired {
		e.conformance.end(state, true)
	}
	t.finish(res.acts)
	return res.decision, true
}

// iecConformanceAction names the outcome of an event with findings for its
// conformance alert: a dropped packet aborted the session (every judged
// event of the packet goes with it), a non-allow decision would have, and
// an allowed event passed.
func iecConformanceAction(packet capture.Decision, decision string) string {
	switch {
	case packet.Action == capture.Drop:
		return "dropped and reset"
	case decision != decisionAllow:
		return "would drop"
	default:
		return "passed"
	}
}

func (t *sessionTable) packet(pkt capture.Packet, state *flow.State, parsing ics.Parsing) (result sessionResult, handled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pressureOffline = false
	t.parsing = parsing
	if !t.hasSessions {
		return sessionResult{}, false
	}
	now := t.now()
	src, okSrc := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, okDst := addrPort(pkt.DstIP, pkt.DstPort)
	if !okSrc || !okDst {
		return t.nonIPv4Locked(state)
	}
	s, dir := t.lookupPacketLocked(src, dst, state)
	var retired sessionActions
	defer func() { result.acts.merge(retired) }()
	if s != nil && s.state == sessionAborted && s.denialExpired(now) {
		retired.merge(t.deleteLocked(sessionKey{s.client, s.server}, s))
		s, dir = t.lookupPacketLocked(src, dst, state)
	}
	for s != nil && s.resetIO != nil && replacementHandshake(s, dir, pkt) {
		done := s.resetIO
		t.mu.Unlock()
		<-done
		t.mu.Lock()
		s, dir = t.lookupPacketLocked(src, dst, state)
		now = t.now()
	}
	defer func() {
		if !handled {
			return
		}
		owner, _ := t.lookupPacketLocked(src, dst, state)
		if owner == nil {
			return
		}
		v := capture.Verdict(0)
		switch result.decision.Action {
		case capture.Accept, capture.Repeat:
			v = capture.VerdictRepeat
		case capture.Drop:
			v = capture.VerdictDrop
		}
		t.rememberTokenLocked(owner, pkt.Token, v)
	}()
	if s != nil {
		if evidence := state.InlinePolicy.Load(); evidence != nil && s.flow != nil {
			copy := *evidence
			copy.Service = s.flow.Key
			s.flow.InlinePolicy.Store(&copy)
		}
		s.ctx = t.sessionContext(s)
		if !synRST(pkt.TCP.Flags) {
			if res, ok := t.replacementLocked(s, dir, pkt, now); ok {
				return res, true
			}
		}
	}
	switch {
	case synRST(pkt.TCP.Flags):
		return t.synRSTLocked(s, state)
	case s == nil:
		return t.newPacketLocked(pkt, src, dst, state, now)
	case s.state == sessionAborted:
		return t.tombstonePacketLocked(s, dir, pkt, state, now)
	case s.state == sessionClosed:
		return t.closedPacketLocked(s, dir, pkt, state, now)
	case reopensLocked(s, dir, pkt):
		return t.reopenLocked(s, dir, pkt, state, now)
	default:
		res := t.livePacketLocked(s, dir, pkt, state, now)
		res.decision.Notify = res.decision.Notify || t.iecAdapter.notifyLocked(pkt.Token)
		return res, true
	}
}

// nonIPv4Locked drops IPv6 traffic inside an enforce envelope.
func (t *sessionTable) nonIPv4Locked(state *flow.State) (sessionResult, bool) {
	ctx := t.stateContext(state)
	matched, mode := t.envelopeLocked(ctx)
	if !matched || mode != "enforce" {
		return sessionResult{}, false
	}
	return dropped(reasonIECInvalid), true
}

func isSYN(f capture.TCPFlags) bool { return f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagACK == 0 }

func synRST(f capture.TCPFlags) bool { return f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagRST != 0 }

// synRSTLocked decides a segment carrying both SYN and RST, which is no
// handshake segment: it never opens, establishes, refuses or closes an
// incarnation, so a SYN-ACK with RST cannot establish one whose client it
// resets. An enforcing session or envelope drops it; monitor sessions
// observe it without changing delivery, and untracked monitor traffic passes
// like every other monitor packet not observed from its SYN.
func (t *sessionTable) synRSTLocked(s *trackedSession, state *flow.State) (sessionResult, bool) {
	if s != nil {
		_, mode := t.envelopeLocked(t.sessionContext(s))
		return invalidSession(mode), true
	}
	matched, mode := t.envelopeLocked(t.stateContext(state))
	if !matched {
		return sessionResult{}, false
	}
	if mode == "enforce" {
		return dropped(reasonIECInvalid), true
	}
	return accepted(reasonIECAccept), true
}

// opens reports whether a client SYN may start a session or incarnation of
// mode: in an enforce envelope only a SYN of a handshake that connection
// tracking has not seen complete (handshakeMarked). One sent into an
// established connection would let its sender choose where the session's
// byte stream starts.
func opens(mode string, pkt capture.Packet) bool {
	return mode != "enforce" || handshakeMarked(pkt)
}

// newPacketLocked handles a packet of no known session: a SYN to 2404 opens
// one; any other packet was not observed from its SYN. An enforce SYN sent
// into an established connection opens nothing and, without payload,
// passes: the server answers it with a challenge ACK, a packet not
// observed from its SYN, and that closes the connection.
func (t *sessionTable) newPacketLocked(pkt capture.Packet, src, dst netip.AddrPort, state *flow.State, now time.Time) (sessionResult, bool) {
	if isSYN(pkt.TCP.Flags) && t.iecAdapter.acceptsSYN(state) {
		ctx := t.stateContext(state)
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			return sessionResult{}, false
		}
		if !pkt.Token.Inline() && sessionProtocol(state) != iecProtocol {
			mode = "monitor"
		}
		if !opens(mode, pkt) {
			if len(pkt.Payload) > 0 {
				return dropped(reasonIECInvalid), true
			}
			return accepted(reasonIECEstablishedSYN), true
		}
		return t.openLocked(nil, src, dst, ctx, mode, pkt, state, now), true
	}
	client, server := src, dst
	if state.ServiceKey().Dir == flow.DirReverse {
		client, server = dst, src
	}
	ctx := t.stateContext(state)
	matched, mode := t.envelopeLocked(ctx)
	if !matched {
		return sessionResult{}, false
	}
	if !pkt.Token.Inline() && sessionProtocol(state) != iecProtocol {
		mode = "monitor"
	}
	if mode == "monitor" && sessionProtocol(state) != iecProtocol && len(pkt.Payload) > 0 {
		return t.observePickupLocked(client, server, ctx, pkt, state, now), true
	}
	if mode != "enforce" || pkt.TCP.Flags&capture.TCPFlagRST != 0 && len(pkt.Payload) == 0 {
		// Monitor: observed, never parsed mid-stream. A bare RST closes.
		return accepted(reasonIECAccept), true
	}
	return t.midstreamLocked(client, server, ctx, pkt, src == client, state, now), true
}

// openLocked starts a new incarnation from its SYN. prev is the tombstone
// or closed session of the same tuple, if any.
func (t *sessionTable) openLocked(prev *trackedSession, client, server netip.AddrPort, ctx rules.EvalContext, mode string, pkt capture.Packet, state *flow.State, now time.Time) sessionResult {
	// The bound counts tuple keys; a retained tuple reuses its existing key.
	if prev == nil && t.fullLocked() {
		t.ledger.Record(limits.TableIECSessions, limits.ReasonRefused, limits.Mode(mode))
		if mode == "enforce" {
			t.countAbort(abortBound)
			return dropped(reasonIECFailClose)
		}
		// Observation loss continues under ordinary policy, without an
		// incarnation or byte stream. Housekeeping coalesces the limit event.
		return accepted(reasonIECUntracked)
	}
	if len(pkt.Payload) > 0 {
		return invalidSession(mode) // SYN with data cannot open a tracked session.
	}
	if mode == "enforce" && !t.health.injectorReady() {
		// No session can be reset: none may start.
		t.countAbort(abortInjector)
		return dropped(reasonIECFailClose)
	}
	n := t.allocateSessionLocked(client, server, ctx, mode, state, now)
	if n == nil {
		return t.admissionLimitLocked(mode)
	}
	if err := t.allocateDirLocked(n, sessionDirClient, pkt.TCP.Seq); err != nil {
		n.releaseInspection()
		return t.admissionLimitLocked(mode)
	}
	_, n.reconnects = t.reconnect[pairKey(client, server)]
	key := sessionKey{client: client, server: server}
	switch {
	case prev != nil && (prev.state == sessionAborted || prev.state == sessionEstablished):
		prev.next.releaseInspection()
		prev.next = n // the tombstone retires once the handshake validates
	default:
		t.sessions[key] = n
		prev.releaseInspection()
	}
	res := accepted(reasonIECAccept)
	res.acts.retired = prev == nil || prev.state == sessionClosed
	return res
}

// midstreamLocked drops a packet of a session not observed from its SYN
// inside an enforce envelope and resets that session once. The
// tombstone then drops its later packets.
func (t *sessionTable) midstreamLocked(client, server netip.AddrPort, ctx rules.EvalContext, pkt capture.Packet, fromClient bool, state *flow.State, now time.Time) sessionResult {
	if t.fullLocked() {
		t.ledger.Record(limits.TableIECSessions, limits.ReasonRefused, limits.ModeEnforce)
		// Unobserved enforce traffic must not bypass the shared table bound.
		t.countAbort(abortBound)
		return dropped(reasonIECFailClose)
	}
	s := t.allocateSessionLocked(client, server, ctx, "enforce", state, now)
	if s == nil {
		return t.admissionLimitLocked("enforce")
	}
	t.sessions[sessionKey{client: client, server: server}] = s
	dir := sessionDirSrv
	if fromClient {
		dir = sessionDirClient
	}
	acts := t.abortLocked(s, abortMidstream, "", &heldPacket{tok: pkt.Token, dir: dir}, now)
	src, dst := client, server
	if !fromClient {
		src, dst = server, client
	}
	toReceiver, toSender, hasSender := observedResets(src, dst, pkt.TCP)
	s.reset.targets[1-dir] = resetTarget{valid: true, r: toReceiver}
	if hasSender {
		s.reset.targets[dir] = resetTarget{valid: true, r: toSender}
	}
	res := droppedWith(reasonIECAbort, acts)
	t.streamFailureLocked(s, &res, &dpi.StreamError{Kind: dpi.StreamMidStream, Proto: sessionProtocol(state)})
	return res
}

// tombstonePacketLocked drops every packet of an aborted incarnation and
// answers challenge ACKs. A SYN with a new ISN starts the next incarnation
// (opens); a retransmitted old SYN does not. The server's SYN-ACK of the
// next incarnation, or its RST refusing that SYN (refuses), passes.
func (t *sessionTable) tombstonePacketLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (sessionResult, bool) {
	ctx := t.sessionContext(s)
	_, currentMode := t.envelopeLocked(ctx)
	tombstone := accepted(reasonIECTombstone)
	if currentMode == "enforce" {
		tombstone = dropped(reasonIECTombstone)
		if s.nonAdmit {
			tombstone.decision = nonAdmitDecision(pkt)
		}
	}
	f := pkt.TCP.Flags
	if dir == sessionDirClient && isSYN(f) {
		if c := s.dirs[sessionDirClient]; c != nil && c.isn == pkt.TCP.Seq {
			return tombstone, true
		}
		if s.next != nil && s.next.dirs[sessionDirClient].isn == pkt.TCP.Seq {
			return accepted(reasonIECAccept), true
		}
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			acts := t.deleteLocked(sessionKey{client: s.client, server: s.server}, s)
			return sessionResult{acts: acts}, false
		}
		if !opens(mode, pkt) {
			return tombstone, true
		}
		return t.openLocked(s, s.client, s.server, ctx, mode, pkt, state, now), true
	}
	if currentMode == "enforce" {
		tombstone.acts = t.challengeLocked(s, dir, pkt, now)
	}
	return tombstone, true
}

// closedPacketLocked passes the payload-free tail of a closed session and
// lets a new SYN open the next incarnation (opens).
func (t *sessionTable) closedPacketLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (sessionResult, bool) {
	if dir == sessionDirClient && isSYN(pkt.TCP.Flags) && pkt.TCP.Seq != s.dirs[sessionDirClient].isn {
		ctx := t.stateContext(state)
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			acts := t.deleteLocked(sessionKey{client: s.client, server: s.server}, s)
			return sessionResult{acts: acts}, false
		}
		if opens(mode, pkt) {
			return t.openLocked(s, s.client, s.server, ctx, mode, pkt, state, now), true
		}
	}
	_, mode := t.envelopeLocked(t.sessionContext(s))
	if len(pkt.Payload) > 0 && mode == "enforce" {
		return dropped(reasonIECClosed), true
	}
	return accepted(reasonIECClosed), true
}

// reopensLocked reports a client SYN that starts a new connection on the
// tuple of an established incarnation: a new ISN, no payload, and the
// handshake mark, so connection tracking no longer holds the old
// connection.
func reopensLocked(s *trackedSession, dir int, pkt capture.Packet) bool {
	return s.state == sessionEstablished && dir == sessionDirClient && isSYN(pkt.TCP.Flags) &&
		(s.dirs[sessionDirClient] == nil || pkt.TCP.Seq != s.dirs[sessionDirClient].isn) && len(pkt.Payload) == 0 && handshakeMarked(pkt)
}

// reopenLocked ends an established incarnation whose tuple a new
// connection's SYN proposes. No old history retires until a peer SYN-ACK
// validates the proposal.
func (t *sessionTable) reopenLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (sessionResult, bool) {
	return t.openLocked(s, s.client, s.server, t.stateContext(state), s.mode, pkt, state, now), true
}

// handshakeLocked follows the SYN and SYN-ACK of a live incarnation. A
// client SYN with a new ISN sent into an established incarnation, as a
// client that lost its connection and reconnects from the same port
// sends, passes and changes nothing: the server answers it with a
// challenge ACK, and the RST the client sends in reply closes the
// incarnation (rstLocked). A SYN with payload is dropped.
func (t *sessionTable) handshakeLocked(s *trackedSession, dir int, pkt capture.Packet, now time.Time) sessionResult {
	f, seq := pkt.TCP.Flags, pkt.TCP.Seq
	if len(pkt.Payload) > 0 {
		return invalidSession(s.mode)
	}
	c2s := s.dirs[sessionDirClient]
	switch {
	case dir == sessionDirClient && f&capture.TCPFlagACK == 0:
		if seq == c2s.isn {
			return accepted(reasonIECAccept)
		}
		if s.dirs[sessionDirSrv] != nil {
			return accepted(reasonIECEstablishedSYN)
		}
		if opens(s.mode, pkt) {
			if err := t.allocateDirLocked(s, sessionDirClient, seq); err != nil {
				return t.inspectionLimitLocked(s, &heldPacket{tok: pkt.Token, dir: dir}, now)
			}
			return accepted(reasonIECAccept)
		}
	case dir == sessionDirSrv && f&capture.TCPFlagACK != 0 && pkt.TCP.Ack == c2s.isn+1:
		if s2c := s.dirs[sessionDirSrv]; s2c == nil {
			if err := t.allocateDirLocked(s, sessionDirSrv, seq); err != nil {
				return t.inspectionLimitLocked(s, &heldPacket{tok: pkt.Token, dir: dir}, now)
			}
			s.state, s.lastSeen = sessionEstablished, now
			return accepted(reasonIECAccept)
		} else if s2c.isn == seq {
			return accepted(reasonIECAccept)
		}
	}
	return invalidSession(s.mode)
}

// livePacketLocked decides a packet of a live incarnation.
func (t *sessionTable) livePacketLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) sessionResult {
	s.lastSeen = now
	f := pkt.TCP.Flags
	enforce := s.mode == "enforce"
	if f&capture.TCPFlagSYN != 0 {
		if s.stopParse {
			return accepted(reasonIECAccept)
		}
		return t.handshakeLocked(s, dir, pkt, now)
	}
	if res := t.resumeObservationLocked(s, dir, pkt, now); res != nil {
		return *res
	}
	if s.dirs[sessionDirSrv] == nil && (enforce || sessionProtocol(s.flow) == iecProtocol) {
		if refuses(s, dir, pkt) {
			res := accepted(reasonIECClosed)
			res.acts.merge(t.closeLocked(s, now))
			return res
		}
		if enforce {
			return dropped(reasonIECInvalid) // nothing else before the SYN-ACK
		}
		return accepted(reasonIECAccept)
	}
	if !s.stopParse && s.dirs[1-dir] != nil && f&capture.TCPFlagACK != 0 {
		if err := t.ackLocked(s, 1-dir, pkt.TCP.Ack); err != nil {
			return t.inspectionLimitLocked(s, &heldPacket{tok: pkt.Token, dir: dir}, now)
		}
	}
	if f&capture.TCPFlagRST != 0 {
		return t.rstLocked(s, dir, pkt, now)
	}
	if s.stopParse {
		res := accepted(reasonIECAccept)
		if f&capture.TCPFlagFIN != 0 {
			t.finLocked(s, dir, pkt, &res)
		}
		return res
	}
	res := accepted(reasonIECAccept)
	if len(pkt.Payload) > 0 {
		res = t.dataLocked(s, dir, pkt, state, now)
		if s.state == sessionAborted {
			return res
		}
	}
	if f&capture.TCPFlagFIN != 0 && res.decision.Action == capture.Accept {
		t.finLocked(s, dir, pkt, &res)
	}
	return res
}

// refuses reports the server's RST that refuses the client's SYN of s, an
// incarnation awaiting its SYN-ACK: no payload, and the ACK the client
// accepts in SYN-SENT, one past its ISN (RFC 9293). It reaches the client,
// which fails at once instead of retransmitting its SYN until it times out.
// The client's kernel ignores any other RST.
func refuses(s *trackedSession, dir int, pkt capture.Packet) bool {
	f := pkt.TCP.Flags
	return dir == sessionDirSrv && f&capture.TCPFlagRST != 0 && f&capture.TCPFlagACK != 0 &&
		len(pkt.Payload) == 0 && s.dirs[sessionDirClient] != nil && s.dirs[sessionDirClient].hasISN &&
		pkt.TCP.Ack == s.dirs[sessionDirClient].isn+1
}

// ackLocked releases history the receiver of direction dir acknowledged, up
// to what was forwarded to it.
func (t *sessionTable) ackLocked(s *trackedSession, dir int, ack uint32) error {
	d := s.dirs[dir]
	off := min(d.seq.Offset(ack), d.forwarded)
	if off <= d.bytes.Floor() {
		return nil
	}
	if err := d.bytes.Ack(off); err != nil {
		return err
	}
	floor := off
	for _, h := range s.held {
		if h.dir == dir {
			floor = min(floor, h.off)
		}
	}
	i := 0
	for i < len(d.frames) && d.frames[i].end <= floor && d.frames[i].operation == nil {
		i++
	}
	if i == len(d.frames) {
		d.frames = nil
		if d.frameLease != nil {
			d.frameLease.Release()
		}
		d.frameLease = nil
	} else {
		d.frames = d.frames[i:]
	}
	return nil
}

// rstLocked handles an endpoint RST. A RST with data is dropped and aborts.
// A bare RST passes, but closes the session, after its pending data is
// dropped, only at the sequence number its receiver expects next: the end
// of what was forwarded to it (RFC 5961). Its receiver ignores any other,
// or answers it with a challenge ACK, which a closed sender answers with a
// RST at that sequence number.
func (t *sessionTable) rstLocked(s *trackedSession, dir int, pkt capture.Packet, now time.Time) sessionResult {
	if len(pkt.Payload) > 0 {
		if s.mode == "enforce" {
			return droppedWith(reasonIECAbort, t.abortLocked(s, abortTransport, "", t.current(s, dir, pkt, now), now))
		}
		res := accepted(reasonIECClosed)
		res.acts.merge(t.closeLocked(s, now))
		return res
	}
	if pkt.TCP.Seq != forwardedSeq(s.dirs[dir]) {
		return accepted(reasonIECAccept)
	}
	res := accepted(reasonIECClosed)
	res.decision.Resolved = t.dropHeldLocked(s, -1)
	res.acts.merge(t.closeLocked(s, now))
	return res
}

// finLocked accepts a FIN that ends the received stream, after dropping the
// direction's pending data.
func (t *sessionTable) finLocked(s *trackedSession, dir int, pkt capture.Packet, res *sessionResult) {
	d := s.dirs[dir]
	if d.seq.Offset(pkt.TCP.Seq)+int64(len(pkt.Payload)) != d.bytes.Next() {
		*res = invalidSession(s.mode)
		return
	}
	if len(pkt.Payload) == 0 {
		res.decision.Resolved = append(res.decision.Resolved, t.dropHeldLocked(s, dir)...)
	}
	t.finForwardedLocked(s, dir, res)
}

// finForwardedLocked records a forwarded FIN of direction dir and closes
// the session once both directions finished.
func (t *sessionTable) finForwardedLocked(s *trackedSession, dir int, res *sessionResult) {
	d := s.dirs[dir]
	d.fin, d.finFwd = true, true
	if s.dirs[1-dir] != nil && s.dirs[1-dir].fin {
		res.decision.Resolved = append(res.decision.Resolved, t.dropHeldLocked(s, -1)...)
		res.acts.merge(t.closeLocked(s, t.now()))
	}
}

// dropHeldLocked drops the held packets of one direction (dir -1: both).
// Their settlement credits survive until completion, rejection or source flush.
func (t *sessionTable) dropHeldLocked(s *trackedSession, dir int) []capture.Resolution {
	var out []capture.Resolution
	kept := s.held[:0]
	for _, h := range s.held {
		if dir >= 0 && h.dir != dir {
			kept = append(kept, h)
			continue
		}
		delete(t.held, h.tok)
		t.heldTotal--
		s.heldBytes -= int(h.end - h.off)
		out = append(out, capture.Resolution{Token: h.tok, Verdict: capture.VerdictDrop})
	}
	s.held = kept
	return out
}

func (t *sessionTable) closeLocked(s *trackedSession, now time.Time) sessionActions {
	acts := t.iecAdapter.endLocked(t, s)
	acts.retired = true
	s.state, s.endedAt = sessionClosed, now
	t.dpi.EndStream(s.id)
	s.clearInspectionBytes()
	return acts
}

func (t *sessionTable) current(s *trackedSession, dir int, pkt capture.Packet, now time.Time) *heldPacket {
	off := s.dirs[dir].seq.Offset(pkt.TCP.Seq)
	return &heldPacket{tok: pkt.Token, mark: pkt.Mark, dir: dir, off: off, end: off + int64(len(pkt.Payload)),
		fin: pkt.TCP.Flags&capture.TCPFlagFIN != 0, since: now}
}

// dataLocked judges a payload: its bytes are checked against what was
// received, newly contiguous bytes are framed and judged, and the packet is
// released only when every byte belongs to complete allowed units.
func (t *sessionTable) dataLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) sessionResult {
	d := s.dirs[dir]
	enforce := s.mode == "enforce"
	cur := t.current(s, dir, pkt, now)
	if enforce && d.finFwd && cur.end > d.forwarded {
		return droppedWith(reasonIECInvalid, t.abortLocked(s, abortTransport, "", cur, now))
	}
	if cur.off < 0 || cur.off < d.bytes.Floor() {
		// Before the stream, or overlapping bytes whose identity was
		// released: not provably identical, so never forwarded.
		if !enforce {
			return accepted(reasonIECAccept)
		}
		if cur.off < 0 {
			return droppedWith(reasonIECAbort, t.abortLocked(s, abortStream, "", cur, now))
		}
		// A below-floor retransmission is not parseable, but still carries
		// bytes of any command awaiting its original verdict completion.
		res := dropped(reasonIECInvalid)
		t.iecAdapter.packetLocked(t, s, cur, &res.acts)
		return res
	}
	start, fresh, err := d.bytes.Add(cur.off, pkt.Payload)
	if err != nil {
		if errors.Is(err, flow.ErrInspectionLimit) {
			return t.inspectionLimitLocked(s, cur, now)
		}
		res := sessionResult{inspect: []dpi.Event{t.iecAdapter.streamErrorEvent(s, dir, cur.off, err, now)}}
		if enforce {
			r := droppedWith(reasonIECAbort, t.abortLocked(s, abortStream, "", cur, now))
			r.inspect = res.inspect
			t.streamFailureLocked(s, &r, err)
			return r
		}
		t.stopParseLocked(s)
		res.decision = capture.Decision{Action: capture.Accept, Reason: reasonIECAccept}
		return res
	}
	d.seq.Advance(d.bytes.Next())
	var res sessionResult
	t.iecAdapter.packetLocked(t, s, cur, &res.acts)
	if len(fresh) > 0 && !s.stopParse {
		denied, trigger, failed := t.inspectLocked(s, dir, pkt, state, start, fresh, &res, now)
		if enforce && (denied || failed) {
			reason := abortDeny
			if failed && !denied {
				reason = abortFraming
				if res.stateLimit {
					reason = abortBound
				}
			}
			r := res.aborting(reasonIECAbort, t.abortLocked(s, reason, trigger, cur, now))
			if failed && sessionProtocol(s.flow) != iecProtocol {
				r.decision.Reason = reasonStreamFailClosed
			}
			if r.stateLimit {
				r.decision.Reason = "state_limit"
			}
			if res.failure != "" {
				r.decision.Reason = string(res.failure)
			}
			if res.policyReason != "" {
				r.decision.Reason = res.policyReason
			}
			return r
		}
	}
	if !enforce {
		d.forwarded = max(d.forwarded, cur.end)
		res.decision = capture.Decision{Action: capture.Accept, Reason: reasonIECAccept}
		if d.nonAdmitting(cur.off, cur.end) {
			res.decision = nonAdmitDecision(pkt)
		}
		return res
	}
	return t.releaseLocked(s, dir, pkt, cur, res, now)
}

// inspectLocked frames and judges newly contiguous bytes. failed reports a
// stream that cannot be enforced (no framing decoder, or a framing error).
func (t *sessionTable) inspectLocked(s *trackedSession, dir int, pkt capture.Packet, state *flow.State, start int64, fresh []byte, res *sessionResult, now time.Time) (denied bool, trigger string, failed bool) {
	d := s.dirs[dir]
	ir, fault := t.inspectSession(state, &dpi.ParsedPacket{
		Timestamp: pkt.Timestamp,
		Payload:   fresh, Proto: "tcp", SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
		TCPSeq: d.seq.Seq(start), TCPSeqValid: true,
		Offset: start, HasOffset: true, Session: s.id, Dir: dpiDir(dir), Role: dpiDir(dir),
		FailClosed: s.mode == "enforce",
	})
	res.packetPanic = fault
	var limitErr *dpi.StreamError
	if errors.As(ir.Err, &limitErr) && limitErr.Kind == dpi.StreamStateLimit {
		res.stateLimit = !s.inspectionLost
		s.inspectionLost = true
		t.stopParseLocked(s)
		return false, "", true
	}
	if err := t.retainFramesLocked(s, d, ir.Frames); err != nil {
		if errors.Is(err, flow.ErrInspectionLimit) {
			res.stateLimit = !s.inspectionLost
			if res.stateLimit {
				t.ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.Mode(s.mode))
			}
			s.inspectionLost = true
		} else {
			res.failure = pairUnsupported
		}
		t.stopParseLocked(s)
		return false, "", true
	}
	res.inspect = append(res.inspect, ir.Events...)
	if !ir.Framed {
		if s.mode == "enforce" {
			t.health.fault(faultFraming, "iec104 stream not framed: decoder unavailable")
		}
		t.stopParseLocked(s)
		return false, "", true
	}
	var judged []dpi.Event
	for _, f := range ir.Frames {
		t.iecAdapter.frameLocked(t, s, dir, f, t.current(s, dir, pkt, now), &res.acts, now)
		t.observePairingLocked(s, dir, f, now)
		if s.mode == "monitor" && sessionProtocol(s.flow) != iecProtocol && !f.Pending {
			if compiled := t.ruleOwner.current.Load(); compiled != nil {
				class, _ := s.pairing.inspect(f, dpiDir(dir), now)
				_, nonAdmit, _ := t.genericUnitPolicyLocked(s, dir, f, class, false, compiled, now, res)
				if nonAdmit {
					for i := range d.frames {
						p := &d.frames[i]
						if frameCarries(f, p.start, p.end) {
							p.nonAdmit = true
						}
					}
				}
			}
		}
		d.framedEnd = f.End
		judged = append(judged, f.Events...)
	}
	var fe *dpi.FrameError
	var se *dpi.StreamError
	streamErr := errors.As(ir.Err, &fe) || errors.As(ir.Err, &se)
	if streamErr {
		t.streamFailureLocked(s, res, ir.Err)
	}
	if streamErr && len(ir.Events) > 0 {
		judged = append(judged, ir.Events[len(ir.Events)-1]) // the error's malformed event
	}
	j := iecJudgement{}
	if sessionProtocol(s.flow) == iecProtocol && s.mode != "enforce" {
		j = t.iecAdapter.judgeLocked(t, s, judged, now)
	} else if sessionProtocol(s.flow) == iecProtocol && streamErr && len(ir.Events) > 0 {
		j = t.iecAdapter.judgeLocked(t, s, ir.Events[len(ir.Events)-1:], now)
	}
	res.acts.events = append(res.acts.events, j.events...)
	res.findings = append(res.findings, j.findings...)
	if s.mode == "enforce" && !j.denied {
		if why := t.prepareUnitsLocked(s, dir, ir.Frames, now, res); why != pairOK {
			res.failure = why
			res.stateLimit = why == stateLimit
			return true, res.trigger, streamErr
		}
	}
	if streamErr {
		t.stopParseLocked(s)
	}
	return j.denied, j.trigger, streamErr
}

func (t *sessionTable) stopParseLocked(s *trackedSession) {
	t.iecAdapter.stopParseLocked(s)
	if !s.stopParse {
		s.stopParse = true
		t.dpi.EndStream(s.id)
		s.clearInspectionBytes()
	}
}

// releaseLocked accepts the current packet when its whole range is framed
// and allowed, else holds it, and releases earlier held packets of the
// direction that became covered. In an enforce envelope every decided
// frame of a live session is allowed: a deny aborts at once.
func (t *sessionTable) releaseLocked(s *trackedSession, dir int, pkt capture.Packet, cur *heldPacket, res sessionResult, now time.Time) sessionResult {
	d := s.dirs[dir]
	// Admit a possible hold before removing any old held token or publishing
	// any successful result. A refusal must drop even a prefix this packet
	// would otherwise have released.
	if !d.covered(cur.off, cur.end) && pkt.Token.Inline() {
		remaining, bytes := len(s.held), s.heldBytes
		for _, h := range s.held {
			if h.dir == dir && d.covered(h.off, h.end) {
				remaining--
				bytes -= int(h.end - h.off)
			}
		}
		if remaining >= sessionMaxHeldPerSession || bytes+len(pkt.Payload) > sessionMaxHeldBytes || t.heldTotal-len(s.held)+remaining >= sessionMaxHeldGlobal {
			return res.aborting(reasonIECAbort, t.abortLocked(s, abortBound, "", cur, now))
		}
		if !t.holdCreditLocked(cur.tok, len(pkt.Payload), true, sessionProtocol(s.flow)) {
			return t.inspectionLimitLocked(s, cur, now)
		}
	}
	if why := t.commitUnitsLocked(s, dir, cur, now); why != pairOK {
		return res.aborting(string(why), t.abortLocked(s, abortDeny, "", cur, now))
	}
	kept := s.held[:0]
	finReleased := false
	for _, h := range s.held {
		if h.dir == dir && d.covered(h.off, h.end) {
			delete(t.held, h.tok)
			t.heldTotal--
			s.heldBytes -= int(h.end - h.off)
			if !d.nonAdmitting(h.off, h.end) {
				d.forwarded = max(d.forwarded, h.end)
				finReleased = finReleased || (h.fin && h.end == d.bytes.Next())
			}
			res.decision.Resolved = append(res.decision.Resolved, capture.Resolution{Token: h.tok, Verdict: capture.VerdictRepeat, Mark: markabi.Continue(h.mark, d.nonAdmitting(h.off, h.end))})
			t.rememberTokenLocked(s, h.tok, capture.VerdictRepeat)
			continue
		}
		kept = append(kept, h)
	}
	s.held = kept
	if finReleased {
		// A released packet ended the stream with its FIN: the FIN was
		// forwarded, so it counts in the RST sequence.
		t.finForwardedLocked(s, dir, &res)
	}
	if d.covered(cur.off, cur.end) || !pkt.Token.Inline() {
		res.decision.Action, res.decision.Reason = capture.Accept, reasonIECAccept
		if d.nonAdmitting(cur.off, cur.end) {
			res.decision = nonAdmitWithResolved(pkt, res.decision.Resolved)
			res.decision.Notify = true
			s.nonAdmit = true
			acts := t.abortLocked(s, abortDeny, "", cur, now)
			if txn := t.aborts[cur.tok]; txn != nil {
				for _, r := range res.decision.Resolved {
					t.aborts[r.Token] = txn
					txn.pending++
				}
			}
			res.acts.merge(acts)
		} else {
			d.forwarded = max(d.forwarded, cur.end)
		}
		return res
	}
	n := int(cur.end - cur.off)
	s.held = append(s.held, cur)
	s.heldBytes += n
	t.held[cur.tok] = s
	t.heldTotal++
	res.decision.Action, res.decision.Reason = capture.Hold, reasonIECHold
	return res
}
