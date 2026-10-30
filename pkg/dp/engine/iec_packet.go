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
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
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

// iecResult is the outcome of one IEC104 envelope packet. Its actions are
// carried out after the session lock is released; drops of held tokens are
// already in decision.Resolved.
type iecResult struct {
	decision capture.Decision
	inspect  []dpi.Event  // decoder events, recorded like any DPI events
	findings []iecFinding // judged events with conformance findings
	acts     iecActions
}

func accepted(reason string) iecResult {
	return iecResult{decision: capture.Decision{Action: capture.Accept, Reason: reason}}
}

func dropped(reason string) iecResult {
	return iecResult{decision: capture.Decision{Action: capture.Drop, Reason: reason}}
}

// droppedWith drops the current packet and every held token of acts.
func droppedWith(reason string, acts iecActions) iecResult {
	res := dropped(reason)
	res.decision.Resolved = acts.drops
	acts.drops = nil
	res.acts = acts
	return res
}

func dpiDir(dir int) dpi.StreamDir {
	if dir == iecDirClient {
		return dpi.ClientToServer
	}
	return dpi.ServerToClient
}

func dirName(dir int) string {
	if dir == iecDirClient {
		return "request"
	}
	return "response"
}

// handleIECPacket decides a TCP packet to or from port 2404 when an IEC104
// envelope may apply. ok is false for packets outside every envelope; they
// take the flow path unchanged. The packet is judged in the IEC104 parsing
// mode in force now; conformance alerts and the connection's alert identity
// are the engine's, so they are settled here, after the table decided.
func (e *Engine) handleIECPacket(pkt capture.Packet, state *flow.State) (capture.Decision, bool) {
	t := e.iec
	if t == nil || !isIECFlow(state) && !e.iecOwnsState(pkt, state) {
		return capture.Decision{}, false
	}
	res, ok := t.packet(pkt, state, e.ICSParsing(iecProtocol))
	if !ok {
		t.finish(res.acts)
		if envelopeMarked(pkt) {
			// nft steered this packet as IEC104 envelope traffic, but the
			// engine finds no envelope for it: fail closed rather than let
			// it through uninspected.
			e.recordPacketStats(pkt, state)
			countIECAbort(abortFailClose)
			t.health.fault(faultEnvelope, "nft steering and the engine envelope disagree")
			return capture.Decision{Action: capture.Drop, Reason: reasonIECFailClose}, true
		}
		return capture.Decision{}, false
	}
	e.recordPacketStats(pkt, state)
	parsed := dpi.ParsedPacket{Payload: pkt.Payload, Proto: pkt.Transport, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	if len(res.inspect) > 0 {
		e.RecordDPIEvents(state, &parsed, res.inspect)
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

func (t *iecTable) packet(pkt capture.Packet, state *flow.State, parsing ics.Parsing) (iecResult, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pressureOffline = false
	t.parsing = parsing
	if !t.hasIEC {
		return iecResult{}, false
	}
	now := t.now()
	src, okSrc := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, okDst := addrPort(pkt.DstIP, pkt.DstPort)
	if !okSrc || !okDst {
		return t.nonIPv4Locked(state)
	}
	s, dir := t.lookupLocked(src, dst)
	if s != nil {
		s.ctx = t.sessionContext(s)
	}
	switch {
	case synRST(pkt.TCP.Flags):
		return t.synRSTLocked(s, state)
	case s == nil:
		return t.newPacketLocked(pkt, src, dst, state, now)
	case s.state == iecAborted:
		return t.tombstonePacketLocked(s, dir, pkt, state, now)
	case s.state == iecClosed:
		return t.closedPacketLocked(s, dir, pkt, state, now)
	case reopensLocked(s, dir, pkt):
		return t.reopenLocked(s, dir, pkt, state, now)
	default:
		res := t.livePacketLocked(s, dir, pkt, state, now)
		_, res.decision.Notify = t.inventoryTokens[pkt.Token]
		return res, true
	}
}

// nonIPv4Locked drops IPv6 traffic inside an enforce envelope.
func (t *iecTable) nonIPv4Locked(state *flow.State) (iecResult, bool) {
	ctx := t.stateContext(state)
	matched, mode := t.envelopeLocked(ctx)
	if !matched || mode != "enforce" {
		return iecResult{}, false
	}
	return dropped(reasonIECInvalid), true
}

func isSYN(f capture.TCPFlags) bool { return f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagACK == 0 }

func synRST(f capture.TCPFlags) bool { return f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagRST != 0 }

// synRSTLocked decides a segment carrying both SYN and RST, which is no
// handshake segment: it never opens, establishes, refuses or closes an
// incarnation, so a SYN-ACK with RST cannot establish one whose client it
// resets. Every session of either mode drops it, as does an enforce
// envelope; monitor traffic of no session passes it untracked, like every
// other monitor packet not observed from its SYN.
func (t *iecTable) synRSTLocked(s *iecSession, state *flow.State) (iecResult, bool) {
	if s != nil {
		return dropped(reasonIECInvalid), true
	}
	matched, mode := t.envelopeLocked(t.stateContext(state))
	if !matched {
		return iecResult{}, false
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
func (t *iecTable) newPacketLocked(pkt capture.Packet, src, dst netip.AddrPort, state *flow.State, now time.Time) (iecResult, bool) {
	if isSYN(pkt.TCP.Flags) && state.ServiceKey().Dir == flow.DirForward && servicePort(state, nil) == iec104Port {
		ctx := t.stateContext(state)
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			return iecResult{}, false
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
		return iecResult{}, false
	}
	if mode != "enforce" || pkt.TCP.Flags&capture.TCPFlagRST != 0 && len(pkt.Payload) == 0 {
		// Monitor: observed, never parsed mid-stream. A bare RST closes.
		return accepted(reasonIECAccept), true
	}
	return t.midstreamLocked(client, server, ctx, pkt, src == client, state, now), true
}

// openLocked starts a new incarnation from its SYN. prev is the tombstone
// or closed session of the same tuple, if any.
func (t *iecTable) openLocked(prev *iecSession, client, server netip.AddrPort, ctx rules.EvalContext, mode string, pkt capture.Packet, state *flow.State, now time.Time) iecResult {
	// The bound counts tuple keys; a retained tuple reuses its existing key.
	if prev == nil && len(t.sessions) >= iecMaxSessions {
		if mode == "enforce" {
			countIECAbort(abortBound)
			return dropped(reasonIECFailClose)
		}
		// Monitor is fail open when observation capacity is exhausted. Do not
		// allocate an incarnation or byte stream for this tuple.
		res := accepted(reasonIECUntracked)
		event := untrackedEvent(client, server, now)
		key := state.ServiceKey()
		event.service = &key
		res.acts.events = append(res.acts.events, event)
		return res
	}
	if len(pkt.Payload) > 0 {
		return dropped(reasonIECInvalid) // SYN with data (no TCP Fast Open in B)
	}
	if mode == "enforce" && !t.health.injectorReady() {
		// No session can be reset: none may start.
		countIECAbort(abortInjector)
		return dropped(reasonIECFailClose)
	}
	n := &iecSession{id: t.newID(), flow: &flow.State{Key: state.ServiceKey()}, client: client, server: server, ctx: ctx, mode: mode, lastSeen: now}
	n.dirs[iecDirClient] = newIECDir(pkt.TCP.Seq)
	_, n.reconnects = t.reconnect[pairKey(client, server)]
	key := iecKey{client: client, server: server}
	switch {
	case prev != nil && prev.state == iecAborted:
		prev.next = n // the tombstone retires once the handshake validates
	default:
		t.sessions[key] = n
	}
	res := accepted(reasonIECAccept)
	res.acts.retired = true // a new connection on the tuple: the previous one is over
	return res
}

// midstreamLocked drops a packet of a session not observed from its SYN
// inside an enforce envelope and resets that session once. The
// tombstone then drops its later packets.
func (t *iecTable) midstreamLocked(client, server netip.AddrPort, ctx rules.EvalContext, pkt capture.Packet, fromClient bool, state *flow.State, now time.Time) iecResult {
	if len(t.sessions) >= iecMaxSessions {
		// Unobserved enforce traffic must not bypass the shared table bound.
		countIECAbort(abortBound)
		return dropped(reasonIECFailClose)
	}
	s := &iecSession{id: t.newID(), flow: &flow.State{Key: state.ServiceKey()}, client: client, server: server, ctx: ctx, mode: "enforce", lastSeen: now}
	t.sessions[iecKey{client: client, server: server}] = s
	dir := iecDirSrv
	if fromClient {
		dir = iecDirClient
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
	return droppedWith(reasonIECAbort, acts)
}

// tombstonePacketLocked drops every packet of an aborted incarnation and
// answers challenge ACKs. A SYN with a new ISN starts the next incarnation
// (opens); a retransmitted old SYN does not. The server's SYN-ACK of the
// next incarnation, or its RST refusing that SYN (refuses), passes.
func (t *iecTable) tombstonePacketLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (iecResult, bool) {
	f := pkt.TCP.Flags
	if dir == iecDirClient && isSYN(f) {
		if c := s.dirs[iecDirClient]; c != nil && c.isn == pkt.TCP.Seq {
			return dropped(reasonIECTombstone), true
		}
		if s.next != nil && s.next.dirs[iecDirClient].isn == pkt.TCP.Seq {
			return accepted(reasonIECAccept), true
		}
		ctx := t.stateContext(state)
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			acts := t.deleteLocked(iecKey{client: s.client, server: s.server}, s)
			return iecResult{acts: acts}, false
		}
		if !opens(mode, pkt) {
			return dropped(reasonIECTombstone), true
		}
		return t.openLocked(s, s.client, s.server, ctx, mode, pkt, state, now), true
	}
	if n := s.next; n != nil && f&capture.TCPFlagSYN == 0 && refuses(n, dir, pkt) {
		// The server refused the next incarnation: the tombstone stays,
		// and the client's next SYN opens another.
		s.next = nil
		return accepted(reasonIECClosed), true
	}
	if n := s.next; dir == iecDirSrv && f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagACK != 0 && n != nil &&
		pkt.TCP.Ack == n.dirs[iecDirClient].isn+1 && len(pkt.Payload) == 0 {
		n.dirs[iecDirSrv] = newIECDir(pkt.TCP.Seq)
		n.state, n.lastSeen = iecEstablished, now
		t.tombstones--
		t.sessions[iecKey{client: s.client, server: s.server}] = n
		return accepted(reasonIECAccept), true
	}
	res := dropped(reasonIECTombstone)
	res.acts = t.challengeLocked(s, dir, pkt, now)
	return res, true
}

// closedPacketLocked passes the payload-free tail of a closed session and
// lets a new SYN open the next incarnation (opens).
func (t *iecTable) closedPacketLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (iecResult, bool) {
	if dir == iecDirClient && isSYN(pkt.TCP.Flags) && pkt.TCP.Seq != s.dirs[iecDirClient].isn {
		ctx := t.stateContext(state)
		matched, mode := t.envelopeLocked(ctx)
		if !matched {
			acts := t.deleteLocked(iecKey{client: s.client, server: s.server}, s)
			return iecResult{acts: acts}, false
		}
		if opens(mode, pkt) {
			return t.openLocked(s, s.client, s.server, ctx, mode, pkt, state, now), true
		}
	}
	if len(pkt.Payload) > 0 && s.mode == "enforce" {
		return dropped(reasonIECClosed), true
	}
	return accepted(reasonIECClosed), true
}

// reopensLocked reports a client SYN that starts a new connection on the
// tuple of an established incarnation: a new ISN, no payload, and the
// handshake mark, so connection tracking no longer holds the old
// connection.
func reopensLocked(s *iecSession, dir int, pkt capture.Packet) bool {
	return s.state == iecEstablished && dir == iecDirClient && isSYN(pkt.TCP.Flags) &&
		pkt.TCP.Seq != s.dirs[iecDirClient].isn && len(pkt.Payload) == 0 && handshakeMarked(pkt)
}

// reopenLocked ends an established incarnation whose tuple a new
// connection's SYN reopens. An enforce incarnation aborts: the SYN drops,
// both endpoints are reset, and the client's retransmitted SYN opens the
// next incarnation from the tombstone. A monitor incarnation closes, and the
// SYN opens the next one at once.
func (t *iecTable) reopenLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) (iecResult, bool) {
	if s.mode == "enforce" {
		return droppedWith(reasonIECAbort, t.abortLocked(s, abortMidstream, "", &heldPacket{tok: pkt.Token, dir: dir}, now)), true
	}
	acts := t.closeLocked(s, now)
	res, ok := t.closedPacketLocked(s, dir, pkt, state, now)
	res.acts.merge(acts)
	return res, ok
}

// handshakeLocked follows the SYN and SYN-ACK of a live incarnation. A
// client SYN with a new ISN sent into an established incarnation, as a
// client that lost its connection and reconnects from the same port
// sends, passes and changes nothing: the server answers it with a
// challenge ACK, and the RST the client sends in reply closes the
// incarnation (rstLocked). A SYN with payload is dropped.
func (t *iecTable) handshakeLocked(s *iecSession, dir int, pkt capture.Packet, now time.Time) iecResult {
	f, seq := pkt.TCP.Flags, pkt.TCP.Seq
	if len(pkt.Payload) > 0 {
		return dropped(reasonIECInvalid)
	}
	c2s := s.dirs[iecDirClient]
	switch {
	case dir == iecDirClient && f&capture.TCPFlagACK == 0:
		if seq == c2s.isn {
			return accepted(reasonIECAccept)
		}
		if s.dirs[iecDirSrv] != nil {
			return accepted(reasonIECEstablishedSYN)
		}
		if opens(s.mode, pkt) {
			s.dirs[iecDirClient] = newIECDir(seq) // the client retried with a new ISN
			return accepted(reasonIECAccept)
		}
	case dir == iecDirSrv && f&capture.TCPFlagACK != 0 && pkt.TCP.Ack == c2s.isn+1:
		if s2c := s.dirs[iecDirSrv]; s2c == nil {
			s.dirs[iecDirSrv] = newIECDir(seq)
			s.state, s.lastSeen = iecEstablished, now
			return accepted(reasonIECAccept)
		} else if s2c.isn == seq {
			return accepted(reasonIECAccept)
		}
	}
	return dropped(reasonIECInvalid)
}

// livePacketLocked decides a packet of a live incarnation.
func (t *iecTable) livePacketLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) iecResult {
	s.lastSeen = now
	f := pkt.TCP.Flags
	enforce := s.mode == "enforce"
	if f&capture.TCPFlagSYN != 0 {
		return t.handshakeLocked(s, dir, pkt, now)
	}
	if s.dirs[iecDirSrv] == nil {
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
	if f&capture.TCPFlagACK != 0 {
		t.ackLocked(s, 1-dir, pkt.TCP.Ack)
	}
	if f&capture.TCPFlagRST != 0 {
		return t.rstLocked(s, dir, pkt, now)
	}
	res := accepted(reasonIECAccept)
	if len(pkt.Payload) > 0 {
		res = t.dataLocked(s, dir, pkt, state, now)
		if s.state == iecAborted {
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
func refuses(s *iecSession, dir int, pkt capture.Packet) bool {
	f := pkt.TCP.Flags
	return dir == iecDirSrv && f&capture.TCPFlagRST != 0 && f&capture.TCPFlagACK != 0 &&
		len(pkt.Payload) == 0 && pkt.TCP.Ack == s.dirs[iecDirClient].isn+1
}

// ackLocked releases history the receiver of direction dir acknowledged, up
// to what was forwarded to it.
func (t *iecTable) ackLocked(s *iecSession, dir int, ack uint32) {
	d := s.dirs[dir]
	off := min(d.seq.Offset(ack), d.forwarded)
	if off <= d.bytes.Floor() {
		return
	}
	d.bytes.Ack(off)
	floor := off
	for _, h := range s.held {
		if h.dir == dir {
			floor = min(floor, h.off)
		}
	}
	i := 0
	for i < len(d.frames) && d.frames[i].end <= floor {
		i++
	}
	d.frames = d.frames[i:]
}

// rstLocked handles an endpoint RST. A RST with data is dropped and aborts.
// A bare RST passes, but closes the session, after its pending data is
// dropped, only at the sequence number its receiver expects next: the end
// of what was forwarded to it (RFC 5961). Its receiver ignores any other,
// or answers it with a challenge ACK, which a closed sender answers with a
// RST at that sequence number.
func (t *iecTable) rstLocked(s *iecSession, dir int, pkt capture.Packet, now time.Time) iecResult {
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
func (t *iecTable) finLocked(s *iecSession, dir int, pkt capture.Packet, res *iecResult) {
	d := s.dirs[dir]
	if d.seq.Offset(pkt.TCP.Seq)+int64(len(pkt.Payload)) != d.bytes.Next() {
		*res = dropped(reasonIECInvalid)
		return
	}
	if len(pkt.Payload) == 0 {
		res.decision.Resolved = append(res.decision.Resolved, t.dropHeldLocked(s, dir)...)
	}
	t.finForwardedLocked(s, dir, res)
}

// finForwardedLocked records a forwarded FIN of direction dir and closes
// the session once both directions finished.
func (t *iecTable) finForwardedLocked(s *iecSession, dir int, res *iecResult) {
	d := s.dirs[dir]
	d.fin, d.finFwd = true, true
	if s.dirs[1-dir].fin {
		res.decision.Resolved = append(res.decision.Resolved, t.dropHeldLocked(s, -1)...)
		res.acts.merge(t.closeLocked(s, t.now()))
	}
}

// dropHeldLocked drops the held packets of one direction (dir -1: both).
// They leave the ledger at once; their completions are ignored.
func (t *iecTable) dropHeldLocked(s *iecSession, dir int) []capture.Resolution {
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

func (t *iecTable) closeLocked(s *iecSession, now time.Time) iecActions {
	acts := t.endInventoryLocked(s)
	acts.retired = true
	s.apci = nil
	s.state, s.endedAt = iecClosed, now
	t.dpi.EndStream(s.id)
	return acts
}

func (t *iecTable) current(s *iecSession, dir int, pkt capture.Packet, now time.Time) *heldPacket {
	off := s.dirs[dir].seq.Offset(pkt.TCP.Seq)
	return &heldPacket{tok: pkt.Token, dir: dir, off: off, end: off + int64(len(pkt.Payload)),
		fin: pkt.TCP.Flags&capture.TCPFlagFIN != 0, since: now}
}

// dataLocked judges a payload: its bytes are checked against what was
// received, newly contiguous bytes are framed and judged, and the packet is
// released only when every byte belongs to complete allowed APDUs.
func (t *iecTable) dataLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, now time.Time) iecResult {
	d := s.dirs[dir]
	enforce := s.mode == "enforce"
	cur := t.current(s, dir, pkt, now)
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
		t.inventoryPacketLocked(s, cur, &res.acts)
		return res
	}
	start, fresh, err := d.bytes.Add(cur.off, pkt.Payload)
	if err != nil {
		res := iecResult{inspect: []dpi.Event{s.streamErrorEvent(dir, cur.off, err, now)}}
		if enforce {
			r := droppedWith(reasonIECAbort, t.abortLocked(s, abortStream, "", cur, now))
			r.inspect = res.inspect
			return r
		}
		t.stopParseLocked(s)
		res.decision = capture.Decision{Action: capture.Accept, Reason: reasonIECAccept}
		return res
	}
	d.seq.Advance(d.bytes.Next())
	var res iecResult
	t.inventoryPacketLocked(s, cur, &res.acts)
	if len(fresh) > 0 && !s.stopParse {
		denied, trigger, failed := t.inspectLocked(s, dir, pkt, state, start, fresh, &res, now)
		if enforce && (denied || failed) {
			reason := abortDeny
			if failed && !denied {
				reason = abortFraming
			}
			r := droppedWith(reasonIECAbort, t.abortLocked(s, reason, trigger, cur, now))
			r.inspect, r.findings = res.inspect, res.findings
			res.acts.merge(r.acts)
			r.acts = res.acts
			return r
		}
	}
	if !enforce {
		d.forwarded = max(d.forwarded, cur.end)
		res.decision = capture.Decision{Action: capture.Accept, Reason: reasonIECAccept}
		return res
	}
	return t.releaseLocked(s, dir, pkt, cur, res, now)
}

// inspectLocked frames and judges newly contiguous bytes. failed reports a
// stream that cannot be enforced (no framing decoder, or a framing error).
func (t *iecTable) inspectLocked(s *iecSession, dir int, pkt capture.Packet, state *flow.State, start int64, fresh []byte, res *iecResult, now time.Time) (denied bool, trigger string, failed bool) {
	d := s.dirs[dir]
	ir := t.dpi.Inspect(state, &dpi.ParsedPacket{
		Timestamp: pkt.Timestamp,
		Payload:   fresh, Proto: "tcp", SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
		TCPSeq: d.seq.Seq(start), TCPSeqValid: true,
		Offset: start, HasOffset: true, Session: s.id, Dir: dpiDir(dir),
	})
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
		s.observeAPCILocked(dir, f, &res.acts, now)
		t.observeInventoryLocked(s, dir, f, t.current(s, dir, pkt, now), &res.acts, now)
		d.frames = append(d.frames, iecFrame{start: f.Start, end: f.End})
		d.framedEnd = f.End
		judged = append(judged, f.Events...)
	}
	var fe *dpi.FrameError
	var se *dpi.StreamError
	streamErr := errors.As(ir.Err, &fe) || errors.As(ir.Err, &se)
	if streamErr && len(ir.Events) > 0 {
		judged = append(judged, ir.Events[len(ir.Events)-1]) // the error's malformed event
	}
	j := t.judgeLocked(s, judged, now)
	res.acts.events = append(res.acts.events, j.events...)
	res.findings = append(res.findings, j.findings...)
	if streamErr {
		t.stopParseLocked(s)
	}
	return j.denied, j.trigger, streamErr
}

func (t *iecTable) stopParseLocked(s *iecSession) {
	s.apci = nil
	if !s.stopParse {
		s.stopParse = true
		t.dpi.EndStream(s.id)
	}
}

// releaseLocked accepts the current packet when its whole range is framed
// and allowed, else holds it, and releases earlier held packets of the
// direction that became covered. In an enforce envelope every decided
// frame of a live session is allowed: a deny aborts at once.
func (t *iecTable) releaseLocked(s *iecSession, dir int, pkt capture.Packet, cur *heldPacket, res iecResult, now time.Time) iecResult {
	d := s.dirs[dir]
	kept := s.held[:0]
	finReleased := false
	for _, h := range s.held {
		if h.dir == dir && h.end <= d.framedEnd {
			delete(t.held, h.tok)
			t.heldTotal--
			s.heldBytes -= int(h.end - h.off)
			d.forwarded = max(d.forwarded, h.end)
			finReleased = finReleased || (h.fin && h.end == d.bytes.Next())
			res.decision.Resolved = append(res.decision.Resolved, capture.Resolution{Token: h.tok, Verdict: capture.VerdictAccept})
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
	if cur.end <= d.framedEnd || !pkt.Token.Inline() {
		d.forwarded = max(d.forwarded, cur.end)
		res.decision.Action, res.decision.Reason = capture.Accept, reasonIECAccept
		return res
	}
	n := int(cur.end - cur.off)
	if len(s.held) >= iecMaxHeldPerSession || s.heldBytes+n > iecMaxHeldBytes || t.heldTotal >= iecMaxHeldGlobal {
		r := droppedWith(reasonIECAbort, t.abortLocked(s, abortBound, "", cur, now))
		r.decision.Resolved = append(res.decision.Resolved, r.decision.Resolved...)
		r.inspect, r.findings = res.inspect, res.findings
		res.acts.merge(r.acts)
		r.acts = res.acts
		return r
	}
	s.held = append(s.held, cur)
	s.heldBytes += n
	t.held[cur.tok] = s
	t.heldTotal++
	res.decision.Action, res.decision.Reason = capture.Hold, reasonIECHold
	return res
}

// streamErrorEvent is the malformed evidence of a byte-level stream error
// (overlap conflict, bounds, bytes before the stream).
func (s *iecSession) streamErrorEvent(dir int, off int64, err error, now time.Time) dpi.Event {
	return dpi.Event{
		Proto: eventfields.ProtoIEC104,
		Kind:  iecKindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError:     "stream: " + err.Error(),
			eventfields.KeyDirection: dirName(dir),
			eventfields.KeySessionID: s.id,
			"offset":                 off,
		},
		Timestamp: now.UTC(),
	}
}
