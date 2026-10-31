// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package dpi

import "github.com/tonylturner/containd/pkg/dp/flow"

// DiscardFlow releases passive reassembly and decoder stream state without
// synthesizing flow-end events or a fail-closed stream error. The owner must
// prevent further Inspect calls until a new connection incarnation.
func (m *Manager) DiscardFlow(state *flow.State) {
	if m == nil {
		return
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	key := state.ID()
	if m.reassembler != nil {
		m.reassembler.complete(key)
	}
	m.endStream(key)
	delete(m.eventTimes, key)
	m.releaseFlowSelection(key)
}

// A legacy flow stream ends at its flow's end (OnFlowEnd), at a FIN or RST
// (CloseStream, ResetStream), or fails (FailStream). A stream that fails
// closed must stay aligned with what its receiver accepts, so a close that
// the receiver would ignore leaves it as it is.

// CloseStream handles the FIN or RST (pkt.TCPFin, pkt.TCPRst) of a legacy
// flow stream once the caller has decided the packet. It reports whether
// the segment ended the sender's stream and returns the decoders' flow-end
// events when it did.
//
// A packet that fails closed ends its stream only in window: a RST at the
// next sequence number the stream expects, a FIN right after the stream's
// contiguous bytes. The stream is then closed and holds no bytes until a
// SYN anchors a new one, a segment starts one mid-stream, or the idle sweep
// removes it. A failed stream never ends at a close, and only a packet
// that fails closed ends a fail-closed stream. Other streams end at any
// FIN or RST.
func (m *Manager) CloseStream(state *flow.State, pkt *ParsedPacket) (bool, []Event, error) {
	if m == nil || len(m.decoders) == 0 || m.reassembler == nil || pkt.HasOffset || !pkt.TCPFin && !pkt.TCPRst {
		return false, nil, nil
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	key, _, pos := streamKey(state, pkt)
	if !m.reassembler.end(key, pos, len(pkt.Payload), pkt.TCPRst, pkt.FailClosed) {
		return false, nil, nil
	}
	m.endStream(key)
	evs, err := m.flowEnd(state, eventTime(state, pkt))
	return true, evs, err
}

// ResetStream ends peer's legacy stream, the opposite direction of a
// connection whose RST CloseStream ended, and returns the decoders'
// flow-end events. As with CloseStream, a failed stream never ends this
// way and only a packet that fails closed ends a fail-closed stream.
func (m *Manager) ResetStream(peer *flow.State, pkt *ParsedPacket) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 || m.reassembler == nil {
		return nil, nil
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	if !m.reassembler.endPeer(peer.ID(), pkt.FailClosed) {
		return nil, nil
	}
	m.endStream(peer.ID())
	return m.flowEnd(peer, eventTime(peer, pkt))
}

// FailStream fails the framed stream of a packet with a StreamError of
// kind: StreamDecoderPanic when its decoder panicked, StreamDenied when the
// policy denied the connection, StreamMidStream when the caller closes a
// connection it picked up mid-connection. The buffered bytes are dropped
// and the stream stays failed, as after a stream error, so nothing on it
// is parsed again. Later packets that fail closed get its error; the flow's end
// clears it. A flow without a framing decoder holds no stream and is left
// alone.
func (m *Manager) FailStream(state *flow.State, pkt *ParsedPacket, kind StreamErrKind) {
	if m == nil || !m.reassembles(pkt) {
		return
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	key, _, _ := streamKey(state, pkt)
	framer := firstFramer(m.dispatch(state, key))
	if framer == nil {
		return
	}
	m.reassembler.fail(key, &StreamError{Kind: kind, Offset: m.reassembler.watermark(key), Proto: framer.Protocol()})
	m.endStream(key)
}

// end handles a FIN or RST that the stream key's own direction sent at pos,
// after n payload bytes, and reports whether it ended the stream. See
// CloseStream.
func (r *reassembler) end(key string, pos position, n int, rst, failClosed bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !failClosed {
		if ok && (s.failed != nil || s.verify) {
			return false
		}
		r.completeLocked(key)
		return true
	}
	if !ok || s.failed != nil || s.mode != posSeq || pos.kind != posSeq {
		return false
	}
	if s.closed {
		return rst && pos.seq == s.closeNext // a RST following this direction's FIN
	}
	next := s.seq0 + uint32(s.end())
	if rst && pos.seq != next || !rst && pos.seq+uint32(n) != next {
		return false
	}
	if !rst {
		next++ // the FIN takes one sequence number
	}
	r.closeLocked(s, next)
	return true
}

// endPeer ends a stream at a RST of the opposite direction and reports
// whether it ended; see ResetStream.
func (r *reassembler) endPeer(key string, failClosed bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	switch {
	case !ok:
		return true
	case s.failed != nil || s.verify && !failClosed:
		return false
	case !failClosed:
		r.completeLocked(key)
	case !s.closed:
		r.closeLocked(s, s.seq0+uint32(s.end()))
	}
	return true
}

// closeLocked closes a fail-closed stream; next is the sequence number a
// later RST of its direction carries in window.
func (r *reassembler) closeLocked(s *stream, next uint32) {
	r.bytesBuffered -= s.held()
	s.buf, s.ooo, s.hist = nil, nil, nil
	s.closed, s.closeNext = true, next
}
