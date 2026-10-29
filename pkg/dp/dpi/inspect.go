// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Inspect passes the packet to the decoders that support the flow. TCP
// payload is fed through the reassembler so that decoders see the stream,
// not single segments. The first supporting StreamDecoder (registration
// order) frames the stream through ParseStream and alone trims it; other
// packet decoders get OnPacket with only the captured segment.
//
// Streams are keyed by the directional flow hash, or by Session and Dir
// when HasOffset is set. A HasOffset packet without Session or Dir is not
// framed. A framed stream's buffer bounds, out-of-order bound and
// conflicting overlaps are *StreamError; the manager adds their malformed
// event. Any framed error discards the direction's buffer: a legacy stream
// starts fresh with the next packet unless the packet asks to fail closed;
// a fail-closed legacy stream stays failed until its flow ends, a session
// stream until EndStream. A failed stream returns its error without
// parsing. Feed, parse and trim are serialized across capture workers.
//
// A SYN anchors a legacy stream. A stream that fails closed has stricter
// rules: only a SYN of a handshake the kernel's connection tracking has
// not seen complete (TCPHandshake) anchors it, never one on its live
// stream (see open), the payload of a SYN it is not anchored at is a
// StreamResync error, and its bytes are not framed when the stream was
// picked up mid-connection, a StreamMidStream error without a malformed
// event (see feed). The payload of a fail-closed RST is not fed, as no
// receiver delivers it.
func (m *Manager) Inspect(state *flow.State, pkt *ParsedPacket) (res InspectResult) {
	if m == nil || len(m.decoders) == 0 {
		return res
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	at := eventTime(state, pkt)
	m.eventTimes[state.Key.Hash()] = at
	defer func() { stampResult(&res, at) }()
	candidates := m.candidates(state)
	tcp := pkt.Proto == "tcp"
	stream := m.reassembles(pkt)
	var framer StreamDecoder
	if stream {
		framer = firstFramer(candidates, state)
	}
	if framer != nil {
		res.Framed = true
		res.Proto = framer.Protocol()
	}
	key, session, pos := streamKey(state, pkt)
	var errEvent *Event
	if framer != nil && !pkt.HasOffset && pkt.TCPSyn && pkt.TCPSeqValid {
		anchored, discarded := m.reassembler.open(key, pkt.TCPSeq, time.Now(), pkt.FailClosed, pkt.TCPHandshake)
		if discarded {
			m.endStream(key)
		}
		if pkt.FailClosed && len(pkt.Payload) > 0 && !anchored {
			errEvent = streamError(state, pkt, &res, &StreamError{Kind: StreamResync, Offset: m.reassembler.watermark(key)})
		}
	}
	if stream && res.Err == nil {
		if err := m.reassembler.failure(key); err != nil {
			if pkt.HasOffset || pkt.FailClosed {
				res.Err, res.Failed = err, true // already reported with its event; not re-emitted
				return res
			}
			m.reassembler.complete(key) // the flow no longer fails closed: start fresh
		}
	}

	if framer != nil && res.Err == nil && len(pkt.Payload) > 0 && !(pkt.FailClosed && pkt.TCPRst) {
		now := time.Now()
		for _, expired := range m.reassembler.sweep(now) {
			m.endStream(expired)
		}
		fed := m.reassembler.feed(key, pos, pkt.Payload, now, true, pkt.HasOffset, pkt.FailClosed)
		res.Gap = fed.gap
		switch {
		case fed.err != nil && fed.err.Kind == StreamMidStream:
			fed.err.Proto = res.Proto
			res.Err = fed.err // nothing was inspected: not malformed
		case fed.err != nil:
			errEvent = streamError(state, pkt, &res, fed.err)
		case len(fed.buf) > 0:
			view := StreamView{Session: session, Dir: pkt.Dir, Base: fed.base, Bytes: fed.buf}
			errEvent = m.parseFramed(state, pkt, framer, &res, key, view)
		}
	}
	if res.Err != nil {
		m.discard(key, pkt.HasOffset || pkt.FailClosed, res.Err)
	}

	for _, d := range candidates {
		if d == nil || !d.Supports(state) {
			continue
		}
		if _, ok := d.(StreamDecoder); ok && tcp {
			continue // on TCP a StreamDecoder only ever frames through ParseStream
		}
		events, err := d.OnPacket(state, pkt)
		res.Events = append(res.Events, events...)
		if err != nil {
			if res.Err == nil {
				res.Err = err // a legacy decoder error passes through unchanged
			}
			break
		}
	}
	if errEvent != nil {
		res.Events = append(res.Events, *errEvent)
	}
	return res
}

// reassembles reports whether pkt's bytes go through the reassembler: TCP,
// and a HasOffset packet only with its Session and Dir.
func (m *Manager) reassembles(pkt *ParsedPacket) bool {
	return pkt.Proto == "tcp" && m.reassembler != nil &&
		!(pkt.HasOffset && (pkt.Session == "" || pkt.Dir == DirUnknown))
}

// streamError records a manager-side error of the framed stream in res and
// returns its malformed event.
func streamError(state *flow.State, pkt *ParsedPacket, res *InspectResult, se *StreamError) *Event {
	se.Proto = res.Proto
	ev := malformedEvent(state, pkt, res.Proto, se)
	res.Err = se
	return &ev
}

// firstFramer returns the first registered StreamDecoder supporting the
// flow, or nil.
func firstFramer(candidates []Decoder, state *flow.State) StreamDecoder {
	for _, d := range candidates {
		if sd, ok := d.(StreamDecoder); ok && sd.Supports(state) {
			return sd
		}
	}
	return nil
}

// parseFramed runs one ParseStream call, records its frames and trims the
// consumed prefix. It returns the malformed event of a framing error, which
// it also stores in res.Err. A decoder that breaks the framing contract, or
// returns an error that is not a *FrameError, yields a FrameError at the
// view's base and none of its frames.
func (m *Manager) parseFramed(state *flow.State, pkt *ParsedPacket, sd StreamDecoder, res *InspectResult, key string, v StreamView) *Event {
	if ender, ok := sd.(StreamEnder); ok {
		m.streamEnds[key] = streamEnd{decoder: ender, session: v.Session, dir: v.Dir}
	}
	sr, err := sd.ParseStream(state, v)
	var fe *FrameError
	switch {
	case err == nil || errors.As(err, &fe):
		if reason := frameContractViolation(v, sr, fe == nil); reason != "" {
			fe, sr = &FrameError{Offset: v.Base, Reason: reason}, StreamResult{}
		}
	default:
		fe, sr = &FrameError{Offset: v.Base, Reason: err.Error()}, StreamResult{}
	}
	for _, f := range sr.Frames {
		res.Frames = append(res.Frames, f)
		res.Events = append(res.Events, f.Events...)
	}
	res.NeedMore = sr.NeedMore
	if fe == nil {
		m.reassembler.trim(key, v.Base, sr.Consumed)
		return nil
	}
	if fe.Event.Kind == "" {
		fe.Event = malformedEvent(state, pkt, res.Proto, fe)
	}
	res.Err = fe
	return &fe.Event
}

// frameContractViolation checks the StreamResult invariants the manager
// relies on: frames contiguous from Base inside the view and, when the
// stream continues (no error), Consumed equal to the complete prefix. On a
// FrameError the buffer is discarded, so Consumed is not used. It returns
// "" when the invariants hold.
func frameContractViolation(v StreamView, sr StreamResult, continues bool) string {
	next := v.Base
	for _, f := range sr.Frames {
		if f.Start != next || f.End <= f.Start {
			return "decoder returned non-contiguous frames"
		}
		next = f.End
	}
	if next > v.Base+int64(len(v.Bytes)) {
		return "decoder returned a frame beyond its view"
	}
	if continues && int64(sr.Consumed) != next-v.Base {
		return "decoder consumed bytes that are not complete frames"
	}
	return ""
}

// discard drops a direction's buffer after a framed error: a session or
// fail-closed stream stays failed until it ends, a legacy stream starts
// fresh.
func (m *Manager) discard(key string, keepFailed bool, err error) {
	if keepFailed {
		m.reassembler.fail(key, err)
	} else {
		m.reassembler.complete(key)
	}
	m.endStream(key)
}

// endStream drops the recorded decoder state for key. Callers hold streamMu,
// which serializes this notification with ParseStream.
func (m *Manager) endStream(key string) {
	ended, ok := m.streamEnds[key]
	if !ok {
		return
	}
	delete(m.streamEnds, key)
	ended.decoder.StreamEnded(ended.session, ended.dir)
}

// malformedEvent is the single event the manager reports for a framed
// error it synthesizes: a StreamError, or a decoder error without one.
func malformedEvent(state *flow.State, pkt *ParsedPacket, proto string, err error) Event {
	attrs := map[string]any{eventfields.KeyError: err.Error()}
	if pkt.HasOffset {
		attrs[eventfields.KeySessionID] = pkt.Session
	}
	return Event{
		FlowID:     state.Key.Hash(),
		Proto:      proto,
		Kind:       "malformed",
		Attributes: attrs,
	}
}

// EndStream drops both directions of a session stream (FIN/RST/abort/expiry
// or generation change) and clears its failed state.
func (m *Manager) EndStream(session string) {
	if m == nil || m.reassembler == nil {
		return
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	for _, dir := range []StreamDir{ClientToServer, ServerToClient} {
		key := sessionStreamKey(session, dir)
		m.reassembler.complete(key)
		m.endStream(key)
	}
}

// streamKey returns the reassembly key, the StreamView session and the
// segment position. Session streams use the caller's absolute offset; legacy
// streams count from the first byte seen, by sequence number when it is
// valid and in arrival order otherwise.
func streamKey(state *flow.State, pkt *ParsedPacket) (key, session string, pos position) {
	if pkt.HasOffset {
		return sessionStreamKey(pkt.Session, pkt.Dir), pkt.Session, position{kind: posOffset, off: pkt.Offset}
	}
	hash := state.Key.Hash()
	if pkt.TCPSeqValid {
		return hash, hash, position{kind: posSeq, seq: pkt.TCPSeq}
	}
	return hash, hash, position{kind: posAppend}
}

func sessionStreamKey(session string, dir StreamDir) string {
	switch dir {
	case ClientToServer:
		return "session/" + session + "/c"
	case ServerToClient:
		return "session/" + session + "/s"
	default:
		return "session/" + session + "/?"
	}
}
