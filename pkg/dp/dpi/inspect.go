// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Inspect passes the packet to the decoders that support the flow. For TCP
// flows the payload is fed through the reassembler so that decoders see the
// accumulated stream rather than individual segments. The first supporting
// StreamDecoder frames the stream through ParseStream and trims it; other
// decoders get OnPacket with the whole buffer, as before.
//
// Streams are keyed by the directional flow hash, or by Session and Dir when
// HasOffset is set. A HasOffset packet without Session or Dir is not framed.
func (m *Manager) Inspect(state *flow.State, pkt *ParsedPacket) InspectResult {
	var res InspectResult
	if m == nil || len(m.decoders) == 0 {
		return res
	}

	stream := pkt.Proto == "tcp" && m.reassembler != nil
	key, session, start, seq := streamKey(state, pkt)
	if pkt.HasOffset && (pkt.Session == "" || pkt.Dir == DirUnknown) {
		stream = false
	}

	failErr := m.failedErr(pkt, key)
	dpiPkt := pkt
	var buf []byte
	var base int64
	fed := false
	if stream && len(pkt.Payload) > 0 && failErr == nil {
		buf, base, res.Gap = m.reassembler.feed(key, pkt.Payload, time.Now(), seq, start)
		dpiPkt = &ParsedPacket{
			Payload: buf,
			Proto:   pkt.Proto,
			SrcPort: pkt.SrcPort,
			DstPort: pkt.DstPort,
		}
		fed = true
	}

	for _, d := range m.candidates(state) {
		if d == nil || !d.Supports(state) {
			continue
		}
		if sd, ok := d.(StreamDecoder); ok && stream {
			if res.Framed {
				continue // one framed decoder per stream direction
			}
			res.Framed = true
			res.Proto = sd.Protocol()
			if failErr != nil {
				res.Err = failErr // already reported with its event; not re-emitted
				continue
			}
			if fed && len(buf) > 0 {
				m.parseFramed(state, sd, &res, key, StreamView{Session: session, Dir: pkt.Dir, Base: base, Bytes: buf}, pkt.HasOffset)
			}
			continue
		}
		events, err := d.OnPacket(state, dpiPkt)
		if err != nil {
			res.Events = append(res.Events, events...)
			res.Err = err
			return res
		}
		res.Events = append(res.Events, events...)
	}
	return res
}

// parseFramed runs one ParseStream call, trims the consumed prefix and, on
// error, discards the stream (legacy) or fails it until EndStream (session).
func (m *Manager) parseFramed(state *flow.State, sd StreamDecoder, res *InspectResult, key string, v StreamView, session bool) {
	sr, err := sd.ParseStream(state, v)
	for _, f := range sr.Frames {
		res.Frames = append(res.Frames, f)
		res.Events = append(res.Events, f.Events...)
	}
	res.NeedMore = sr.NeedMore
	if sr.Consumed > 0 {
		m.reassembler.Trim(key, sr.Consumed)
	}
	if err == nil {
		return
	}
	var fe *FrameError
	if errors.As(err, &fe) {
		res.Events = append(res.Events, fe.Event)
	}
	res.Err = err
	m.reassembler.Complete(key)
	if session {
		m.mu.Lock()
		m.failed[key] = err
		m.mu.Unlock()
	}
}

// EndStream drops both directions of a session stream (FIN/RST/abort/expiry
// or generation change) and clears its failed state.
func (m *Manager) EndStream(session string) {
	if m == nil {
		return
	}
	for _, dir := range []StreamDir{ClientToServer, ServerToClient} {
		key := sessionStreamKey(session, dir)
		if m.reassembler != nil {
			m.reassembler.Complete(key)
		}
		m.mu.Lock()
		delete(m.failed, key)
		m.mu.Unlock()
	}
}

// streamKey returns the reassembly key, the StreamView session, the
// absolute offset a new stream starts at, and the sequence number to feed.
// Legacy streams count offsets from the first byte seen.
func streamKey(state *flow.State, pkt *ParsedPacket) (key, session string, start int64, seq uint32) {
	if pkt.HasOffset {
		return sessionStreamKey(pkt.Session, pkt.Dir), pkt.Session, pkt.Offset, uint32(pkt.Offset)
	}
	hash := state.Key.Hash()
	return hash, hash, 0, pkt.TCPSeq
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

func (m *Manager) failedErr(pkt *ParsedPacket, key string) error {
	if !pkt.HasOffset {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed[key]
}
