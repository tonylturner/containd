// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// ProtocolPacketDecoder selects an explicit protocol layer without consulting
// endpoint ports. CIP uses this to distinguish encapsulation from implicit I/O.
type ProtocolPacketDecoder interface {
	OnProtocolPacket(*flow.State, *ParsedPacket) ([]Event, error)
}

// NewObservationManager registers only enabled ICS protocols. Supply fresh
// decoder instances, never instances owned by a legacy manager. This manager
// has no port-selected registrations; InspectProtocol is its only dispatch.
func NewObservationManager(decoders ...StreamDecoder) (*Manager, error) {
	m := NewManager()
	m.observation = make(map[string]StreamDecoder)
	for _, d := range decoders {
		if d == nil {
			return nil, fmt.Errorf("nil observation decoder")
		}
		p := d.Protocol()
		switch p {
		case eventfields.ProtoModbus, eventfields.ProtoDNP3, eventfields.ProtoIEC104, eventfields.ProtoCIP:
		default:
			return nil, fmt.Errorf("unknown observation protocol %q", p)
		}
		if p == eventfields.ProtoCIP {
			if _, ok := d.(ProtocolPacketDecoder); !ok {
				return nil, fmt.Errorf("CIP observation requires explicit encapsulation dispatch")
			}
		}
		if m.observation[p] != nil {
			return nil, fmt.Errorf("duplicate observation protocol %q", p)
		}
		m.observation[p] = d
	}
	return m, nil
}

// HasProtocol reports the immutable enabled observation registry.
func (m *Manager) HasProtocol(protocol string) bool {
	return m != nil && m.observation[protocol] != nil
}

// InspectProtocol bypasses port selection and Supports. TCP requires a caller-
// annotated session, direction and offset from ISN+1. It uses the same framing
// contract and session cleanup as Inspect, but returns events only: never a
// policy decision. Unknown and disabled names are errors, never fallbacks.
func (m *Manager) InspectProtocol(protocol string, state *flow.State, pkt *ParsedPacket) InspectResult {
	return m.InspectProtocolAt(protocol, state, pkt, time.Now())
}

// InspectProtocolAt uses an injected ingestion clock for stream expiry.
func (m *Manager) InspectProtocolAt(protocol string, state *flow.State, pkt *ParsedPacket, now time.Time) InspectResult {
	res := InspectResult{Proto: protocol}
	if !m.HasProtocol(protocol) {
		res.Err = fmt.Errorf("unknown or disabled observation protocol %q", protocol)
		return res
	}
	if state == nil || pkt == nil {
		res.Err = fmt.Errorf("observation requires state and packet")
		return res
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	d := m.observation[protocol]
	if pkt.Proto == "udp" {
		if protocol != eventfields.ProtoCIP {
			res.Err = fmt.Errorf("observation protocol %q does not support UDP", protocol)
			return res
		}
		// The constructor requires this explicit layer for CIP; never fall back
		// to the decoder's port-selected OnPacket path.
		pd := d.(ProtocolPacketDecoder)
		res.Events, res.Err = pd.OnProtocolPacket(state, pkt)
		return res
	}
	if pkt.Proto != "tcp" || !pkt.HasOffset || pkt.Session == "" || (pkt.Dir != ClientToServer && pkt.Dir != ServerToClient) || pkt.Offset < 0 {
		res.Err = fmt.Errorf("observation TCP requires session, direction and nonnegative offset")
		return res
	}
	res.Framed = true
	key, session, pos := streamKey(state, pkt)
	if err := m.reassembler.failure(key); err != nil {
		res.Err, res.Failed = err, true
		return res
	}
	if len(pkt.Payload) == 0 {
		return res
	}
	for _, expired := range m.reassembler.sweep(now) {
		m.endStream(expired)
	}
	fed := m.reassembler.feed(key, pos, pkt.Payload, now, true, true, false)
	res.Gap = fed.gap
	var ev *Event
	if fed.err != nil {
		ev = streamError(state, pkt, &res, fed.err)
	} else if len(fed.buf) > 0 {
		ev = m.parseFramed(state, pkt, d, &res, key, StreamView{Session: session, Dir: pkt.Dir, Base: fed.base, Bytes: fed.buf})
	}
	if res.Err != nil {
		m.discard(key, true, res.Err)
	}
	if ev != nil {
		res.Events = append(res.Events, *ev)
	}
	return res
}
