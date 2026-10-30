// SPDX-License-Identifier: Apache-2.0

package dpi

import "github.com/tonylturner/containd/pkg/dp/flow"

// FramingProtocol reports the pinned TCP decoder, or the decoder that would
// own a new stream. It creates no state. Callers use the same session metadata
// as Inspect so passive identification can distinguish ownership from merely
// supporting one of the connection's ports.
func (m *Manager) FramingProtocol(state *flow.State, pkt *ParsedPacket) string {
	if m == nil || !m.reassembles(pkt) {
		return ""
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	if d := m.flowFramer(state, pkt); d != nil {
		return d.Protocol()
	}
	return ""
}

// flowFramer reuses either direction's pin. For a new connection, the server
// endpoint's indexed decoders precede the opener's; registration order breaks
// ties within a port. This is independent of the first direction captured.
// Callers hold streamMu.
func (m *Manager) flowFramer(state *flow.State, pkt *ParsedPacket) StreamDecoder {
	key, _, _ := streamKey(state, pkt)
	peer := state.Key.Reversed().Hash()
	if pkt.HasOffset {
		dir := ClientToServer
		if pkt.Dir == ClientToServer {
			dir = ServerToClient
		}
		peer = sessionStreamKey(pkt.Session, dir)
	}
	if d := m.reassembler.framingDecoder(key, peer); d != nil {
		return d
	}
	// candidates indexes the source endpoint first. Orient only its lookup;
	// Supports and ParseStream always receive the original directional state.
	serverFirst := *state
	if state.Key.Dir == flow.DirForward {
		serverFirst.Key = state.Key.Reversed()
	}
	return firstFramer(m.candidates(&serverFirst), state)
}
