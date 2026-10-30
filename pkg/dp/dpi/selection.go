// SPDX-License-Identifier: Apache-2.0

package dpi

import "github.com/tonylturner/containd/pkg/dp/flow"

// committedSelection shares one dispatch across TCP directions and session
// keys. The existing ownership indexes also bridge wire and session dispatch,
// without another pin or lifecycle. Callers hold streamMu.
func (m *Manager) committedSelection(state *flow.State, id string, pkt *ParsedPacket) []Decoder {
	if selected := m.selected[id]; len(selected) != 0 {
		return selected
	}
	if state.Key.Proto != 6 {
		return nil
	}
	// Hashing the peer allocates. Resolve it only when this direction has
	// no committed selection, never on an established packet's own-id hit.
	peer := peerStreamKey(state, pkt)
	if selected := m.selected[peer]; len(selected) != 0 {
		return selected
	}
	peerFlow := peer
	if pkt != nil && pkt.HasOffset {
		peerFlow = peerFlowID(state)
	}
	for _, flowID := range []string{state.ID(), peerFlow} {
		if selected := m.selected[flowID]; len(selected) != 0 {
			return selected
		}
		for key := range m.flowStreams[flowID] {
			if selected := m.selected[key]; len(selected) != 0 {
				return selected
			}
		}
	}
	return nil
}

func peerFlowID(state *flow.State) string {
	return state.Connection.Load().Peer(state.Key).Hash()
}

// Session streams are independent of directional wire flow IDs. Keep both
// ownership indexes so flow sweeps and explicit session ends can release their
// selections without scanning unrelated flows. All callers hold streamMu.
func (m *Manager) ownSelection(flowID, key string) {
	if flowID == key {
		return // legacy dispatch needs no additional ownership bookkeeping
	}
	streams := m.flowStreams[flowID]
	if streams == nil {
		streams = make(map[string]struct{})
		m.flowStreams[flowID] = streams
	}
	if _, exists := streams[key]; exists {
		return
	}
	streams[key] = struct{}{}
	owners := m.streamFlows[key]
	if owners == nil {
		owners = make(map[string]struct{})
		m.streamFlows[key] = owners
	}
	owners[flowID] = struct{}{}
}

func (m *Manager) releaseSelection(key string) {
	delete(m.selected, key)
	for flowID := range m.streamFlows[key] {
		delete(m.flowStreams[flowID], key)
		if len(m.flowStreams[flowID]) == 0 {
			delete(m.flowStreams, flowID)
		}
	}
	delete(m.streamFlows, key)
}

func (m *Manager) releaseFlowSelection(flowID string) {
	delete(m.selected, flowID)
	for key := range m.flowStreams[flowID] {
		delete(m.streamFlows[key], flowID)
		if len(m.streamFlows[key]) != 0 {
			continue // another wire leg still owns this session direction
		}
		if m.reassembler != nil {
			m.reassembler.complete(key)
		}
		m.endStream(key)
		m.releaseSelection(key)
	}
	delete(m.flowStreams, flowID)
}
