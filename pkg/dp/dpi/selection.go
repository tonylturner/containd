// SPDX-License-Identifier: Apache-2.0

package dpi

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
