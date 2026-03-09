// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	defaultReassemblyMax     = 64 * 1024       // 64 KB per stream
	defaultReassemblyTimeout = 30 * time.Second // idle stream timeout
)

// ParsedPacket is a minimal packet representation for DPI decoders.
// Capture will populate this in later phases.
type ParsedPacket struct {
	Payload []byte
	Proto   string // "tcp", "udp"
	SrcPort uint16
	DstPort uint16
	TCPSeq  uint32 // TCP sequence number (0 for UDP)
}

// Event is emitted by decoders and fed to rules/IDS/telemetry.
type Event struct {
	FlowID     string
	Proto      string
	Kind       string
	Attributes map[string]any
	Timestamp  time.Time
}

// Decoder inspects packets for a given flow and emits protocol events.
type Decoder interface {
	Supports(state *flow.State) bool
	OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error)
	OnFlowEnd(state *flow.State) ([]Event, error)
}

// PortHinter is an optional interface that decoders can implement to
// declare the TCP/UDP ports they handle. This allows the Manager to
// build a port-based index and skip calling Supports() on every decoder
// for every packet. Decoders that do not implement PortHinter are
// consulted for every packet via the fallback path.
type PortHinter interface {
	// Ports returns the TCP and UDP ports this decoder handles.
	// Return nil slices if the decoder uses custom Supports() logic.
	Ports() (tcpPorts, udpPorts []uint16)
}

// Manager dispatches packets to registered decoders.
type Manager struct {
	decoders    []Decoder
	tcpByPort   map[uint16][]Decoder // TCP port -> matching decoders
	udpByPort   map[uint16][]Decoder // UDP port -> matching decoders
	anyDecoders []Decoder            // decoders with no port-specific hint
	reassembler *Reassembler
}

func NewManager(decoders ...Decoder) *Manager {
	m := &Manager{
		tcpByPort:   make(map[uint16][]Decoder),
		udpByPort:   make(map[uint16][]Decoder),
		reassembler: NewReassembler(defaultReassemblyMax, defaultReassemblyTimeout),
	}
	for _, d := range decoders {
		m.Add(d)
	}
	return m
}

// Decoders returns the registered decoders.
func (m *Manager) Decoders() []Decoder {
	if m == nil {
		return nil
	}
	return m.decoders
}

func (m *Manager) Add(dec Decoder) {
	if dec == nil {
		return
	}
	m.decoders = append(m.decoders, dec)
	if ph, ok := dec.(PortHinter); ok {
		tcpPorts, udpPorts := ph.Ports()
		if len(tcpPorts) > 0 || len(udpPorts) > 0 {
			for _, p := range tcpPorts {
				m.tcpByPort[p] = append(m.tcpByPort[p], dec)
			}
			for _, p := range udpPorts {
				m.udpByPort[p] = append(m.udpByPort[p], dec)
			}
			return
		}
	}
	// Decoder has no port hint — consult on every packet.
	m.anyDecoders = append(m.anyDecoders, dec)
}

// candidates returns the decoders that may handle the given flow based
// on port indexing, plus all fallback (anyDecoders) decoders.
func (m *Manager) candidates(state *flow.State) []Decoder {
	var portMap map[uint16][]Decoder
	switch state.Key.Proto {
	case 6: // TCP
		portMap = m.tcpByPort
	case 17: // UDP
		portMap = m.udpByPort
	}

	// Collect port-indexed decoders for both src and dst ports.
	var indexed []Decoder
	if portMap != nil {
		if decs := portMap[state.Key.SrcPort]; len(decs) > 0 {
			indexed = append(indexed, decs...)
		}
		if decs := portMap[state.Key.DstPort]; len(decs) > 0 {
			// Avoid duplicates when SrcPort == DstPort.
			if state.Key.SrcPort != state.Key.DstPort {
				indexed = append(indexed, decs...)
			}
		}
	}

	if len(indexed) == 0 {
		return m.anyDecoders
	}
	if len(m.anyDecoders) == 0 {
		return indexed
	}
	return append(indexed, m.anyDecoders...)
}

// OnPacket passes the packet to decoders that support the flow.
// For TCP flows the payload is fed through the reassembler so that
// decoders see the full accumulated stream rather than individual
// segments.
func (m *Manager) OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}

	// For TCP flows, use the reassembler to accumulate payloads.
	usedReassembly := false
	flowKey := state.Key.Hash()
	dpiPkt := pkt
	if pkt.Proto == "tcp" && len(pkt.Payload) > 0 && m.reassembler != nil {
		reassembled := m.reassembler.Feed(flowKey, pkt.Payload, time.Now(), pkt.TCPSeq)
		dpiPkt = &ParsedPacket{
			Payload: reassembled,
			Proto:   pkt.Proto,
			SrcPort: pkt.SrcPort,
			DstPort: pkt.DstPort,
		}
		usedReassembly = true
	}

	var out []Event
	for _, d := range m.candidates(state) {
		if d == nil || !d.Supports(state) {
			continue
		}
		events, err := d.OnPacket(state, dpiPkt)
		if err != nil {
			return out, err
		}
		out = append(out, events...)

		// If the decoder implements StreamDecoder, trim consumed bytes.
		if usedReassembly {
			if sd, ok := d.(StreamDecoder); ok {
				if consumed := sd.ConsumedBytes(); consumed > 0 {
					m.reassembler.Trim(flowKey, consumed)
				}
			}
		}
	}
	return out, nil
}

// OnFlowEnd notifies decoders of flow termination and cleans up reassembly
// state for the flow.
func (m *Manager) OnFlowEnd(state *flow.State) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}

	// Clean up reassembly buffer for this flow.
	if m.reassembler != nil {
		m.reassembler.Complete(state.Key.Hash())
	}

	var out []Event
	for _, d := range m.candidates(state) {
		if d == nil || !d.Supports(state) {
			continue
		}
		events, err := d.OnFlowEnd(state)
		if err != nil {
			return out, err
		}
		out = append(out, events...)
	}
	return out, nil
}
