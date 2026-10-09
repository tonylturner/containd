// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	defaultReassemblyMax     = 64 * 1024        // 64 KB per stream
	defaultReassemblyTimeout = 30 * time.Second // idle stream timeout
)

// ParsedPacket is a minimal packet representation for DPI decoders.
type ParsedPacket struct {
	Payload []byte
	Proto   string // "tcp", "udp"
	SrcPort uint16
	DstPort uint16
	// TCPSeq is the sequence number of the first payload byte. It is
	// meaningful only when HasTCPSeq is set; zero is a valid sequence.
	TCPSeq    uint32
	HasTCPSeq bool
	// TCPSyn marks a SYN segment: the sender starts a new sequence space
	// at TCPSeq, replacing any stream state an earlier connection on the
	// same tuple left behind.
	TCPSyn bool
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

	// streamMu makes Feed -> DecodeStream -> Trim atomic per packet. The
	// engine calls OnPacket from one goroutine per capture interface, and
	// a forwarded segment is captured on both its ingress and egress
	// interface; without the lock two goroutines could decode the same
	// bytes twice or trim bytes the other has not parsed yet.
	streamMu sync.Mutex
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

// OnPacket passes the packet to decoders that support the flow. TCP
// payload for StreamDecoders goes through the reassembler, so they see
// the in-order byte stream of the flow direction and each message is
// decoded exactly once; all other decoders see the packet as captured.
func (m *Manager) OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}
	var streamDecoders []StreamDecoder
	var packetDecoders []Decoder
	for _, d := range m.candidates(state) {
		if d == nil || !d.Supports(state) {
			continue
		}
		if sd, ok := d.(StreamDecoder); ok && pkt.Proto == "tcp" && m.reassembler != nil {
			streamDecoders = append(streamDecoders, sd)
			continue
		}
		packetDecoders = append(packetDecoders, d)
	}

	out := m.decodeStream(state, pkt, streamDecoders)
	for _, d := range packetDecoders {
		events, err := d.OnPacket(state, pkt)
		if err != nil {
			return out, err
		}
		out = append(out, events...)
	}
	return out, nil
}

// decodeStream feeds the segment into the flow direction's stream, lets
// every stream decoder frame the buffered bytes, and drops the bytes they
// consumed. Decoders parse the same buffer, so the largest consumption
// wins.
func (m *Manager) decodeStream(state *flow.State, pkt *ParsedPacket, decoders []StreamDecoder) []Event {
	if len(decoders) == 0 {
		return nil
	}
	flowKey := state.Key.Hash()
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	if pkt.TCPSyn && pkt.HasTCPSeq {
		m.reassembler.Open(flowKey, pkt.TCPSeq, time.Now())
	}
	if len(pkt.Payload) == 0 {
		return nil
	}
	stream := m.reassembler.Feed(flowKey, pkt.Payload, time.Now(), pkt.TCPSeq, pkt.HasTCPSeq)
	var out []Event
	consumed := 0
	for _, d := range decoders {
		events, n := d.DecodeStream(state, stream)
		out = append(out, events...)
		consumed = max(consumed, n)
	}
	m.reassembler.Trim(flowKey, consumed)
	return out
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
