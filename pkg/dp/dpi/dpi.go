// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"errors"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	defaultReassemblyMax     = 64 * 1024        // 64 KB buffered per stream direction
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
	TCPSyn  bool   // TCPSeq is the first payload sequence (after the SYN)
	TCPFin  bool   // the segment carries FIN
	TCPRst  bool   // the segment carries RST
	// TCPHandshake marks a SYN or SYN-ACK of a connection whose handshake
	// the kernel's connection tracking has not seen complete. A fail-closed
	// one without it anchors no stream: it was sent into an established
	// connection.
	TCPHandshake bool

	TCPSeqValid bool      // TCPSeq is real (Seq 0 valid)
	Offset      int64     // absolute start of Payload in this direction (only when HasOffset)
	HasOffset   bool      // the caller tracked the handshake and computed Offset
	Session     string    // required when HasOffset
	Dir         StreamDir // required when HasOffset
	// FailClosed asks for a flow stream that cannot resynchronize: its
	// consumed bytes are kept to verify retransmissions, and a framed
	// error fails it until the flow ends instead of restarting it.
	FailClosed bool
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
	streamMu    sync.Mutex // one feed/parse/trim transaction across capture workers
	decoders    []Decoder
	tcpByPort   map[uint16][]Decoder // TCP port -> matching decoders
	udpByPort   map[uint16][]Decoder // UDP port -> matching decoders
	anyDecoders []Decoder            // decoders with no port-specific hint
	reassembler *reassembler
	streamEnds  map[string]streamEnd
}

type streamEnd struct {
	decoder StreamEnder
	session string
	dir     StreamDir
}

func NewManager(decoders ...Decoder) *Manager {
	m := &Manager{
		tcpByPort:   make(map[uint16][]Decoder),
		udpByPort:   make(map[uint16][]Decoder),
		reassembler: newReassembler(defaultReassemblyMax, defaultReassemblyTimeout),
		streamEnds:  make(map[string]streamEnd),
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

// OnPacket passes the packet to decoders that support the flow and returns
// only the events. It is Inspect without the framing metadata.
func (m *Manager) OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error) {
	res := m.Inspect(state, pkt)
	return res.Events, res.Err
}

// OnFlowEnd notifies decoders of flow termination and cleans up reassembly
// state for the flow.
func (m *Manager) OnFlowEnd(state *flow.State) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}
	m.streamMu.Lock()
	defer m.streamMu.Unlock()

	// Clean up reassembly buffer for this flow.
	if m.reassembler != nil {
		key := state.Key.Hash()
		m.reassembler.complete(key)
		m.endStream(key)
	}
	return m.flowEnd(state)
}

// flowEnd returns the decoders' flow-end events. Must be called with
// streamMu held.
func (m *Manager) flowEnd(state *flow.State) ([]Event, error) {
	var out []Event
	var errs []error
	for _, d := range m.candidates(state) {
		if d == nil || !d.Supports(state) {
			continue
		}
		events, err := d.OnFlowEnd(state)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, events...)
	}
	return out, errors.Join(errs...)
}
