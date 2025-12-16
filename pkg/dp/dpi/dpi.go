package dpi

import (
	"time"

	"github.com/containd/containd/pkg/dp/flow"
)

// ParsedPacket is a minimal packet representation for DPI decoders.
// Capture will populate this in later phases.
type ParsedPacket struct {
	Payload []byte
	Proto   string // "tcp", "udp"
	SrcPort uint16
	DstPort uint16
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

// Manager dispatches packets to registered decoders.
type Manager struct {
	decoders []Decoder
}

func NewManager(decoders ...Decoder) *Manager {
	return &Manager{decoders: decoders}
}

func (m *Manager) Add(dec Decoder) {
	if dec == nil {
		return
	}
	m.decoders = append(m.decoders, dec)
}

// OnPacket passes the packet to decoders that support the flow.
func (m *Manager) OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}
	var out []Event
	for _, d := range m.decoders {
		if d == nil || !d.Supports(state) {
			continue
		}
		events, err := d.OnPacket(state, pkt)
		if err != nil {
			return out, err
		}
		out = append(out, events...)
	}
	return out, nil
}

// OnFlowEnd notifies decoders of flow termination.
func (m *Manager) OnFlowEnd(state *flow.State) ([]Event, error) {
	if m == nil || len(m.decoders) == 0 {
		return nil, nil
	}
	var out []Event
	for _, d := range m.decoders {
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
