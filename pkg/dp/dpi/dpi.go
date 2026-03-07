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
	decoders    []Decoder
	reassembler *Reassembler
}

func NewManager(decoders ...Decoder) *Manager {
	return &Manager{
		decoders:    decoders,
		reassembler: NewReassembler(defaultReassemblyMax, defaultReassemblyTimeout),
	}
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
		reassembled := m.reassembler.Feed(flowKey, pkt.Payload, time.Now())
		dpiPkt = &ParsedPacket{
			Payload: reassembled,
			Proto:   pkt.Proto,
			SrcPort: pkt.SrcPort,
			DstPort: pkt.DstPort,
		}
		usedReassembly = true
	}

	var out []Event
	for _, d := range m.decoders {
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
