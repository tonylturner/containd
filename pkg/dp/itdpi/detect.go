// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// PortDetector emits coarse IT protocol detections based on ports/signatures.
type PortDetector struct{}

func NewPortDetector() *PortDetector { return &PortDetector{} }

func (d *PortDetector) Supports(state *flow.State) bool { return state != nil }

func (d *PortDetector) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil {
		return nil, nil
	}
	proto := detectProto(pkt)
	if proto == "" {
		return nil, nil
	}
	attrs := map[string]any{
		"detected":   proto,
		"src_port":   pkt.SrcPort,
		"dst_port":   pkt.DstPort,
		"transport":  pkt.Proto,
	}
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      proto,
		Kind:       "detect",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *PortDetector) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

func detectProto(pkt *dpi.ParsedPacket) string {
	// Signature first.
	if len(pkt.Payload) >= 4 && bytes.HasPrefix(pkt.Payload, []byte("SSH-")) {
		return "ssh"
	}
	// Port heuristics.
	switch pkt.SrcPort {
	case 22, 2222, 8022:
		return "ssh"
	case 3389:
		return "rdp"
	case 445, 139:
		return "smb"
	case 161, 162:
		return "snmp"
	case 123:
		return "ntp"
	}
	switch pkt.DstPort {
	case 22, 2222, 8022:
		return "ssh"
	case 3389:
		return "rdp"
	case 445, 139:
		return "smb"
	case 161, 162:
		return "snmp"
	case 123:
		return "ntp"
	}
	return ""
}

