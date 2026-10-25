// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// recordPacketStats is called once by the handler that owns the packet. Generic
// flows count before any cached verdict return; IEC probes count once ownership
// is known, or leave accounting to handleFlowPacket when they decline it.
// Held-token resolutions and flow-end events are not packet arrivals and never
// call this method.
func (e *Engine) recordPacketStats(pkt capture.Packet, state *flow.State) {
	if e == nil || e.stats == nil {
		return
	}
	proto := pkt.Transport
	src, dst := "", ""
	if state != nil {
		src, dst = stateIPs(state)
		proto = e.packetStatsProtocol(state, proto)
	}
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.stats.RecordPacket(src, dst, proto, len(pkt.Payload), now)
}

// packetStatsProtocol attributes packets without consulting emitted events.
// Supporting decoders identify the service even for a split APDU's first
// segment, an ACK or a retransmit. Shared-port/unknown services retain their
// transport label rather than arbitrarily charging one protocol or both.
func (e *Engine) packetStatsProtocol(state *flow.State, transport string) string {
	proto := ""
	for _, dec := range e.dpiMgr.Decoders() {
		if dec == nil || !dec.Supports(state) {
			continue
		}
		name := ""
		if sd, ok := dec.(dpi.StreamDecoder); ok {
			name = sd.Protocol()
		} else {
			typeName := fmt.Sprintf("%T", dec)
			name = icsDecoderProto[typeName]
			if name == "" {
				name = itDecoderProto[typeName]
			}
		}
		if name == "" {
			continue // Utility detectors do not identify a unique service.
		}
		if proto != "" && proto != name {
			return transport
		}
		proto = name
	}
	if proto == "" {
		return transport
	}
	return proto
}
