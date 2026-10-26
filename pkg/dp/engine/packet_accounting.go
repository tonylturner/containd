// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net/netip"
	"reflect"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Resolve the legacy registration names before any engines dispatch packets.
// StreamDecoder supplies its own protocol, including for custom registrations.
var accountingProtocolByType = func() map[reflect.Type]string {
	names := make(map[reflect.Type]string)
	for _, dec := range DefaultDecoders() {
		typ := reflect.TypeOf(dec)
		name := icsDecoderProto[typ.String()]
		if name == "" {
			name = itDecoderProto[typ.String()]
		}
		if name != "" {
			names[typ] = name
		}
	}
	return names
}()

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
	var src, dst netip.Addr
	if state != nil {
		src, _ = netip.AddrFromSlice(state.Key.SrcIP)
		dst, _ = netip.AddrFromSlice(state.Key.DstIP)
		proto = e.packetStatsProtocol(state, proto)
	}
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.stats.RecordPacket(src, dst, proto, len(pkt.Payload), now)
}

// packetStatsProtocol attributes packets without consulting emitted events.
// Resolve once per directional flow, before the first payload is decoded, and
// cache in Application under flowMu. Supports is a flow-level predicate; later
// event protocols never relabel transport counters. Shared-port/unknown services
// retain their transport label. Reconfigure replaces both flows and decoders,
// so no cached labels survive a decoder-set change.
func (e *Engine) packetStatsProtocol(state *flow.State, transport string) string {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	if state.Application != "" {
		return state.Application
	}
	state.Application = e.resolvePacketStatsProtocol(state, transport)
	return state.Application
}

func (e *Engine) resolvePacketStatsProtocol(state *flow.State, transport string) string {
	if transport == "" {
		transport = "unknown"
	}
	proto := ""
	for _, dec := range e.dpiMgr.Decoders() {
		if dec == nil || !dec.Supports(state) {
			continue
		}
		name := ""
		if sd, ok := dec.(dpi.StreamDecoder); ok {
			name = sd.Protocol()
		} else {
			name = accountingProtocolByType[reflect.TypeOf(dec)]
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
