// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// inlinePolicy never substitutes a later lookup, a port heuristic or a subnet
// for receive-time service and interface evidence.
func inlinePolicy(pkt capture.Packet, snap *rules.Snapshot) *flow.InlinePolicy {
	ctx := rules.EvalContext{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, Proto: pkt.Transport,
		Port: strconv.Itoa(int(pkt.DstPort))}
	service := packetKey(pkt)
	service.Dir = flow.DirForward
	p := &flow.InlinePolicy{Context: ctx, Service: service}
	m := pkt.Queue
	if m == nil {
		return p
	}
	ctx.IngressDevice, ctx.EgressDevice = m.IngressDevice, m.EgressDevice
	ct := m.Conntrack
	if ct != nil && ct.DirectionKnown {
		p.Reply = ct.IsReply
		if ct.IsReply {
			ctx.IngressDevice, ctx.EgressDevice = ctx.EgressDevice, ctx.IngressDevice
		}
		// The original client and reply source are independent required
		// coordinates. Missing endpoints never become an invented reverse tuple.
		ctx.SrcIP, ctx.DstIP, ctx.Port = nil, nil, ""
		if ct.Original.Source.IsValid() {
			ctx.SrcIP = net.IP(ct.Original.Source.Addr().AsSlice())
		}
		if ct.Reply.Source.IsValid() {
			ctx.DstIP = net.IP(ct.Reply.Source.Addr().AsSlice())
			ctx.Port = strconv.Itoa(int(ct.Reply.Source.Port()))
		}
		if ct.HasMark && ct.HasStatus {
			ctx.Conntrack = &rules.ConntrackContext{Mark: ct.Mark,
				Original: rules.ConnectionTuple{Source: ct.Original.Source, Destination: ct.Original.Destination},
				Reply:    rules.ConnectionTuple{Source: ct.Reply.Source, Destination: ct.Reply.Destination}}
			// INPUT/OUTPUT do not have both interfaces. Only a verified gate
			// mark supplies its recorded egress zone, never an invented device.
			if ct.Mark&enforce.GateCtMark != 0 && snap != nil {
				index := uint8((ct.Mark & enforce.GateZoneCtMask) >> enforce.GateZoneCtShift)
				for _, zone := range snap.Gate.Zones {
					if zone.Index == index {
						ctx.DstZone = zone.Name
					}
				}
			}
		}
		service.SrcIP, service.DstIP = ctx.SrcIP, ctx.DstIP
		service.SrcPort, service.DstPort = ct.Original.Source.Port(), ct.Reply.Source.Port()
		if ct.IsReply {
			service = service.Reversed()
		}
	}
	ctx.SrcZone = deviceZone(snap, ctx.IngressDevice)
	if ctx.DstZone == "" {
		ctx.DstZone = deviceZone(snap, ctx.EgressDevice)
	}
	p.Context, p.Service = ctx, service
	return p
}

func deviceZone(snap *rules.Snapshot, device string) string {
	if snap == nil || device == "" {
		return ""
	}
	for zone, devices := range snap.ZoneIfaces {
		for _, candidate := range devices {
			if candidate == device {
				return zone
			}
		}
	}
	return ""
}

func statePolicyContext(snap *rules.Snapshot, state *flow.State, zones *zoneCache) rules.EvalContext {
	if p := state.InlinePolicy.Load(); p != nil {
		ctx := p.Context
		// Resolve current policy zones and identities, not an install-time
		// identity or a capture-time rule decision.
		ctx.SrcZone = deviceZone(snap, ctx.IngressDevice)
		ctx.DstZone = deviceZone(snap, ctx.EgressDevice)
		if ct := ctx.Conntrack; ct != nil && ct.Mark&enforce.GateCtMark != 0 && snap != nil {
			index := uint8((ct.Mark & enforce.GateZoneCtMask) >> enforce.GateZoneCtShift)
			for _, zone := range snap.Gate.Zones {
				if zone.Index == index {
					ctx.DstZone = zone.Name
				}
			}
		}
		ctx.Identities = snap.IdentitiesOf(ctx.SrcIP)
		return ctx
	}
	key := state.ServiceKey()
	ctx := rules.EvalContext{SrcIP: key.OpenerIP(), DstIP: key.ServerIP(),
		Proto: protocolName(key.Proto), Port: strconv.Itoa(int(servicePort(state, nil)))}
	ctx.SrcZone, ctx.DstZone = zones.resolve(snap, ctx.SrcIP, ctx.DstIP)
	ctx.Identities = snap.IdentitiesOf(ctx.SrcIP)
	return ctx
}

// Address-scope callers already test transport/ports with parsed packet data.
func stateAddressContext(snap *rules.Snapshot, state *flow.State, zones *zoneCache) rules.EvalContext {
	if state.InlinePolicy.Load() != nil {
		return statePolicyContext(snap, state, zones)
	}
	key := state.ServiceKey()
	ctx := rules.EvalContext{SrcIP: key.OpenerIP(), DstIP: key.ServerIP()}
	ctx.SrcZone, ctx.DstZone = zones.resolve(snap, ctx.SrcIP, ctx.DstIP)
	return ctx
}
