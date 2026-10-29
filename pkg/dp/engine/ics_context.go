// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// evalContextsFromDPIEvent is shared by retained-event preview and live
// evaluation. Every object gets the full rule precedence independently.
func evalContextsFromDPIEvent(snap *rules.Snapshot, state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, srcZone, dstZone string) []rules.EvalContext {
	if state == nil || pkt == nil || !isRuleEvaluableICSEvent(ev.Proto) || isStreamErrorEvent(ev) {
		return nil
	}
	base := rules.EvalContext{
		SrcZone: srcZone, DstZone: dstZone, SrcIP: state.Key.OpenerIP(), DstIP: state.Key.ServerIP(),
		Proto: strings.ToLower(pkt.Proto), Port: strconv.Itoa(int(servicePort(state, pkt))),
		Identities: snap.IdentitiesOf(state.Key.OpenerIP()),
	}
	objects := icsContextsFromDPIEvent(state, ev, nil)
	contexts := make([]rules.EvalContext, len(objects))
	for i := range objects {
		contexts[i] = base
		contexts[i].ICS = &objects[i]
	}
	return contexts
}

// icsContextsFromDPIEvent consumes decoded targets, never scalar display
// addresses. Coverage is a separate object with message-wide facts only.
func icsContextsFromDPIEvent(state *flow.State, ev dpi.Event, safeRead func(map[string]any) bool) []rules.ICSContext {
	if strings.EqualFold(ev.Proto, iecProtocol) {
		return []rules.ICSContext{*iecObjectFromDPIEvent(ev, safeRead)}
	}
	a := ev.Attributes
	write, hasWrite := eventfields.Bool(a, eventfields.KeyIsWrite)
	base := rules.ICSContext{Protocol: strings.ToLower(ev.Proto), Direction: messageDirection(state), ReadOnly: hasWrite && !write, WriteOnly: hasWrite && write}
	if fc, ok := eventfields.Uint8(a, eventfields.KeyFunctionCode); ok {
		base.FunctionCode, base.HasFunctionCode = fc, true
	}
	var objects []rules.ICSContext
	switch base.Protocol {
	case eventfields.ProtoModbus:
		if unit, ok := eventfields.Uint8(a, eventfields.KeyUnitID); ok {
			base.UnitID = &unit
		}
		base.Spans, base.SpansUnknown = modbusAddressSpans(state, ev)
		objects = append(objects, base)
	case eventfields.ProtoDNP3:
		base.Master, base.Outstation = dnp3Stations(a)
		headers, ok := dnp3ObjectHeaders(a["objects"])
		if !ok {
			base.ObjectUnknown = true
		}
		if len(headers) == 0 {
			objects = append(objects, base)
		}
		for i, h := range headers {
			obj := base
			obj.Group = &h.Group
			if h.HasVariation {
				obj.Variation = &h.Variation
			}
			obj.Spans, obj.SpansUnknown = dnp3HeaderSpans(h)
			// A stopped layout retains its header, but its point coverage
			// is unknown even if its start/stop fields were readable.
			if i == len(headers)-1 {
				codes, _ := eventfields.Strings(a, eventfields.KeyUndecoded)
				for _, code := range codes {
					switch code {
					case "dnp3.object_unsupported", "dnp3.object_truncated", "dnp3.object_qualifier":
						obj.SpansUnknown = true
					}
				}
			}
			objects = append(objects, obj)
		}
	case eventfields.ProtoCIP:
		// Service 0x0a is a container, not an operation. Its children carry
		// their own targets; an incomplete wrapper contributes coverage only.
		if !base.HasFunctionCode || base.FunctionCode != 0x0a {
			target, _ := eventfields.String(a, eventfields.KeyCIPTarget)
			base.ObjectUnknown = target == "unknown"
			if v, ok := eventfields.Uint16(a, eventfields.KeyObjectClass); ok {
				base.ObjectClass, base.HasObjectClass = v, true
			}
			if v, ok := eventfields.Uint16(a, eventfields.KeyInstanceID); ok {
				base.Instance = &v
			}
			if v, ok := eventfields.Uint16(a, eventfields.KeyAttributeID); ok {
				base.Attribute = &v
			}
			if target == "symbolic" {
				base.Symbol, _ = eventfields.Strings(a, eventfields.KeyCIPSymbol)
			}
			base.AttributeUnknown = !base.HasFunctionCode || (base.FunctionCode != 0x0e && base.FunctionCode != 0x10 && base.FunctionCode != 0x18 && base.FunctionCode != 0x19)
			base.InstanceUnknown = base.HasFunctionCode && (base.FunctionCode == 0x11 || (base.FunctionCode == 0x55 && base.HasObjectClass && base.ObjectClass == 0x6b))
			objects = append(objects, base)
		}
	}
	if incomplete, _ := eventfields.Bool(a, eventfields.KeyCoverageIncomplete); incomplete {
		coverage := rules.ICSContext{Protocol: base.Protocol, Direction: base.Direction, ObjectUnknown: true}
		if base.Protocol == eventfields.ProtoDNP3 {
			coverage.Master, coverage.Outstation = base.Master, base.Outstation
			coverage.FunctionCode, coverage.HasFunctionCode = base.FunctionCode, base.HasFunctionCode
			coverage.ReadOnly, coverage.WriteOnly = base.ReadOnly, base.WriteOnly
		}
		objects = append(objects, coverage)
	}
	return objects
}

func dnp3Stations(a map[string]any) (master, outstation *uint16) {
	var source, destination *uint16
	if v, ok := eventfields.Uint16(a, "source_address"); ok {
		source = &v
	}
	if v, ok := eventfields.Uint16(a, "destination_address"); ok {
		destination = &v
	}
	dir, _ := eventfields.String(a, eventfields.KeyDirection)
	switch dir {
	case "master":
		return source, destination
	case "outstation":
		return destination, source
	default:
		return nil, nil
	}
}

// The live decoder owns typed headers; retained JSON restores that same
// schema before context construction, including pointer presence and indexes.
func dnp3ObjectHeaders(value any) ([]dnp3.ObjectHeader, bool) {
	if value == nil {
		return nil, true
	}
	if headers, ok := value.([]dnp3.ObjectHeader); ok {
		return headers, true
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var headers []dnp3.ObjectHeader
	if err := json.Unmarshal(encoded, &headers); err != nil {
		return nil, false
	}
	return headers, true
}

func dnp3HeaderSpans(h dnp3.ObjectHeader) ([]rules.AddressSpan, bool) {
	if !h.HasQualifier || !h.HasCount || !h.HasVariation {
		return nil, true
	}
	switch h.Qualifier {
	case 0x00, 0x01, 0x02:
		if h.Start == nil || h.Stop == nil || *h.Start > *h.Stop {
			return nil, true
		}
		return []rules.AddressSpan{{Low: *h.Start, High: *h.Stop}}, false
	case 0x17, 0x28, 0x39:
		spans := make([]rules.AddressSpan, 0, len(h.Points))
		unknown := uint64(len(h.Points)) != h.Count
		for _, p := range h.Points {
			if p.Index == nil {
				unknown = true
				continue
			}
			spans = append(spans, rules.AddressSpan{Low: *p.Index, High: *p.Index})
		}
		return spans, unknown
	default:
		return nil, true
	}
}

// modbusAddressSpans bounds a Modbus message's spans by the connection's
// orientation, not the decoder's message kind. A message from the
// connection's opener is a request: unless the decoder decoded it as a
// request with bounded spans, its spans are unknown, so a request the
// decoder labelled a reply (a client using source port 502) cannot pass as
// touching nothing. A reply reads or writes nothing by itself: it touches
// only the spans it echoes (FC 5, 6, 15, 16, 22).
func modbusAddressSpans(state *flow.State, ev dpi.Event) ([]rules.AddressSpan, bool) {
	spans, ok := modbus.AddressSpans(ev.Attributes)
	if !isReply(state) && (ev.Kind != "request" || !ok) {
		return nil, true
	}
	if len(spans) == 0 {
		return nil, false
	}
	out := make([]rules.AddressSpan, len(spans))
	for i, sp := range spans {
		out[i] = rules.AddressSpan{Low: uint32(sp.First), High: uint32(sp.Last)}
	}
	return out, false
}
