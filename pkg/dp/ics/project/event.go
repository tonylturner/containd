// SPDX-License-Identifier: Apache-2.0

// Package project is the pure decoded-message to policy-context projection.
package project

import (
	"encoding/json"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Objects consumes decoded targets, never scalar display
// addresses. Coverage is a separate object with message-wide facts only.
func Objects(state *flow.State, ev dpi.Event, safeRead func(map[string]any) bool) []rules.ICSContext {
	if strings.EqualFold(ev.Proto, eventfields.ProtoIEC104) {
		object := iecObject(ev, safeRead)
		if incomplete, _ := eventfields.Bool(ev.Attributes, eventfields.KeyCoverageIncomplete); incomplete {
			object.ObjectUnknown = true
		}
		return []rules.ICSContext{*object}
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
		if base.HasFunctionCode && base.FunctionCode == 5 {
			if value, ok := eventfields.Uint16(a, eventfields.KeyValue); ok {
				base.ValueInvalid = value != 0 && value != 0xff00
			}
		}
		if unit, ok := eventfields.Uint8(a, eventfields.KeyUnitID); ok {
			base.UnitID = &unit
		}
		base.Spans, base.SpansUnknown = ModbusSpans(state, ev)
		objects = append(objects, base)
	case eventfields.ProtoDNP3:
		base.Master, base.Outstation = DNP3Stations(a)
		headers, ok := DNP3Headers(a["objects"])
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
			obj.Spans, obj.SpansUnknown = DNP3Spans(h)
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
		// Responses have no wire target and are not correlated with their
		// requests. Even retained target/coverage attributes cannot turn
		// that absence into an unknown operation that object DENYs match.
		if ev.Kind == eventfields.KindResponse {
			return []rules.ICSContext{base}
		}
		// Encapsulation and implicit-I/O events have message facts but no CIP
		// service operation. Keep their base context for message selectors,
		// without turning absent object facts into unknown object coverage.
		if ev.Kind == "session" {
			objects = append(objects, base)
		} else if !base.HasFunctionCode || base.FunctionCode != 0x0a {
			// Service 0x0a is a container, not an operation. Its children carry
			// their own targets; an incomplete wrapper contributes coverage only.
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

func DNP3Stations(a map[string]any) (master, outstation *uint16) {
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

// DNP3Headers restores typed headers from retained JSON using the same
// schema before context construction, including pointer presence and indexes.
func DNP3Headers(value any) ([]dnp3.ObjectHeader, bool) {
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

func DNP3Spans(h dnp3.ObjectHeader) ([]rules.AddressSpan, bool) {
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

// ModbusSpans bounds a Modbus message's spans by the connection's
// orientation, not the decoder's message kind. A message from the
// connection's opener is a request: unless the decoder decoded it as a
// request with bounded spans, its spans are unknown, so a request the
// decoder labelled a reply (a client using source port 502) cannot pass as
// touching nothing. A reply reads or writes nothing by itself: it touches
// only the spans it echoes (FC 5, 6, 15, 16, 22).
func ModbusSpans(state *flow.State, ev dpi.Event) ([]rules.AddressSpan, bool) {
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

func iecObject(ev dpi.Event, safeRead func(map[string]any) bool) *rules.ICSContext {
	a := ev.Attributes
	c := &rules.IEC104Context{}
	c.APCIType, _ = eventfields.String(a, eventfields.KeyAPCIType)
	c.Class, _ = eventfields.String(a, eventfields.KeyClass)
	if v, ok := eventfields.Uint8(a, eventfields.KeyTypeID); ok {
		c.TypeID = &v
	}
	if v, ok := eventfields.Uint16(a, eventfields.KeyCA); ok {
		c.CA = &v
	}
	if v, ok := eventfields.Uint32(a, eventfields.KeyIOA); ok {
		c.IOA = &v
	}
	if c.APCIType == "I" {
		if v, ok := eventfields.Uint8(a, eventfields.KeyCause); ok {
			c.COT = &v
		}
		if v, ok := eventfields.Uint8(a, eventfields.KeyOriginator); ok {
			c.Originator = &v
		}
		if v, ok := eventfields.Bool(a, eventfields.KeyCOTNegative); ok {
			c.Negative = &v
		}
		if v, ok := eventfields.Bool(a, eventfields.KeyCOTTest); ok {
			c.Test = &v
		}
		if c.TypeID != nil && len(rules.IEC104CommandStates(*c.TypeID)) > 0 {
			if v, ok := eventfields.Uint8(a, eventfields.KeyValue); ok {
				c.CommandState = &v
			}
			if v, ok := eventfields.Uint8(a, eventfields.KeyQualifier); ok {
				c.CommandQualifier = &v
			}
		}
		if c.TypeID != nil && ((*c.TypeID >= 45 && *c.TypeID <= 50) || (*c.TypeID >= 58 && *c.TypeID <= 63)) {
			if v, ok := eventfields.Bool(a, eventfields.KeySelect); ok {
				c.Select = &v
			}
		}
	}
	c.Broadcast = iecBroadcast(a)
	if safeRead != nil {
		c.SafeRead = safeRead(a)
	}
	dir, _ := eventfields.String(a, eventfields.KeyDirection)
	invalid := false
	if c.TypeID != nil {
		switch *c.TypeID {
		case 46, 47, 59, 60:
			if value, ok := eventfields.Uint8(a, eventfields.KeyValue); ok {
				invalid = value != 1 && value != 2
			}
		}
	}
	return &rules.ICSContext{Protocol: eventfields.ProtoIEC104, Direction: dir, IEC104: c, ValueInvalid: invalid}
}

func iecBroadcast(a map[string]any) bool {
	apci, _ := eventfields.String(a, eventfields.KeyAPCIType)
	ca, ok := eventfields.Uint16(a, eventfields.KeyCA)
	return apci == "I" && ok && ca == 65535
}

func isReply(state *flow.State) bool {
	return state != nil && state.ServiceKey().Dir == flow.DirReverse
}
func messageDirection(state *flow.State) string {
	if isReply(state) {
		return "response"
	}
	return "request"
}
