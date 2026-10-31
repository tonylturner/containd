// SPDX-License-Identifier: Apache-2.0

package project

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

// Observation reconstructs decoded facts, not packets, for the same projector
// used by live policy and retained-event preview. Missing facts remain absent.
func Observation(o evidence.Observation) ([]rules.EvalContext, error) {
	if err := o.ValidateEnvelope(); err != nil {
		return nil, err
	}
	s := o.Service
	key := flow.Key{SrcIP: net.ParseIP(s.ClientIP), DstIP: net.ParseIP(s.ServerIP), DstPort: s.ServerPort, Dir: flow.DirForward}
	if key.SrcIP == nil || key.DstIP == nil {
		return nil, fmt.Errorf("invalid service addresses")
	}
	if s.Transport == "tcp" {
		key.Proto = 6
	} else if s.Transport == "udp" {
		key.Proto = 17
	} else {
		return nil, fmt.Errorf("unsupported transport")
	}
	if s.Direction == "response" {
		key = key.Reversed()
	} else if s.Direction != "request" {
		return nil, fmt.Errorf("missing service direction")
	}
	state := &flow.State{Key: key}
	attrs := map[string]any{}
	put := func(k string, v any) { attrs[k] = v }
	if len(o.Quality.Conformance) > 0 {
		put(eventfields.KeyConformance, o.Quality.Conformance)
	}
	if len(o.Quality.Undecoded) > 0 {
		put(eventfields.KeyUndecoded, o.Quality.Undecoded)
	}
	if !o.Quality.Complete || len(o.Quality.Loss) > 0 {
		put(eventfields.KeyCoverageIncomplete, true)
	}
	events := []dpi.Event{{Proto: s.Protocol, Kind: s.Direction, Attributes: attrs, Timestamp: o.CapturedAt}}
	switch {
	case o.Modbus != nil:
		m := o.Modbus
		if m.UnitID != nil {
			put(eventfields.KeyUnitID, *m.UnitID)
		}
		if m.FunctionCode != nil {
			if *m.FunctionCode == 5 && len(m.Values) == 1 {
				put(eventfields.KeyValue, m.Values[0])
			}
			put(eventfields.KeyFunctionCode, *m.FunctionCode)
			put(eventfields.KeyIsWrite, modbus.IsWriteFunctionCode(*m.FunctionCode))
		}
		if m.Subfunction != nil {
			put("sub_function", *m.Subfunction)
		}
		if m.MEIType != nil {
			put("mei_type", *m.MEIType)
		}
		if m.FunctionCode != nil {
			if *m.FunctionCode == 15 {
				put("byte_count", (len(m.Values)+7)/8)
			}
			if *m.FunctionCode == 16 {
				put("byte_count", 2*len(m.Values))
			}
		}
		for i, sp := range m.Spans {
			if sp.First > sp.Last || sp.Last > 65535 {
				return nil, fmt.Errorf("invalid Modbus span")
			}
			if m.FunctionCode != nil && *m.FunctionCode == 23 {
				prefix := "read_"
				if sp.Role == "write" {
					prefix = "write_"
					put("byte_count", 2*(sp.Last-sp.First+1))
				}
				put(prefix+"address", sp.First)
				put(prefix+"quantity", sp.Last-sp.First+1)
			} else {
				if i != 0 {
					return nil, fmt.Errorf("multiple spans in single-target Modbus operation")
				}
				put("address", sp.First)
				put("quantity", sp.Last-sp.First+1)
			}
		}
	case o.DNP3 != nil:
		d := o.DNP3
		if d.FunctionCode != nil {
			put(eventfields.KeyFunctionCode, *d.FunctionCode)
			put(eventfields.KeyIsWrite, dnp3.IsWriteFunctionCode(*d.FunctionCode))
		}
		if d.Master != nil {
			put("source_address", *d.Master)
		}
		if d.Outstation != nil {
			put("destination_address", *d.Outstation)
		}
		put(eventfields.KeyDirection, "master")
		if s.Direction == "response" {
			put(eventfields.KeyDirection, "outstation")
			if d.Master != nil {
				put("destination_address", *d.Master)
			}
			if d.Outstation != nil {
				put("source_address", *d.Outstation)
			}
		}
		headers := make([]dnp3.ObjectHeader, 0, len(d.Objects))
		for _, obj := range d.Objects {
			h := dnp3.ObjectHeader{}
			if obj.Group == nil {
				put(eventfields.KeyCoverageIncomplete, true)
				continue
			}
			h.Group = *obj.Group
			if obj.Variation != nil {
				h.Variation = *obj.Variation
				h.HasVariation = true
			}
			if obj.Qualifier != nil {
				h.Qualifier = *obj.Qualifier
				h.HasQualifier = true
			}
			if obj.Count != nil {
				h.Count = uint64(*obj.Count)
				h.HasCount = true
			}
			if h.Qualifier <= 2 && len(obj.Spans) == 1 {
				lo, hi := obj.Spans[0].First, obj.Spans[0].Last
				h.Start = &lo
				h.Stop = &hi
			}
			if h.Qualifier == 0x17 || h.Qualifier == 0x28 || h.Qualifier == 0x39 {
				for _, sp := range obj.Spans {
					if sp.First != sp.Last {
						return nil, fmt.Errorf("indexed DNP3 span is not a point")
					}
					v := sp.First
					h.Points = append(h.Points, dnp3.Point{Index: &v})
				}
			}
			headers = append(headers, h)
		}
		put("objects", headers)
	case o.IEC104 != nil:
		iec := o.IEC104
		put(eventfields.KeyAPCIType, iec.APCIType)
		put(eventfields.KeyDirection, s.Direction)
		if iec.TypeID != nil {
			put(eventfields.KeyTypeID, *iec.TypeID)
			put(eventfields.KeyClass, iec104.ClassOf(*iec.TypeID))
		}
		if iec.CA != nil {
			put(eventfields.KeyCA, *iec.CA)
		}
		if iec.COT != nil {
			put(eventfields.KeyCause, *iec.COT)
		}
		if iec.Originator != nil {
			put(eventfields.KeyOriginator, *iec.Originator)
		}
		if iec.Negative != nil {
			put(eventfields.KeyCOTNegative, *iec.Negative)
		}
		if iec.Test != nil {
			put(eventfields.KeyCOTTest, *iec.Test)
		}
		events = nil
		for _, obj := range iec.Objects {
			a := make(map[string]any, len(attrs)+3)
			for k, v := range attrs {
				a[k] = v
			}
			if obj.IOA != nil {
				a[eventfields.KeyIOA] = *obj.IOA
			}
			if obj.Select != nil {
				a[eventfields.KeySelect] = *obj.Select
			}
			if obj.Qualifier != nil {
				a[eventfields.KeyQualifier] = *obj.Qualifier
			}
			if obj.CommandState != nil {
				a[eventfields.KeyValue] = *obj.CommandState
			}
			events = append(events, dpi.Event{Proto: s.Protocol, Kind: s.Direction, Attributes: a, Timestamp: o.CapturedAt})
		}
	case o.CIP != nil:
		c := o.CIP
		if c.Service != nil {
			put(eventfields.KeyFunctionCode, *c.Service)
		}
		if c.Class != nil {
			put(eventfields.KeyObjectClass, *c.Class)
		}
		if c.Instance != nil {
			put(eventfields.KeyInstanceID, *c.Instance)
		}
		if c.Attribute != nil {
			put(eventfields.KeyAttributeID, *c.Attribute)
		}
		// CIP is retained but never eligible for a learner certificate.
	default:
		return nil, fmt.Errorf("no decoded protocol facts")
	}
	var contexts []rules.EvalContext
	for _, ev := range events {
		for _, obj := range Objects(state, ev, iec104.SafeRead) {
			obj := obj
			contexts = append(contexts, rules.EvalContext{SrcIP: net.ParseIP(s.ClientIP), DstIP: net.ParseIP(s.ServerIP), Proto: s.Transport, Port: strconv.Itoa(int(s.ServerPort)), ICS: &obj, Now: o.CapturedAt})
		}
	}
	return contexts, nil
}
