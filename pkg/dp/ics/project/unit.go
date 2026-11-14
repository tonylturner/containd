// SPDX-License-Identifier: Apache-2.0
package project

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// UnitObjects projects immutable decoder authority for live policy. Class and
// direction come from the owning session, never retained event attributes.
func UnitObjects(unit dpi.ParsedUnit, class rules.MessageClass, dir dpi.StreamDir) ([]rules.ICSContext, error) {
	direction := "request"
	if dir == dpi.ServerToClient {
		direction = "response"
	}
	base := rules.ICSContext{MessageClass: class, Direction: direction}
	switch u := unit.(type) {
	case *modbus.Unit:
		s, err := modbus.PairingShape(u)
		if err != nil {
			return nil, err
		}
		base.Protocol = "modbus"
		base.FunctionCode = s.FunctionCode
		base.HasFunctionCode = true
		base.UnitID = &s.UnitID
		base.WriteOnly = modbus.IsWriteFunctionCode(s.FunctionCode)
		base.ReadOnly = !base.WriteOnly
		for _, span := range s.Spans {
			base.Spans = append(base.Spans, rules.AddressSpan{Low: uint32(span.First), High: uint32(span.Last)})
		}
		return []rules.ICSContext{base}, nil
	case *dnp3.Unit:
		s, err := dnp3.PairingShape(u)
		if err != nil {
			return nil, err
		}
		base.Protocol = "dnp3"
		master, outstation := s.Link.Source, s.Link.Destination
		if !s.Link.Master {
			master, outstation = outstation, master
		}
		base.Master, base.Outstation = &master, &outstation
		if !s.LinkOnly {
			base.FunctionCode = s.FunctionCode
			base.HasFunctionCode = true
			base.WriteOnly = dnp3.IsWriteFunctionCode(s.FunctionCode)
			base.ReadOnly = !base.WriteOnly
		}
		if len(s.Objects) == 0 {
			return []rules.ICSContext{base}, nil
		}
		out := make([]rules.ICSContext, 0, len(s.Objects))
		for _, header := range s.Objects {
			obj := base
			obj.Group = &header.Group
			obj.Variation = &header.Variation
			obj.Spans, obj.SpansUnknown = DNP3Spans(header)
			out = append(out, obj)
		}
		return out, nil
	case *iec104.Unit:
		s, err := iec104.PairingShape(u)
		if err != nil {
			return nil, err
		}
		base.Protocol = "iec104"
		ctl := rules.IEC104Context{APCIType: s.Format, SafeRead: s.Format != "I"}
		if s.Format != "I" {
			base.IEC104 = &ctl
			return []rules.ICSContext{base}, nil
		}
		ctl.TypeID, ctl.CA, ctl.COT, ctl.Originator = &s.TypeID, &s.CA, &s.Cause, &s.Originator
		ctl.Negative, ctl.Test = &s.Negative, &s.Test
		ctl.Class = iec104.ClassOf(s.TypeID)
		ctl.SafeRead = ctl.Class == iec104.ClassMonitor && direction == "response" || s.TypeID == 100 || s.TypeID == 70 || s.TypeID == 102 && direction == "request"
		out := make([]rules.ICSContext, 0, len(s.Objects))
		for _, point := range s.Objects {
			obj, c := base, ctl
			c.IOA = &point.IOA
			if (s.TypeID >= 45 && s.TypeID <= 50) || (s.TypeID >= 58 && s.TypeID <= 63) {
				c.Select = &point.Select
			}
			if len(rules.IEC104CommandStates(s.TypeID)) > 0 {
				v := uint8(point.ValueBits)
				c.CommandState = &v
				c.CommandQualifier = &point.Qualifier
			}
			obj.IEC104 = &c
			out = append(out, obj)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported typed policy unit %T", unit)
	}
}
