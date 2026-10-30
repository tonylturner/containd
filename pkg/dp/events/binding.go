// SPDX-License-Identifier: Apache-2.0

package events

import (
	"github.com/tonylturner/containd/pkg/dp/flow"
	"maps"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// A record lives as long as any event of its group remains in the general
// ring. Binding survives eviction of the identification (or decoder) event,
// without creating an unbounded second flow store.
type bindingRecord struct {
	connection     flow.TransportConnectionID
	refs           int
	wires          map[string]int
	application    string
	identification map[string]any
}

func (s *Store) retainBinding(ev Event) {
	if s.bindings == nil {
		s.bindings = map[string]*bindingRecord{}
	}
	key, _ := flowGroup(ev)
	r := s.bindings[key]
	if r == nil {
		r = &bindingRecord{wires: map[string]int{}}
		s.bindings[key] = r
	}
	if ev.TransportConnectionID != "" {
		r.connection = ev.TransportConnectionID
	}
	r.refs++
	r.wires[ev.FlowID]++
	if r.refs == 1 && r.identification == nil && r.connection != "" {
		for _, other := range s.bindings {
			if other != r && other.connection == r.connection && other.identification != nil {
				r.identification = maps.Clone(other.identification)
				r.application = other.application
				break
			}
		}
	}
	if key != ev.FlowID && r.identification == nil {
		if wire := s.bindings[ev.FlowID]; wire != nil && wire.identification != nil {
			r.identification = maps.Clone(wire.identification)
			r.application = wire.application
		}
	}
	if ev.Proto == eventfields.ProtoIdentify && ev.Kind == eventfields.KindIdentification {
		r.identification = maps.Clone(ev.Attributes)
		for otherKey, other := range s.bindings {
			if otherKey != key && (other.wires[ev.FlowID] > 0 || r.connection != "" && other.connection == r.connection) {
				other.identification = maps.Clone(ev.Attributes)
				if ev.Attributes[eventfields.KeyIdentificationState] == "confirmed" {
					other.application, _ = ev.Attributes[eventfields.KeyProtocol].(string)
				}
			}
		}
		if ev.Attributes[eventfields.KeyIdentificationState] == "confirmed" {
			if p, ok := ev.Attributes[eventfields.KeyProtocol].(string); ok && p != "" {
				r.application = p
			}
		}
		return
	}
	if ev.Attributes[eventfields.KeyObservationOnly] == true {
		// Observation output can be the only retained evidence for a session
		// group (IEC events carry a frozen session_id across wire directions).
		r.application = ev.Proto
		return
	}
	if r.identification != nil && r.identification[eventfields.KeyIdentificationState] == "confirmed" {
		return
	}
	if legacyApplication(ev) != "" {
		r.application = ev.Proto
	}
}

func (s *Store) releaseBinding(ev Event) {
	key, _ := flowGroup(ev)
	if r := s.bindings[key]; r != nil {
		r.refs--
		r.wires[ev.FlowID]--
		if r.wires[ev.FlowID] == 0 {
			delete(r.wires, ev.FlowID)
		}
		if r.refs == 0 {
			delete(s.bindings, key)
		}
	}
}

func legacyApplication(ev Event) string {
	// Protocol, service, firewall and identification markers describe telemetry,
	// not a decoder binding. Only application decoder output names an app.
	switch ev.Proto {
	case "modbus", "dnp3", "iec104", "cip":
		switch ev.Kind {
		case "request", "response", "exception", "malformed", "unsupported", "apci", "session":
			return ev.Proto
		}
	case "dns", "tls", "http", "ssh", "smb", "ntp", "snmp", "rdp":
		if ev.Kind == "protocol" || ev.Kind == "port" || ev.Kind == "detect" {
			return ""
		}
		return ev.Proto
	}
	return ""
}
