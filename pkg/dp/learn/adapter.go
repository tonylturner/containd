// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

// Normalize converts an atomic decoder emission into whole normalized parents.
// Both offline import and explicit live watches use this adapter. serial is an
// adapter-owned monotonic message identity, not part of semantic evidence hashes.
func Normalize(ds evidence.Dataset, state *flow.State, events []dpi.Event, serial *uint64) ([]evidence.Observation, error) {
	if state == nil {
		return nil, fmt.Errorf("missing connection coordinates")
	}
	var parents []evidence.Observation
	apdus := map[string]int{}
	for _, ev := range events {
		identification := ev.Proto == eventfields.ProtoIdentify && ev.Kind == eventfields.KindIdentification
		observationBound := observationBoundEvent(ev)
		if identification {
			if !observationBound {
				continue
			}
			// Retain binding authority even if the passive decoder emits no
			// parent. This is undecoded evidence, not a fabricated ICS message.
			ev.Proto, _ = eventfields.String(ev.Attributes, eventfields.KeyProtocol)
		}
		if !ics.Supported(ev.Proto) {
			continue
		}
		if !identification && ev.Kind != "request" && ev.Kind != "response" && ev.Kind != "apci" && ev.Kind != "malformed" && ev.Kind != "unsupported" && ev.Kind != "exception" && ev.Kind != "session" {
			continue
		}
		wire := state.Key
		k := wire
		if ds.Source == evidence.SourceLive {
			k = state.ServiceKey()
		}
		coordinates := evidence.CoordinatesWire
		authority := evidence.Authority{Wire: tuple(wire), Correlation: "wire", RoleCertain: roleCertain(state, ev), RoleEvidence: PortDecoderAuthority, StandardPort: ics.IsProtocolPortOn(ev.Proto, k.Proto, serverPort(k))}
		if ds.Source == evidence.SourceLive {
			authority.CaptureHook = state.CaptureHook
		}
		if ds.Source == evidence.SourceLive && state.Connection.Load().Verified() {
			logical := tuple(k)
			authority.Logical = &logical
			authority.Correlation = "verified"
			ct := state.Connection.Load().Evidence
			authority.Aliases = &evidence.WireAliases{
				Original: tuple(flow.TupleKey(ct.Original, flow.DirForward)),
				Reply:    tuple(flow.TupleKey(ct.Reply, flow.DirReverse)),
			}
			authority.MappingFingerprint, _ = evidence.Digest(struct {
				Original, Reply any
				Zone            uint16
			}{ct.Original, ct.Reply, ct.Zone})
			coordinates = evidence.CoordinatesLogical
		}
		direction := "request"
		if k.Dir == flow.DirReverse {
			direction = "response"
		}
		if ev.Proto == "iec104" {
			if d, ok := eventfields.String(ev.Attributes, eventfields.KeyDirection); ok {
				direction = d
			}
		}
		transport := "tcp"
		if k.Proto == 17 {
			transport = "udp"
		}
		connection := EvidenceConnectionID(state, ev)
		*serial++
		parentID := strconv.FormatUint(*serial, 10)
		apdu, _ := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
		if ev.Proto == "iec104" && apdu != "" {
			parentID = apdu
		}
		o := evidence.Observation{SchemaVersion: evidence.SchemaVersion, DatasetID: ds.ID, Source: ds.Source, CapturedAt: ev.Timestamp, ConnectionID: connection, ParentID: parentID, Authority: authority, Service: evidence.ServiceKey{ClientIP: k.OpenerIP().String(), ServerIP: k.ServerIP().String(), ServerPort: serverPort(k), Transport: transport, Direction: direction, Protocol: ev.Proto, Coordinates: coordinates}, DecoderVersion: ds.DecoderVersion, ProfileFingerprint: ds.ProfileFingerprint, SnapshotFingerprint: ds.SnapshotFingerprint, Quality: evidence.Quality{Complete: true, Decoded: true}, Outcome: evidence.Outcome{Delivery: "unknown"}, Evidence: []evidence.EvidenceRef{{DatasetID: ds.ID, CaptureSHA256: ds.CaptureSHA256}}}
		if observationBound {
			o.Authority.RoleCertain = false
			o.Authority.RoleEvidence = observationBindingAuthority
		}
		if identification {
			o.Quality.Decoded = false
			parents = append(parents, o)
			continue
		}
		a := ev.Attributes
		o.Quality.Conformance, _ = eventfields.Strings(a, eventfields.KeyConformance)
		o.Quality.Undecoded, _ = eventfields.Strings(a, eventfields.KeyUndecoded)
		incomplete, _ := eventfields.Bool(a, eventfields.KeyCoverageIncomplete)
		o.Quality.Complete = !incomplete && ev.Kind != "malformed"
		o.Quality.Decoded = ev.Kind != "malformed" && ev.Kind != "unsupported"
		switch ev.Proto {
		case "modbus":
			m := &evidence.Modbus{UnitID: bytePtr(a, eventfields.KeyUnitID), FunctionCode: bytePtr(a, eventfields.KeyFunctionCode), Subfunction: wordPtr(a, "sub_function"), MEIType: bytePtr(a, "mei_type"), AndMask: wordPtr(a, "and_mask"), OrMask: wordPtr(a, "or_mask")}
			objects := project.Objects(state, ev, nil)
			for _, obj := range objects {
				for i, sp := range obj.Spans {
					role := "read"
					if obj.WriteOnly {
						role = "write"
					}
					if m.FunctionCode != nil && *m.FunctionCode == 23 && i == 0 {
						role = "read"
					}
					m.Spans = append(m.Spans, evidence.Span{First: sp.Low, Last: sp.High, Role: role})
				}
				if obj.SpansUnknown {
					o.Quality.Complete = false
				}
			}
			if values, ok := a["values"]; ok {
				data, err := json.Marshal(values)
				if err != nil {
					return nil, err
				}
				if err := json.Unmarshal(data, &m.Values); err != nil {
					return nil, fmt.Errorf("invalid modbus values: %w", err)
				}
			}
			if v := wordPtr(a, "value"); v != nil {
				m.Values = append(m.Values, *v)
			}
			o.Modbus = m
			o.ObjectCount = uint32(max(1, len(m.Spans)))
		case "dnp3":
			d := &evidence.DNP3{FunctionCode: bytePtr(a, eventfields.KeyFunctionCode)}
			d.Master, d.Outstation = project.DNP3Stations(a)
			headers, ok := project.DNP3Headers(a["objects"])
			if !ok {
				o.Quality.Decoded = false
			}
			for i, h := range headers {
				g := h.Group
				obj := evidence.DNP3Object{Index: uint32(i), Group: &g, AllObjects: h.Addressing == "all"}
				if h.HasVariation {
					v := h.Variation
					obj.Variation = &v
				}
				if h.HasQualifier {
					v := h.Qualifier
					obj.Qualifier = &v
				}
				if h.HasCount && h.Count <= 1<<32-1 {
					v := uint32(h.Count)
					obj.Count = &v
				}
				spans, unknown := project.DNP3Spans(h)
				for _, sp := range spans {
					obj.Spans = append(obj.Spans, evidence.Span{First: sp.Low, Last: sp.High, Role: "target"})
				}
				if unknown && h.Addressing != "all" && h.Addressing != "count" {
					o.Quality.Complete = false
				}
				obj.DataDigest = h.DataDigest
				d.Objects = append(d.Objects, obj)
				o.ObjectCount += uint32(max(1, len(h.Points)))
			}
			o.DNP3 = d
		case "iec104":
			iec := &evidence.IEC104{TypeID: bytePtr(a, eventfields.KeyTypeID), CA: wordPtr(a, eventfields.KeyCA), COT: bytePtr(a, eventfields.KeyCause), Originator: bytePtr(a, eventfields.KeyOriginator), Negative: boolPtr(a, eventfields.KeyCOTNegative), Test: boolPtr(a, eventfields.KeyCOTTest)}
			iec.APCIType, _ = eventfields.String(a, eventfields.KeyAPCIType)
			if count, ok := eventfields.Uint32(a, eventfields.KeyObjectCount); ok {
				o.ObjectCount = count
			}
			if ioa, ok := eventfields.Uint32(a, eventfields.KeyIOA); ok {
				idx, _ := eventfields.Uint32(a, eventfields.KeyObjectIndex)
				obj := evidence.IEC104Object{Index: idx, IOA: &ioa, Select: boolPtr(a, eventfields.KeySelect), Qualifier: bytePtr(a, eventfields.KeyQualifier)}
				if iec.APCIType == "I" && iec.TypeID != nil && len(rules.IEC104CommandStates(*iec.TypeID)) > 0 {
					obj.CommandState = bytePtr(a, eventfields.KeyValue)
				}
				if v, ok := a[eventfields.KeyValue]; ok {
					obj.ValueDigest, _ = evidence.Digest(v)
				}
				iec.Objects = append(iec.Objects, obj)
			}
			o.IEC104 = iec
			key := connection + "/" + parentID
			if i, ok := apdus[key]; ok {
				p := &parents[i]
				if observationBound {
					p.Authority.RoleCertain = false
					p.Authority.RoleEvidence = observationBindingAuthority
				}
				left, _ := evidence.Digest(struct {
					Type  *uint8
					CA    *uint16
					Count uint32
				}{p.IEC104.TypeID, p.IEC104.CA, p.ObjectCount})
				right, _ := evidence.Digest(struct {
					Type  *uint8
					CA    *uint16
					Count uint32
				}{iec.TypeID, iec.CA, o.ObjectCount})
				if left != right {
					p.Quality.Complete = false
				}
				p.IEC104.Objects = append(p.IEC104.Objects, iec.Objects...)
				p.Quality.Conformance = append(p.Quality.Conformance, o.Quality.Conformance...)
				p.Quality.Undecoded = append(p.Quality.Undecoded, o.Quality.Undecoded...)
				p.Quality.Complete = p.Quality.Complete && o.Quality.Complete
				continue
			}
			apdus[key] = len(parents)
		case "cip":
			o.CIP = &evidence.CIP{Service: bytePtr(a, eventfields.KeyFunctionCode), Class: wordPtr(a, eventfields.KeyObjectClass), Instance: wordPtr(a, eventfields.KeyInstanceID), Attribute: wordPtr(a, eventfields.KeyAttributeID)}
			o.CIP.TargetDigest, _ = evidence.Digest(a)
			o.ObjectCount = 1
		}
		parents = append(parents, o)
	}
	for i := range parents {
		o := &parents[i]
		if o.IEC104 != nil {
			seen := map[uint32]bool{}
			for _, obj := range o.IEC104.Objects {
				if obj.Index >= o.ObjectCount || seen[obj.Index] {
					o.Quality.Complete = false
				}
				seen[obj.Index] = true
			}
			if len(seen) != int(o.ObjectCount) {
				o.Quality.Complete = false
			}
		}
	}
	return parents, nil
}

// EvidenceConnectionID is shared with the collector's rejection path so dropped
// events exclude exactly the identity Normalize would have retained.
func EvidenceConnectionID(state *flow.State, ev dpi.Event) string {
	if ev.Connection != nil && ev.Connection.Key != "" {
		return ev.Connection.Key
	}
	if state != nil {
		if c := state.Connection.Load(); c != nil && c.Key != "" {
			return c.Key
		}
	}
	if ev.FlowID != "" {
		return ev.FlowID
	}
	if state != nil {
		return state.Key.Hash()
	}
	return ""
}

func tuple(k flow.Key) evidence.Tuple {
	transport := "tcp"
	if k.Proto == 17 {
		transport = "udp"
	}
	return evidence.Tuple{Source: evidence.Endpoint{IP: k.SrcIP.String(), Port: k.SrcPort}, Destination: evidence.Endpoint{IP: k.DstIP.String(), Port: k.DstPort}, Transport: transport}
}
func serverPort(k flow.Key) uint16 {
	if k.Dir == flow.DirReverse {
		return k.SrcPort
	}
	return k.DstPort
}
func bytePtr(a map[string]any, k string) *uint8 {
	if v, ok := eventfields.Uint8(a, k); ok {
		return &v
	}
	return nil
}
func wordPtr(a map[string]any, k string) *uint16 {
	if v, ok := eventfields.Uint16(a, k); ok {
		return &v
	}
	return nil
}
func boolPtr(a map[string]any, k string) *bool {
	if v, ok := eventfields.Bool(a, k); ok {
		return &v
	}
	return nil
}

// Without verified correlation or a captured opener, echoed write layouts do
// not establish request direction. Unambiguous read layouts and protocol-level
// station/session direction can still establish roles in midstream captures.
func roleCertain(state *flow.State, ev dpi.Event) bool {
	c := state.Connection.Load()
	if c.Verified() || c != nil && c.Coverage().Load() {
		return true
	}
	switch ev.Proto {
	case "modbus":
		fc := bytePtr(ev.Attributes, eventfields.KeyFunctionCode)
		if ev.Kind == "request" && fc != nil {
			switch *fc {
			case 3, 4, 7, 11, 12, 17:
				return true
			}
		}
	case "dnp3":
		master, outstation := project.DNP3Stations(ev.Attributes)
		direction, _ := eventfields.String(ev.Attributes, eventfields.KeyDirection)
		return master != nil && outstation != nil && ((direction == "master" && state.Key.Dir == flow.DirForward) || (direction == "outstation" && state.Key.Dir == flow.DirReverse))
	case "iec104":
		direction, ok := eventfields.String(ev.Attributes, eventfields.KeyDirection)
		apdu, present := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
		return ok && (direction == "request" || direction == "response") && present && apdu != ""
	}
	return false
}
