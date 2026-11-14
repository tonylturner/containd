// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"net"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

func classificationEvent(o evidence.Observation) dpi.Event {
	ev := dpi.Event{Proto: o.Service.Protocol, Kind: o.Service.Direction, Attributes: map[string]any{}}
	a := ev.Attributes
	if d := o.DNP3; d != nil {
		if d.FunctionCode != nil {
			a["function_code"] = *d.FunctionCode
		} else if o.MessageClass == string(rules.ClassSession) {
			ev.Kind = "session"
		}
		if d.ApplicationUNS != nil {
			a["application_uns"] = *d.ApplicationUNS
		}
	}
	if d := o.IEC104; d != nil {
		a["apci_type"], a["direction"] = d.APCIType, o.Service.Direction
		if d.TypeID != nil {
			a["type_id"] = *d.TypeID
		}
		if d.COT != nil {
			a["cause"] = *d.COT
		}
	}
	return ev
}

func observationClass(o evidence.Observation) rules.MessageClass {
	class := project.MessageClass(classificationEvent(o))
	if o.MessageClass != "" && o.MessageClass != string(class) {
		return rules.ClassUnknown
	}
	return class
}

func pairingCertifiable(o evidence.Observation) bool {
	if o.Service.Direction != "response" || o.Service.Protocol == "cip" {
		return true
	}
	switch observationClass(o) {
	case rules.ClassAutonomous, rules.ClassSession:
		return true
	case rules.ClassSolicited:
		return o.Source == evidence.SourceLive && o.PairingOutcome == "paired" && o.PairingReason == "paired"
	default:
		return false
	}
}

// observationContexts consumes the common projector. Class facts newly retained
// by normalization are bound here without changing historical observation
// interpretation. APCI controls have no ASDU objects to iterate.
func observationContexts(o evidence.Observation) ([]rules.EvalContext, error) {
	class := observationClass(o)
	if o.MessageClass != "" && class == rules.ClassUnknown {
		return nil, nil
	}
	if o.IEC104 != nil && class == rules.ClassSession {
		if err := o.ValidateEnvelope(); err != nil {
			return nil, err
		}
		objects := project.Objects(nil, classificationEvent(o), iec104.SafeRead)
		var contexts []rules.EvalContext
		for i := range objects {
			contexts = append(contexts, rules.EvalContext{
				SrcIP: net.ParseIP(o.Service.ClientIP), DstIP: net.ParseIP(o.Service.ServerIP),
				Proto: o.Service.Transport, Port: strconv.Itoa(int(o.Service.ServerPort)),
				ICS: &objects[i], Now: o.CapturedAt,
			})
		}
		return contexts, nil
	}
	contexts, err := project.Observation(o)
	for i := range contexts {
		contexts[i].ICS.MessageClass = class
	}
	return contexts, err
}

func optionalStation(v *uint16) []uint16 {
	if v == nil {
		return nil
	}
	return []uint16{*v}
}
