// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// IEC104ObservationFromEvents extracts one ASDU, not one observation per object.
// The caller supplies session, endpoints, direction and time. APCI-only frames
// and undecodable ASDU headers have no inventory identity.
func IEC104ObservationFromEvents(evs []dpi.Event) (IEC104Observation, bool) {
	if len(evs) == 0 {
		return IEC104Observation{}, false
	}
	a := evs[0].Attributes
	ca, hasCA := eventfields.Uint16(a, eventfields.KeyCA)
	typ, hasType := eventfields.Uint8(a, eventfields.KeyTypeID)
	if !hasCA || !hasType {
		return IEC104Observation{}, false
	}
	o := IEC104Observation{CA: ca, TypeID: typ}
	o.COT, _ = eventfields.Uint8(a, eventfields.KeyCause)
	for _, ev := range evs[:min(len(evs), 127)] {
		if ioa, ok := eventfields.Uint32(ev.Attributes, eventfields.KeyIOA); ok {
			o.IOAs = append(o.IOAs, ioa)
		}
	}
	return o, true
}

// IsCommand reports whether this observation counts as an attempted command.
func (o IEC104Observation) IsCommand() bool {
	return o.ControlDirection && commandType(o.TypeID)
}

// RecordIEC104DeliveryOverflow counts commands whose delivery evidence could
// not fit the engine's bounded ledger. Such commands are never credited as
// accepted. Call outside the IEC table lock, like the other input methods.
func (inv *Inventory) RecordIEC104DeliveryOverflow(n uint64) {
	inv.iec104.busyOutcomes.Add(n)
}
