// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// learnableICSEvent reports ICS events that may feed the asset inventory
// and the learner. IEC104 events never do: B does not auto-learn or render
// permissive IEC104 rules (spec §7.4).
func learnableICSEvent(ev dpi.Event) bool {
	return isICSEvent(ev.Proto, ev.Kind) && !strings.EqualFold(ev.Proto, eventfields.ProtoIEC104)
}

// iecIdentityKeys are the IEC104 command identity attributes that derived
// alerts keep (spec §7.4), so an alert names its command, CA and IOA and
// groups with its session in /flows.
var iecIdentityKeys = []string{
	eventfields.KeySessionID, eventfields.KeyAPDUID, eventfields.KeyDirection,
	eventfields.KeyAPCIType, eventfields.KeyTypeID, eventfields.KeyClass,
	eventfields.KeyCA, eventfields.KeyIOA, eventfields.KeySelect,
	eventfields.KeyUFunction, eventfields.KeyCause,
}

// withDerivedIdentity copies the IEC104 identity of ev into a derived
// alert's attributes. Alerts derived from other protocols are unchanged.
func withDerivedIdentity(ev dpi.Event, attrs map[string]any) map[string]any {
	if !strings.EqualFold(ev.Proto, eventfields.ProtoIEC104) {
		return attrs
	}
	for _, k := range iecIdentityKeys {
		if v, ok := ev.Attributes[k]; ok {
			attrs[k] = v
		}
	}
	return attrs
}
