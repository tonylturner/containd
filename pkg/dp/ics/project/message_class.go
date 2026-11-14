// SPDX-License-Identifier: Apache-2.0

package project

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// MessageClass projects decoded event facts for offline predicate preview.
// It never trusts message_class or pairing stamps and cannot establish pairing
// or live authority; live classification must consume a typed decoder unit.
func MessageClass(ev dpi.Event) rules.MessageClass {
	if ev.Kind == eventfields.KindMalformed || ev.Kind == eventfields.KindUnsupported {
		return rules.ClassUnknown
	}
	a := ev.Attributes
	if _, failed := a[eventfields.KeyError]; failed {
		return rules.ClassUnknown
	}
	switch strings.ToLower(ev.Proto) {
	case eventfields.ProtoModbus:
		switch ev.Kind {
		case "request":
			return rules.ClassRequest
		case "response", "exception":
			return rules.ClassSolicited
		}
	case eventfields.ProtoDNP3:
		fc, ok := eventfields.Uint8(a, eventfields.KeyFunctionCode)
		if !ok {
			if ev.Kind == "session" {
				return rules.ClassSession
			}
			return rules.ClassUnknown
		}
		if fc == 0 {
			return rules.ClassSession
		}
		uns, hasUNS := eventfields.Bool(a, "application_uns")
		if !hasUNS || (fc == 130) != uns {
			return rules.ClassUnknown
		}
		if fc == 130 {
			return rules.ClassAutonomous
		}
		if fc == 129 {
			return rules.ClassSolicited
		}
		if fc >= 1 && fc <= 33 {
			return rules.ClassRequest
		}
	case eventfields.ProtoIEC104:
		apci, _ := eventfields.String(a, eventfields.KeyAPCIType)
		if apci == "S" || apci == "U" {
			return rules.ClassSession
		}
		id, hasID := eventfields.Uint8(a, eventfields.KeyTypeID)
		cot, hasCOT := eventfields.Uint8(a, eventfields.KeyCause)
		dir, _ := eventfields.String(a, eventfields.KeyDirection)
		if apci != "I" || !hasID || !hasCOT || iec104.ClassOf(id) == iec104.ClassUnknown {
			return rules.ClassUnknown
		}
		if dir == "request" && (cot == 5 || cot == 6 || cot == 8) {
			return rules.ClassRequest
		}
		if dir != "response" {
			return rules.ClassUnknown
		}
		if (iec104.ClassOf(id) == iec104.ClassMonitor && cot >= 1 && cot <= 3) || (id == 70 && cot == 4) {
			return rules.ClassAutonomous
		}
		if cot == 5 || cot == 7 || cot == 9 || cot == 10 || (cot >= 20 && cot <= 36) {
			return rules.ClassSolicited
		}
	}
	return rules.ClassUnknown
}
