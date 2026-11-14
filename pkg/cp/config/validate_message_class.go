// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
)

// checkMessageClassKeys also rejects incompatible fields supplied with zero
// values. Merge-patch nulls are deleted before the merged object reaches here.
func checkMessageClassKeys(p ICSPredicate, fields map[string]json.RawMessage) error {
	if p.MessageClass == "" {
		return nil
	}
	for key := range fields {
		if incompatibleClassKey(p, key) {
			return fmt.Errorf("ics %s is incompatible with messageClass %s", key, p.MessageClass)
		}
	}
	return validateMessageClass(p, "")
}

func incompatibleClassKey(p ICSPredicate, key string) bool {
	switch key {
	case "writeOnly", "unitId", "objectClasses", "instances", "attributes", "tags",
		"selectExecute", "commandStates", "commandQualifiers":
		return true
	}
	if p.MessageClass != "session" {
		return false
	}
	switch key {
	case "groups", "variations", "addresses":
		return true
	case "typeIds", "classes", "ca", "ioa", "cot", "originators", "negative", "test":
		return true
	case "functionCode":
		return p.Protocol != "dnp3"
	}
	return false
}

func validateMessageClass(p ICSPredicate, ruleID string) error {
	if p.MessageClass == "" {
		return nil
	}
	fail := func(detail string) error {
		return fmt.Errorf("rule %s ics messageClass %s: %s", ruleID, p.MessageClass, detail)
	}
	if p.MessageClass != "autonomous" && p.MessageClass != "session" {
		return fail("must be autonomous or session")
	}
	if p.Protocol != "dnp3" && p.Protocol != ICSProtocolIEC104 {
		return fail("requires protocol dnp3 or iec104")
	}
	if p.Direction != "request" && p.Direction != "response" {
		return fail("requires direction request or response")
	}
	if p.MessageClass == "autonomous" && p.Direction != "response" {
		return fail("autonomous requires direction response")
	}
	if p.WriteOnly || p.UnitID != nil || p.ObjectClasses != nil || p.Instances != nil ||
		p.Attributes != nil || p.Tags != nil || p.SelectExecute != "" ||
		p.CommandStates != nil || p.CommandQualifiers != nil {
		return fail("incompatible access or object predicate")
	}
	if p.MessageClass == "session" {
		if p.Groups != nil || p.Variations != nil || p.Addresses != nil || iec104FieldSet(p) != "" {
			return fail("session controls have no application object selectors")
		}
	}
	if p.Protocol == "dnp3" {
		want := uint8(130)
		if p.MessageClass == "session" {
			want = 0 // application Confirm; omitted also covers link controls
		}
		for _, fc := range p.FunctionCode {
			if fc != want {
				return fail(fmt.Sprintf("incompatible functionCode %d; only %d is supported", fc, want))
			}
		}
		return nil
	}
	if p.MessageClass == "session" {
		if p.FunctionCode != nil {
			return fail("IEC session controls cannot select functionCode")
		}
		return nil
	}
	if p.Negative != nil && *p.Negative {
		return fail("autonomous messages cannot be negative confirmations")
	}
	for _, class := range p.Classes {
		if class != "monitor" && class != "system" {
			return fail("autonomous classes must be monitor or system")
		}
	}
	for _, id := range p.TypeIDs {
		if id < 1 || id > 255 || (iec104.ClassOf(uint8(id)) != iec104.ClassMonitor && id != 70) {
			return fail(fmt.Sprintf("incompatible typeIds value %d", id))
		}
		if len(p.Classes) > 0 && !slices.Contains(p.Classes, iec104.ClassOf(uint8(id))) {
			return fail("typeIds and classes have incompatible values")
		}
	}
	hasMonitor, hasInit := len(p.TypeIDs) == 0, len(p.TypeIDs) == 0
	for _, id := range p.TypeIDs {
		hasMonitor = hasMonitor || id != 70
		hasInit = hasInit || id == 70
	}
	if len(p.Classes) > 0 {
		hasMonitor = hasMonitor && slices.Contains(p.Classes, "monitor")
		hasInit = hasInit && slices.Contains(p.Classes, "system")
	}
	hasMonitorCOT, hasInitCOT := len(p.COT) == 0, len(p.COT) == 0
	for _, cot := range p.COT {
		if cot < 1 || cot > 4 {
			return fail(fmt.Sprintf("incompatible cot value %d", cot))
		}
		if (cot == 4 && !hasInit) || (cot != 4 && !hasMonitor) {
			return fail("cot 4 requires type 70; monitor types require cot 1, 2 or 3")
		}
		hasMonitorCOT = hasMonitorCOT || cot != 4
		hasInitCOT = hasInitCOT || cot == 4
	}
	// An omitted type list permits either autonomous family; it does not
	// require the rule to cover both.
	if len(p.TypeIDs) > 0 && ((hasMonitor && !hasMonitorCOT) || (hasInit && !hasInitCOT)) {
		return fail("typeIds and cot have incompatible values")
	}
	return nil
}
