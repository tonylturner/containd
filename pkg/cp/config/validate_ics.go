// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import "fmt"

// ICSProtocolIEC104 is the ICS predicate protocol of IEC 60870-5-104 rules.
const ICSProtocolIEC104 = "iec104"

// icsProtocols are the protocols an ICS predicate can name.
var icsProtocols = map[string]struct{}{
	"modbus": {}, "dnp3": {}, "cip": {}, "s7comm": {}, "mms": {}, "bacnet": {}, "opcua": {},
	ICSProtocolIEC104: {},
}

func validateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Mode != "" && p.Mode != "learn" && p.Mode != "enforce" {
		return fmt.Errorf("rule %s ics mode invalid %q", ruleID, p.Mode)
	}
	if p.Protocol == "" {
		return validateICSWithoutProtocol(p, ruleID)
	}
	if _, ok := icsProtocols[p.Protocol]; !ok {
		return fmt.Errorf("rule %s ics protocol %q is not supported", ruleID, p.Protocol)
	}
	if p.ReadOnly && p.WriteOnly {
		return fmt.Errorf("rule %s ics predicate cannot be both readOnly and writeOnly", ruleID)
	}
	if p.Direction != "" && p.Direction != "request" && p.Direction != "response" {
		return fmt.Errorf("rule %s ics direction invalid %q", ruleID, p.Direction)
	}
	if p.Protocol == ICSProtocolIEC104 {
		return validateIEC104Predicate(p, ruleID)
	}
	if field := iec104FieldSet(p); field != "" {
		return fmt.Errorf("rule %s ics %s is only supported for protocol iec104", ruleID, field)
	}
	if len(p.ObjectClasses) > 0 && p.Protocol != "cip" {
		return fmt.Errorf("rule %s ics objectClasses only supported for cip protocol", ruleID)
	}
	return nil
}

// validateICSWithoutProtocol rejects semantic values on a predicate that
// names no protocol: they would match any ICS protocol, or stop a pure
// L3/L4 rule from matching at all. ics: {} stays valid.
//
// mode alone is not rejected: the policy templates set it on their L3/L4
// rules (pkg/cp/templates/templates.go:87-88) and the engine reads it as
// the rule's enforcement mode.
func validateICSWithoutProtocol(p ICSPredicate, ruleID string) error {
	field := ""
	switch {
	case len(p.FunctionCode) > 0:
		field = "functionCode"
	case p.UnitID != nil:
		field = "unitId"
	case len(p.Addresses) > 0:
		field = "addresses"
	case len(p.ObjectClasses) > 0:
		field = "objectClasses"
	case p.ReadOnly:
		field = "readOnly"
	case p.WriteOnly:
		field = "writeOnly"
	case p.Direction != "":
		field = "direction"
	default:
		field = iec104FieldSet(p)
	}
	if field != "" {
		return fmt.Errorf("rule %s ics %s needs an ics protocol", ruleID, field)
	}
	return nil
}

// iec104FieldSet names the first IEC104 list field that is set (non-nil),
// or "".
func iec104FieldSet(p ICSPredicate) string {
	switch {
	case p.TypeIDs != nil:
		return "typeIds"
	case p.Classes != nil:
		return "classes"
	case p.CA != nil:
		return "ca"
	case p.IOA != nil:
		return "ioa"
	default:
		return ""
	}
}
