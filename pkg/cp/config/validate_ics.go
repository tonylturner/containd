// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ICSProtocolIEC104 is the ICS predicate protocol of IEC 60870-5-104 rules.
const ICSProtocolIEC104 = "iec104"

// This user-facing diagnostic is also shown by the rule editors.
const unsupportedICSAddressesMessage = "Address filters are not supported for DNP3 or CIP. Remove this filter before saving; protocol-specific station, point and CIP path selectors are not available yet."

func validateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Mode != "" && p.Mode != "learn" && p.Mode != "enforce" {
		return fmt.Errorf("rule %s ics mode invalid %q", ruleID, p.Mode)
	}
	if p.Protocol == "" {
		return validateICSWithoutProtocol(p, ruleID)
	}
	if err := ics.ValidateRule(ruleID, p.Protocol); err != nil {
		return err
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
	return validateICSAddresses(p, ruleID)
}

// validateICSAddresses permits generic addresses only for Modbus, and refuses
// entries the evaluator cannot parse or that exceed the protocol's limit.
func validateICSAddresses(p ICSPredicate, ruleID string) error {
	if len(p.Addresses) > 0 && (p.Protocol == "dnp3" || p.Protocol == "cip") {
		return fmt.Errorf("rule %s: %s", ruleID, unsupportedICSAddressesMessage)
	}
	limit := rules.ICSAddressMax(p.Protocol)
	for _, spec := range p.Addresses {
		_, high, err := rules.ParseICSAddressSpec(spec)
		if err == nil && high > limit {
			err = fmt.Errorf("%s addresses end at %d", p.Protocol, limit)
		}
		if err != nil {
			return fmt.Errorf("rule %s ics addresses entry %q: %v; use one value or a low-high range, "+
				"each decimal or 0x hex, low <= high", ruleID, spec, err)
		}
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
