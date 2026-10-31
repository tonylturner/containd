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

// ValidateICSPredicate validates one rule's ICS selectors, including predicates
// constructed in Go. Preview can use it without a whole candidate configuration.
// Whole-policy activation and enforce-ALLOW descriptor checks still need Validate.
func ValidateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Mode == "learn" {
		return fmt.Errorf("rule %s ics.mode learn is no longer supported; use monitor", ruleID)
	}
	if p.Mode != "" && p.Mode != "monitor" && p.Mode != "enforce" {
		return fmt.Errorf("rule %s ics mode invalid %q", ruleID, p.Mode)
	}
	if p.Protocol == "" {
		if p.Mode != "" {
			return fmt.Errorf("rule %s ics.mode requires ics.protocol", ruleID)
		}
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
	if err := validateProtocolSelectors(p, ruleID); err != nil {
		return err
	}
	if p.UnitID != nil && (p.Protocol == "dnp3" || p.Protocol == "cip") {
		return fmt.Errorf("rule %s ics unitId is not supported for protocol %s; remove this filter", ruleID, p.Protocol)
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

// validateICSAddresses permits Modbus addresses and grouped DNP3 point indexes, and refuses
// entries the evaluator cannot parse or that exceed the protocol's limit.
func validateICSAddresses(p ICSPredicate, ruleID string) error {
	if len(p.Addresses) > 0 {
		if p.Protocol == "cip" {
			return fmt.Errorf("rule %s ics addresses is not supported for protocol cip; use target selectors", ruleID)
		}
		if p.Protocol == "dnp3" && len(p.Groups) == 0 {
			return fmt.Errorf("rule %s ics addresses requires non-empty groups for protocol dnp3", ruleID)
		}
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
		field = protocolSelectorField(p)
	}
	if field != "" {
		return fmt.Errorf("rule %s ics %s needs an ics protocol", ruleID, field)
	}
	return nil
}

// iec104FieldSet names the first IEC104 field that is set, or "".
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
	case p.COT != nil:
		return "cot"
	case p.Originators != nil:
		return "originators"
	case p.Negative != nil:
		return "negative"
	case p.Test != nil:
		return "test"
	case p.CommandStates != nil:
		return "commandStates"
	case p.CommandQualifiers != nil:
		return "commandQualifiers"
	case p.SelectExecute != "":
		return "selectExecute"
	default:
		return ""
	}
}
