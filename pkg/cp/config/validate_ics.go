// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import "fmt"

func validateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Protocol == "" {
		return nil
	}
	if p.Mode != "" && p.Mode != "learn" && p.Mode != "enforce" {
		return fmt.Errorf("rule %s ics mode invalid %q", ruleID, p.Mode)
	}
	if p.ReadOnly && p.WriteOnly {
		return fmt.Errorf("rule %s ics predicate cannot be both readOnly and writeOnly", ruleID)
	}
	if p.Direction != "" && p.Direction != "request" && p.Direction != "response" {
		return fmt.Errorf("rule %s ics direction invalid %q", ruleID, p.Direction)
	}
	if len(p.FunctionCode) > 0 && p.Protocol != "modbus" && p.Protocol != "dnp3" && p.Protocol != "cip" && p.Protocol != "s7comm" && p.Protocol != "bacnet" && p.Protocol != "opcua" && p.Protocol != "mms" {
		return fmt.Errorf("rule %s ics functionCode only supported for modbus, dnp3, cip, s7comm, bacnet, opcua, and mms currently", ruleID)
	}
	if len(p.ObjectClasses) > 0 && p.Protocol != "cip" {
		return fmt.Errorf("rule %s ics objectClasses only supported for cip protocol", ruleID)
	}
	return nil
}
