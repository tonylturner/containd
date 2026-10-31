// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"strings"
)

func dnp3FieldSet(p ICSPredicate) string {
	switch {
	case p.Masters != nil:
		return "masters"
	case p.Outstations != nil:
		return "outstations"
	case p.Groups != nil:
		return "groups"
	case p.Variations != nil:
		return "variations"
	}
	return ""
}

func cipFieldSet(p ICSPredicate) string {
	switch {
	case p.Instances != nil:
		return "instances"
	case p.Attributes != nil:
		return "attributes"
	case p.Tags != nil:
		return "tags"
	}
	return ""
}

func protocolSelectorField(p ICSPredicate) string {
	if field := iec104FieldSet(p); field != "" {
		return field
	}
	if field := dnp3FieldSet(p); field != "" {
		return field
	}
	return cipFieldSet(p)
}

func validateProtocolSelectors(p ICSPredicate, ruleID string) error {
	for _, scope := range []struct{ protocol, field string }{
		{"dnp3", dnp3FieldSet(p)}, {"cip", cipFieldSet(p)},
	} {
		if scope.field != "" && p.Protocol != scope.protocol {
			return fmt.Errorf("rule %s ics %s is only supported for protocol %s", ruleID, scope.field, scope.protocol)
		}
	}
	switch p.Protocol {
	case "dnp3":
		for _, list := range []struct {
			field  string
			values []uint16
		}{{"masters", p.Masters}, {"outstations", p.Outstations}} {
			if err := validateSelectorList(list.field, list.values, 0, 65519, ruleID); err != nil {
				return err
			}
		}
		for _, list := range []struct {
			field  string
			values []int
		}{{"groups", p.Groups}, {"variations", p.Variations}} {
			if err := validateSelectorList(list.field, list.values, 0, 255, ruleID); err != nil {
				return err
			}
		}
	case "cip":
		for _, list := range []struct {
			field  string
			values []uint16
		}{{"instances", p.Instances}, {"attributes", p.Attributes}} {
			if err := validateSelectorList(list.field, list.values, 0, 65535, ruleID); err != nil {
				return err
			}
		}
		return validateCIPTags(p, ruleID)
	}
	return nil
}

func validateSelectorList[T ~int | ~uint16](field string, values []T, low, high int, ruleID string) error {
	if values != nil && len(values) == 0 {
		return fmt.Errorf("rule %s ics %s must not be empty; omit it to match any value", ruleID, field)
	}
	for _, value := range values {
		if int(value) < low || int(value) > high {
			return fmt.Errorf("rule %s ics %s value %d out of range %d..%d", ruleID, field, value, low, high)
		}
	}
	return nil
}

var cipTagName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,39}$`)

func validateCIPTags(p ICSPredicate, ruleID string) error {
	if p.Tags == nil {
		return nil
	}
	if len(p.Tags) == 0 {
		return fmt.Errorf("rule %s ics tags must not be empty; omit it to match any value", ruleID)
	}
	if len(p.ObjectClasses) > 0 || len(p.Instances) > 0 || len(p.Attributes) > 0 {
		return fmt.Errorf("rule %s ics tags cannot combine with objectClasses, instances or attributes", ruleID)
	}
	for _, tag := range p.Tags {
		for i, name := range strings.Split(tag, ".") {
			if i == 0 {
				name = strings.TrimPrefix(name, "Program:")
			}
			if !cipTagName.MatchString(name) {
				return fmt.Errorf("rule %s ics tags path %q has invalid name; use dot-separated names of 1..40 letters, digits or underscores, starting with a letter or underscore", ruleID, tag)
			}
		}
	}
	return nil
}

func validateIEC104Selectors(p ICSPredicate, ruleID string) error {
	if err := validateSelectorList("cot", p.COT, 1, 63, ruleID); err != nil {
		return err
	}
	if err := validateSelectorList("originators", p.Originators, 0, 255, ruleID); err != nil {
		return err
	}
	if err := validateIEC104Commands(p, ruleID); err != nil {
		return err
	}
	if p.SelectExecute == "" {
		return nil
	}
	if p.SelectExecute != "select" && p.SelectExecute != "execute" {
		return fmt.Errorf("rule %s ics selectExecute must be select or execute", ruleID)
	}
	for _, id := range p.TypeIDs {
		if !(id >= 45 && id <= 50 || id >= 58 && id <= 63) {
			return fmt.Errorf("rule %s ics selectExecute is not supported for typeIds value %d; use 45..50 or 58..63", ruleID, id)
		}
	}
	return nil
}

func validateIEC104Commands(p ICSPredicate, ruleID string) error {
	if p.CommandStates == nil && p.CommandQualifiers == nil {
		return nil
	}
	if len(p.TypeIDs) == 0 {
		return fmt.Errorf("rule %s ics commandStates/commandQualifiers requires typeIds", ruleID)
	}
	low := -1
	for _, id := range p.TypeIDs {
		group := 0
		switch id {
		case 45, 58:
			group = 0
		case 46, 47, 59, 60:
			group = 1
		default:
			return fmt.Errorf("rule %s ics commandStates/commandQualifiers is not supported for typeIds value %d", ruleID, id)
		}
		if p.CommandStates != nil && low != -1 && low != group {
			return fmt.Errorf("rule %s ics commandStates requires typeIds in one state domain (45/58 or 46/47/59/60)", ruleID)
		}
		low = group
	}
	if err := validateSelectorList("commandStates", p.CommandStates, low, low+1, ruleID); err != nil {
		return err
	}
	return validateSelectorList("commandQualifiers", p.CommandQualifiers, 0, 31, ruleID)
}
