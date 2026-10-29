// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"strings"
)

func matchICSStations(p ICSPredicate, obj *ICSContext) bool {
	return matchOptional(p.Masters, obj.Master) && matchOptional(p.Outstations, obj.Outstation)
}

func matchOptional[T comparable](list []T, value *T) bool {
	return len(list) == 0 || (value != nil && slices.Contains(list, *value))
}

func matchByteList(list []int, value *uint8) bool {
	return len(list) == 0 || (value != nil && slices.Contains(list, int(*value)))
}

func denying(action Action) bool {
	return action == ActionDeny || action == ActionReset
}

// An unknown object overrides only the object-selector conjunction. Message
// facts (stations, function, direction, access and L3/L4) still have to match.
func matchICSObjects(ce *compiledEntry, ctx EvalContext) bool {
	p, obj := ce.ICS, ctx.ICS
	hasSelectors := false
	switch p.Protocol {
	case "dnp3":
		hasSelectors = len(p.Groups) > 0 || len(p.Variations) > 0 || len(p.Addresses) > 0
	case "cip":
		hasSelectors = len(p.ObjectClasses) > 0 || len(p.Instances) > 0 ||
			len(p.Attributes) > 0 || len(p.Tags) > 0
	}
	if obj.ObjectUnknown && hasSelectors {
		return denying(ce.Action)
	}
	return matchICSAddresses(ce, ctx) &&
		matchICSObjectClass(p, ctx) &&
		matchByteList(p.Groups, obj.Group) &&
		matchICSVariation(p.Variations, obj.Variation, ce.Action) &&
		matchUnknownOptional(p.Instances, obj.Instance, obj.InstanceUnknown, ce.Action) &&
		matchUnknownOptional(p.Attributes, obj.Attribute, obj.AttributeUnknown, ce.Action) &&
		matchICSTags(ce.tagPaths, obj.Symbol, ce.Action)
}

func matchICSVariation(list []int, value *uint8, action Action) bool {
	if len(list) > 0 && value != nil && *value == 0 && denying(action) {
		return true
	}
	return matchByteList(list, value)
}

func matchUnknownOptional(list []uint16, value *uint16, unknown bool, action Action) bool {
	if len(list) > 0 && unknown {
		return denying(action)
	}
	return matchOptional(list, value)
}

func compileTagPaths(tags []string) [][]string {
	paths := make([][]string, len(tags))
	for i, tag := range tags {
		paths[i] = strings.Split(tag, ".")
	}
	return paths
}

func matchICSTags(tags [][]string, symbol []string, action Action) bool {
	if len(tags) == 0 {
		return true
	}
	if len(symbol) == 0 {
		return false
	}
	for _, selector := range tags {
		if symbolPrefix(selector, symbol) || (denying(action) && symbolPrefix(symbol, selector)) {
			return true
		}
	}
	return false
}

func symbolPrefix(prefix, target []string) bool {
	if len(prefix) > len(target) {
		return false
	}
	for i, segment := range prefix {
		if !strings.EqualFold(segment, target[i]) {
			return false
		}
	}
	return true
}
