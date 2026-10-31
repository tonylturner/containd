// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

// canonicalPolicyJSON collapses empty collections and canonicalizes predicate
// sets, not decision lists. Firewall, NAT forwards and steering entries retain
// configured order. Unknown future fields retain order too.
func canonicalPolicyJSON(input any) ([]byte, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalPolicyValue(value, ""))
}

func canonicalPolicyValue(value any, field string) any {
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 {
			return nil
		}
		for key, child := range v {
			kind := key
			if field == "ZoneIfaces" || field == "LocalIPv4ByDevice" {
				kind = "Devices"
			}
			v[key] = canonicalPolicyValue(child, kind)
		}
		return v
	case []any:
		if len(v) == 0 {
			return nil
		}
		for i, child := range v {
			v[i] = canonicalPolicyValue(child, "")
		}
		if policySetField(field) {
			type item struct {
				key   string
				value any
			}
			items := make([]item, len(v))
			for i, child := range v {
				// Values came from JSON and contain no unsupported types.
				key, _ := json.Marshal(child)
				items[i] = item{string(key), child}
			}
			slices.SortFunc(items, func(a, b item) int { return cmp.Compare(a.key, b.key) })
			items = slices.CompactFunc(items, func(a, b item) bool { return a.key == b.key })
			v = v[:len(items)]
			for i := range items {
				v[i] = items[i].value
			}
		}
		return v
	default:
		return value
	}
}

func policySetField(field string) bool {
	// Predicate JSON mixes exported names and explicit lower-camel tags.
	switch strings.ToLower(field) {
	case "sourcezones", "destzones", "sources", "destinations", "identities", "viaforwards", "protocols",
		"functioncode", "addresses", "objectclasses", "typeids", "classes", "ca", "ioa", "cot",
		"originators", "commandstates", "commandqualifiers", "masters", "outstations", "groups",
		"variations", "instances", "attributes", "tags", "daysofweek", "ingressdevices", "allowedsources",
		"icsdevices", "icscidrs", "destdevices", "sourcedevices", "ports", "devices", "ifaces", "decoders":
		return true
	default:
		return false
	}
}
