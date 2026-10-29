// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/hex"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func addFinding(attrs map[string]any, code string) {
	addCode(attrs, eventfields.KeyConformance, code)
}

func addUndecoded(attrs map[string]any, code string) {
	addCode(attrs, eventfields.KeyUndecoded, code)
}

func addCode(attrs map[string]any, key, code string) {
	codes, _ := eventfields.Strings(attrs, key)
	codes = append(slices.Clone(codes), code)
	slices.Sort(codes)
	attrs[key] = slices.Compact(codes)
}

// Keep only complete, recognized logical segments. In particular, missing
// instance and attribute segments are not wire evidence of zero identifiers.
func addPathFields(path []byte, attrs map[string]any) {
	if len(path) == 0 {
		return
	}
	attrs["cip_path"] = hex.EncodeToString(path)
	p := decodePath(path)
	if p.finding != "" {
		addFinding(attrs, p.finding)
	}
	if p.undecoded != "" {
		addUndecoded(attrs, p.undecoded)
	}
	for _, seg := range p.segments {
		key := ""
		switch seg.code {
		case 0x20, 0x21:
			key = "object_class"
		case 0x24, 0x25:
			key = "instance_id"
		case 0x28, 0x29:
			key = "member_id"
		case 0x2c, 0x2d:
			key = "connection_point"
		case 0x30, 0x31:
			key = "attribute_id"
		default:
			continue
		}
		attrs[key] = seg.value
		if key == "object_class" {
			attrs["object_class_name"] = ObjectClassName(seg.value)
		}
	}
	if p.finding != "" || p.undecoded != "" {
		return
	}
	class, hasClass := attrs["object_class"].(uint16)
	instance, hasInstance := attrs["instance_id"].(uint16)
	attribute, hasAttribute := attrs["attribute_id"].(uint16)
	if hasClass && hasInstance && hasAttribute {
		attrs["address"] = FormatAddress(EPathResult{ClassID: class, InstanceID: instance, AttributeID: attribute})
	}
}
