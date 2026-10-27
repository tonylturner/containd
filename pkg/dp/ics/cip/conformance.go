// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func addFinding(attrs map[string]any, code string) {
	codes, _ := eventfields.Strings(attrs, eventfields.KeyConformance)
	codes = append(slices.Clone(codes), code)
	slices.Sort(codes)
	attrs[eventfields.KeyConformance] = slices.Compact(codes)
}

// Keep only complete, recognized logical segments. In particular, missing
// instance and attribute segments are not wire evidence of zero identifiers.
func addPathFields(path []byte, attrs map[string]any) {
	if len(path) == 0 {
		return
	}
	attrs["cip_path"] = hex.EncodeToString(path)
	for pos := 0; pos < len(path); {
		seg := path[pos]
		key := ""
		switch seg {
		case 0x20, 0x21:
			key = "object_class"
		case 0x24, 0x25:
			key = "instance_id"
		case 0x28, 0x29:
			key = "member_id"
		case 0x2c, 0x2d, 0x30, 0x31:
			key = "attribute_id"
		case 0x91: // ANSI extended symbolic segment, padded to a word
			if pos+2 > len(path) {
				addFinding(attrs, "cip.epath_truncated")
				return
			}
			size := 2 + (int(path[pos+1])+1)/2*2
			if size > len(path)-pos {
				addFinding(attrs, "cip.epath_truncated")
				return
			}
			pos += size
			continue
		default:
			// No guessed offsets through unsupported segment formats.
			return
		}
		size := 2
		if seg&1 != 0 {
			size = 4
		}
		if size > len(path)-pos {
			addFinding(attrs, "cip.epath_truncated")
			return
		}
		value := uint16(path[pos+1])
		if size == 4 {
			value = binary.LittleEndian.Uint16(path[pos+2 : pos+4])
		}
		attrs[key] = value
		if key == "object_class" {
			attrs["object_class_name"] = ObjectClassName(value)
		}
		pos += size
	}
	class, hasClass := attrs["object_class"].(uint16)
	instance, hasInstance := attrs["instance_id"].(uint16)
	attribute, hasAttribute := attrs["attribute_id"].(uint16)
	if hasClass && hasInstance && hasAttribute {
		attrs["address"] = FormatAddress(EPathResult{ClassID: class, InstanceID: instance, AttributeID: attribute})
	}
}
