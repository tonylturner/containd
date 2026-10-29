// SPDX-License-Identifier: Apache-2.0
package cip

import "encoding/binary"

type pathSegment struct {
	code   byte
	value  uint16
	symbol string
}

type decodedPath struct {
	segments     []pathSegment
	finding      string
	undecoded    string
	validPadding bool
}

// decodePath is shared by telemetry extraction and access classification.
// Only the currently supported 8/16-bit logical and ANSI symbolic formats
// are walked. Partial fields remain useful telemetry, never a complete target.
func decodePath(path []byte) decodedPath {
	r := decodedPath{validPadding: true}
	for pos := 0; pos < len(path); {
		code := path[pos]
		size := 2
		switch code {
		case 0x20, 0x24, 0x28, 0x2c, 0x30:
		case 0x21, 0x25, 0x29, 0x2d, 0x31:
			size = 4
		case 0x91:
			if pos+2 > len(path) {
				r.finding = "cip.epath_truncated"
				return r
			}
			size = 2 + (int(path[pos+1])+1)/2*2
		default:
			r.undecoded = "cip.epath_unsupported"
			return r
		}
		if size > len(path)-pos {
			r.finding = "cip.epath_truncated"
			return r
		}
		value := uint16(path[pos+1])
		if code == 0x91 {
			if value == 0 || value%2 != 0 && path[pos+size-1] != 0 {
				r.validPadding = false
			}
		} else if size == 4 {
			r.validPadding = r.validPadding && path[pos+1] == 0
			value = binary.LittleEndian.Uint16(path[pos+2 : pos+4])
		}
		s := pathSegment{code: code, value: value}
		if code == 0x91 {
			s.symbol = string(path[pos+2 : pos+2+int(value)])
		}
		r.segments = append(r.segments, s)
		pos += size
	}
	return r
}

type serviceTarget struct {
	class           uint16
	instance        uint16
	hasInstance     bool
	symbolic        bool
	symbol          []string
	members         bool
	attribute       bool
	connectionPoint bool
	valid           bool
}

func decodeTarget(path []byte) serviceTarget {
	p := decodePath(path)
	if len(p.segments) == 0 || p.finding != "" || p.undecoded != "" || !p.validPadding {
		return serviceTarget{}
	}
	t := serviceTarget{valid: true, symbolic: p.segments[0].code == 0x91}
	if t.symbolic {
		for _, s := range p.segments {
			switch s.code {
			case 0x91:
				t.symbol = append(t.symbol, s.symbol)
			case 0x28, 0x29:
				// Element indexes do not change the symbol subtree.
			default:
				return serviceTarget{}
			}
		}
		return t
	}
	if p.segments[0].code != 0x20 && p.segments[0].code != 0x21 {
		return serviceTarget{}
	}
	t.class = p.segments[0].value
	// A class may be followed by one instance and at most one attribute,
	// member or connection point. Mixed or repeated targets are ambiguous.
	for _, s := range p.segments[1:] {
		terminal := t.attribute || t.members || t.connectionPoint
		switch s.code {
		case 0x24, 0x25:
			if t.hasInstance || terminal {
				return serviceTarget{}
			}
			t.instance, t.hasInstance = s.value, true
		case 0x30, 0x31:
			if !t.hasInstance || terminal {
				return serviceTarget{}
			}
			t.attribute = true
		case 0x28, 0x29, 0x2c, 0x2d:
			if !t.hasInstance || terminal {
				return serviceTarget{}
			}
			t.members = s.code == 0x28 || s.code == 0x29
			t.connectionPoint = !t.members
		default:
			return serviceTarget{}
		}
	}
	return t
}

func (t serviceTarget) instanceTarget() bool {
	return t.hasInstance && !t.attribute && !t.members && !t.connectionPoint
}
