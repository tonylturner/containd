// SPDX-License-Identifier: Apache-2.0
package dnp3

import "encoding/binary"

// Point is evidence, not a generic policy address. Index is absent for count-
// only, all-object and virtual-address qualifiers: absence never means point zero.
type Point struct {
	Index *uint32 `json:"index,omitempty"`
	CROB  *CROB   `json:"crob,omitempty"`
}

// CROB preserves every encoded value of group 12 variation 1.
type CROB struct {
	Control       uint8  `json:"control"`
	Operation     uint8  `json:"operation"`
	OperationName string `json:"operation_name"`
	TripClose     uint8  `json:"trip_close"`
	Queue         bool   `json:"queue"`
	Clear         bool   `json:"clear"`
	Count         uint8  `json:"count"`
	OnTime        uint32 `json:"on_time_ms"`
	OffTime       uint32 `json:"off_time_ms"`
	Status        uint8  `json:"status"`
}

func crobValue(b []byte) *CROB {
	op := b[0] & 15
	name := "reserved"
	if op < 5 {
		name = []string{"nul", "pulse_on", "pulse_off", "latch_on", "latch_off"}[op]
	}
	return &CROB{b[0], op, name, b[0] >> 6, b[0]&0x10 != 0, b[0]&0x20 != 0, b[1], binary.LittleEndian.Uint32(b[2:6]), binary.LittleEndian.Uint32(b[6:10]), b[10]}
}

// attachPoints walks only a header whose full object layout was validated.
// Header-only ranges stay compact even when they name billions of points.
func attachPoints(oh *ObjectHeader, b []byte, fc byte) {
	rc := oh.Qualifier & 15
	if rc == rangeNone || oh.Count == 0 {
		return
	}
	prefix := int(oh.Qualifier>>4) & 7
	if prefix >= 4 {
		return
	} // size-prefixed opaque values do not encode an index
	if headerOnlyFunction(fc) && prefix == 0 {
		return
	}
	width := 0
	if prefix != 0 {
		width = 1 << (prefix - 1)
	}
	key := uint16(oh.Group)<<8 | uint16(oh.Variation)
	size := fixedObjectSize[key]
	if headerOnlyFunction(fc) {
		size = 0
	}
	// Count-only zero-sized headers cannot cause unbounded allocations. Every
	// point record here consumes at least an index/value bit in the wire data.
	if width+size == 0 && packedObjectBits[key] == 0 {
		return
	}
	pos := 0
	for i := uint64(0); i < oh.Count; i++ {
		p := Point{}
		if width > 0 {
			v := readUint(b[pos : pos+width])
			p.Index = &v
			pos += width
		} else if oh.Start != nil && rc <= rangeStartStop4 {
			v := *oh.Start + uint32(i)
			p.Index = &v
		}
		if key == 0x0c01 && !headerOnlyFunction(fc) {
			p.CROB = crobValue(b[pos : pos+11])
		}
		oh.Points = append(oh.Points, p)
		pos += size
	}
}

// Retain complete readable points before a truncated value, never inventing a
// partial CROB or scanning the unknown tail for another header.
func attachPartialPoints(oh *ObjectHeader, b []byte, fc byte) {
	prefix := int(oh.Qualifier>>4) & 7
	if prefix >= 4 {
		return
	}
	width := 0
	if prefix > 0 {
		width = 1 << (prefix - 1)
	}
	size, known := fixedObjectSize[uint16(oh.Group)<<8|uint16(oh.Variation)]
	if headerOnlyFunction(fc) {
		size = 0
		known = true
	}
	if !known || width+size == 0 {
		return
	}
	count := min(oh.Count, uint64(len(b)/(width+size)))
	original := oh.Count
	oh.Count = count
	attachPoints(oh, b[:int(count)*(width+size)], fc)
	oh.Count = original
	oh.Covered += int(count) * (width + size)
}

// validEncoding follows opendnp3's control/status enums: 0..18 are assigned
// statuses, 126 is deprecated NON_PARTICIPATING; 127 is its undefined sentinel.
func (c *CROB) validEncoding() bool {
	return c.Operation <= 4 && c.TripClose < 3 && (c.Status <= 18 || c.Status == 126)
}
