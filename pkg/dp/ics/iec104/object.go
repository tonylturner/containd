// SPDX-License-Identifier: Apache-2.0
package iec104

import (
	"encoding/binary"
	"math"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// decodeTypedElement is shared by the event and unit readers. Validation never
// uses event attributes as authority; both projections start from this tree.
func decodeTypedElement(d descriptor, b []byte, o *Object) *conformanceError {
	n := elementSize[d.elem]
	switch d.elem {
	case elemSIQ:
		o.ValueBits, o.Quality = uint32(b[0]&1), b[0]&0xf0
	case elemDIQ:
		o.ValueBits, o.Quality = uint32(b[0]&3), b[0]&0xf0
	case elemVTI:
		o.ValueBits, o.Transient, o.Quality = uint32(b[0]&127), b[0]&128 != 0, b[1]
	case elemBSIQDS, elemFloatQDS:
		o.ValueBits, o.Quality = binary.LittleEndian.Uint32(b), b[4]
	case elemNVAQDS, elemSVAQDS:
		o.ValueBits, o.Quality = uint32(binary.LittleEndian.Uint16(b)), b[2]
	case elemNVA:
		o.ValueBits = uint32(binary.LittleEndian.Uint16(b))
	case elemBCR:
		o.ValueBits, o.Qualifier, o.Quality = binary.LittleEndian.Uint32(b), b[4]&31, b[4]&0xe0
	case elemSCO, elemDCO, elemRCO:
		state := b[0] & 3
		if d.elem == elemSCO {
			if b[0]&2 != 0 {
				return elementError("SCO reserved bit 1 set")
			}
		} else if state == 0 || state == 3 {
			return elementError("command state %d is not a command (only 1 and 2)", state)
		}
		o.ValueBits, o.Qualifier, o.Select = uint32(state), (b[0]>>2)&31, b[0]&128 != 0
	case elemNVAQOS, elemSVAQOS:
		o.ValueBits, o.Qualifier, o.Select = uint32(binary.LittleEndian.Uint16(b)), b[2]&127, b[2]&128 != 0
	case elemFloatQOS:
		o.ValueBits, o.Qualifier, o.Select = binary.LittleEndian.Uint32(b), b[4]&127, b[4]&128 != 0
	case elemBSI:
		o.ValueBits = binary.LittleEndian.Uint32(b)
	case elemCOI, elemQOI, elemQCC, elemQRP:
		o.Qualifier = b[0]
	case elemTSC:
		o.TestSequence = binary.LittleEndian.Uint16(b)
	case elemNone:
	}
	if d.timed {
		copy(o.Time[:], b[n:])
		return validateCP56(o.Time[:])
	}
	return nil
}

// attrs is an event projection only. The typed tree retains float bits, the
// otherwise unexposed test sequence and exact time flags for pairing.
func (o Object) attrs(d descriptor) map[string]any {
	a := map[string]any{eventfields.KeyIOA: o.IOA}
	switch d.elem {
	case elemSIQ, elemDIQ, elemSCO, elemDCO, elemRCO:
		a[eventfields.KeyValue] = uint8(o.ValueBits)
	case elemVTI:
		v := int16(o.ValueBits)
		if v&64 != 0 {
			v -= 128
		}
		a[eventfields.KeyValue] = int8(v)
		a[keyTransient] = o.Transient
	case elemBSIQDS, elemBSI:
		a[eventfields.KeyValue] = o.ValueBits
	case elemNVAQDS, elemSVAQDS, elemNVA, elemNVAQOS, elemSVAQOS:
		a[eventfields.KeyValue] = int16(o.ValueBits)
	case elemBCR:
		a[eventfields.KeyValue] = int32(o.ValueBits)
	case elemFloatQDS, elemFloatQOS:
		f := math.Float32frombits(o.ValueBits)
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			a[eventfields.KeyValueInvalid] = true
		} else {
			a[eventfields.KeyValue] = f
		}
	}
	switch d.elem {
	case elemSIQ, elemDIQ, elemVTI, elemBSIQDS, elemNVAQDS, elemSVAQDS, elemBCR, elemFloatQDS:
		a[eventfields.KeyQuality] = o.Quality
	}
	switch d.elem {
	case elemBCR, elemSCO, elemDCO, elemRCO, elemNVAQOS, elemSVAQOS, elemFloatQOS, elemCOI, elemQOI, elemQCC, elemQRP:
		a[eventfields.KeyQualifier] = o.Qualifier
	}
	switch d.elem {
	case elemSCO, elemDCO, elemRCO, elemNVAQOS, elemSVAQOS, elemFloatQOS:
		a[eventfields.KeySelect] = o.Select
	}
	if d.timed {
		cp56Attrs(o.Time[:], a)
	} // Already validated by the reader.
	return a
}
