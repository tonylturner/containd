// SPDX-License-Identifier: Apache-2.0
package dnp3

import "encoding/binary"

// ObjectValue retains exact numeric bits and wire flags, status and time.
// Group/variation on the enclosing header defines signedness and IEEE754 width.
// No JSON digest or event attribute needs to be reparsed to compare echoes.
type ObjectValue struct {
	Bits          uint64
	Flags, Status uint8
	Time          uint64 // absolute 48-bit or relative 16-bit milliseconds
}

func objectValue(key uint16, b []byte) *ObjectValue {
	v := &ObjectValue{}
	value := b
	switch key {
	case 0x0102, 0x0201, 0x0202, 0x0203, 0x0a02:
		v.Flags, v.Bits = b[0], uint64(b[0]>>7)
		if key == 0x0202 {
			v.Time = uintLE(b[1:7])
		}
		if key == 0x0203 {
			v.Time = uintLE(b[1:3])
		}
		return v
	case 0x1401, 0x1402, 0x1601, 0x1602, 0x1e01, 0x1e02, 0x1e05, 0x1e06, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2007, 0x2801, 0x2802, 0x2803:
		v.Flags = b[0]
		value = b[1:]
	case 0x2901, 0x2902, 0x2903, 0x2904:
		v.Status = b[len(b)-1]
		value = b[:len(b)-1]
	case 0x3201:
		v.Time = uintLE(b)
		return v
	case 0x0c01:
		return nil // Every field is already retained as CROB.
	}
	switch key {
	case 0x2003, 0x2004, 0x2007:
		v.Time = uintLE(value[len(value)-6:])
		value = value[:len(value)-6]
	}
	v.Bits = uintLE(value)
	return v
}
func uintLE(b []byte) uint64 {
	if len(b) == 8 {
		return binary.LittleEndian.Uint64(b)
	}
	var v uint64
	for i, x := range b {
		v |= uint64(x) << (8 * i)
	}
	return v
}
