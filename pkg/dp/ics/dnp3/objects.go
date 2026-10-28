// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/binary"
	"encoding/json"
)

// ObjectHeader represents a parsed DNP3 object group header.
type ObjectHeader struct {
	HasQualifier bool    `json:"has_qualifier"`
	HasVariation bool    `json:"has_variation"`
	HasCount     bool    `json:"has_count"`
	Start        *uint32 `json:"start,omitempty"`
	Stop         *uint32 `json:"stop,omitempty"`
	Addressing   string  `json:"addressing,omitempty"`
	Points       []Point `json:"points,omitempty"`
	Group        uint8   `json:"group"`
	Variation    uint8   `json:"variation"`
	Qualifier    uint8   `json:"qualifier"`
	Count        uint64  `json:"count"`
	Size         int     `json:"size"`
	Offset       int     `json:"offset"`
	Covered      int     `json:"covered"` // inspected header/value bytes from Offset
}

const maxDecodedPoints = 8192

// String renders owned evidence deterministically, including optional indices.
func (h ObjectHeader) String() string {
	b, err := json.Marshal(h)
	if err != nil {
		panic(err)
	} // This fixed, scalar-only schema is always encodable.
	return string(b)
}

// Qualifier fields (IEEE 1815-2012 application layer object header): bits
// 4-6 are the object prefix code, bits 0-3 the range specifier code.
const (
	rangeStartStop1 = 0x0
	rangeStartStop2 = 0x1
	rangeStartStop4 = 0x2
	rangeVirtual1   = 0x3
	rangeVirtual2   = 0x4
	rangeVirtual4   = 0x5
	rangeNone       = 0x6
	rangeCount1     = 0x7
	rangeCount2     = 0x8
	rangeCount4     = 0x9
	rangeFreeFormat = 0xB

	prefixNone = 0
	// Prefix codes 1-3 are 1/2/4-octet indexes, 4-6 are 1/2/4-octet object sizes.
	prefixSize1 = 4
)

// ParseObjectHeaders walks the object headers of one application fragment
// starting at offset. fc is the fragment's function code: it decides whether
// objects carry values. Every header is followed by its objects, so the walk
// skips each object's prefix and value before the next header. It stops at the
// first header whose objects it cannot size (an unknown group/variation, a
// reserved code, or truncated data) instead of reading values as headers; that
// header is still returned because its group is known.
func ParseObjectHeaders(data []byte, offset int, fc uint8) []ObjectHeader {
	headers, _ := parseObjectHeaders(data, offset, fc)
	return headers
}

// A stop distinguishes exhausted segment bytes from content we cannot size or
// accept. Only exhaustion can be normal at a non-final transport boundary.
type objectWalkStop uint8

const (
	walkComplete objectWalkStop = iota
	walkTruncated
	walkInvalid
	walkUnsupported
	walkLimited
)

func parseObjectHeaders(data []byte, offset int, fc uint8) ([]ObjectHeader, objectWalkStop) {
	if offset < 0 || offset > len(data) {
		return nil, walkInvalid
	}
	if offset == len(data) {
		return nil, walkComplete
	}
	headers := make([]ObjectHeader, 0, 4)
	pos := offset
	for pos < len(data) {
		oh := ObjectHeader{Group: data[pos], Offset: pos, Covered: min(3, len(data)-pos)}
		if len(data)-pos >= 2 {
			oh.Variation = data[pos+1]
			oh.HasVariation = true
		}
		if len(data)-pos < 3 {
			return append(headers, oh), walkTruncated
		}
		oh.Variation, oh.Qualifier, oh.HasQualifier = data[pos+1], data[pos+2], true
		rangeLen, count, valid, ok := readRange(data[pos+3:], oh.Qualifier&0x0F)
		oh.Size = 3 + rangeLen
		oh.HasCount = ok && valid
		if oh.HasCount {
			oh.Count = count
			rc := oh.Qualifier & 15
			switch {
			case rc <= rangeVirtual4:
				width := 1 << int(rc%3)
				start, stop := readUint(data[pos+3:pos+3+width]), readUint(data[pos+3+width:pos+3+2*width])
				oh.Start = &start
				oh.Stop = &stop
				oh.Addressing = "range"
				if rc >= rangeVirtual1 {
					oh.Addressing = "virtual"
				}
			case rc == rangeNone:
				oh.Addressing = "all"
			default:
				oh.Addressing = "count"
			}
		}
		headers = append(headers, oh)
		if oh.Qualifier&0x80 != 0 || (oh.Qualifier>>4)&7 == 7 {
			return headers, walkInvalid
		}
		if !ok {
			return headers, walkTruncated
		}
		if !valid {
			return headers, walkInvalid
		}
		pos += oh.Size
		headers[len(headers)-1].Covered = oh.Size
		if oh.Count > maxDecodedPoints && !(headerOnlyFunction(fc) && oh.Qualifier>>4 == 0) {
			return headers, walkLimited
		}
		n, stop := objectsLen(data[pos:], oh, fc)
		if stop != walkComplete {
			if stop == walkTruncated {
				attachPartialPoints(&headers[len(headers)-1], data[pos:], fc)
			}
			return headers, stop
		}
		attachPoints(&headers[len(headers)-1], data[pos:pos+n], fc)
		headers[len(headers)-1].Covered += n
		pos += n
	}
	return headers, walkComplete
}

// readRange decodes the range field for range code rc. It returns the field
// length, the object count, whether the range is meaningful, and false only
// when the field itself is truncated.
func readRange(b []byte, rc uint8) (n int, count uint64, valid, ok bool) {
	startStop := func(width int) (int, uint64, bool, bool) {
		if len(b) < 2*width {
			return 0, 0, false, false
		}
		start, stop := readUint(b[:width]), readUint(b[width:2*width])
		if stop < start {
			return 2 * width, 0, false, true
		}
		return 2 * width, uint64(stop) - uint64(start) + 1, true, true
	}
	countOf := func(width int) (int, uint64, bool, bool) {
		if len(b) < width {
			return 0, 0, false, false
		}
		return width, uint64(readUint(b[:width])), true, true
	}
	switch rc {
	case rangeStartStop1, rangeVirtual1:
		return startStop(1)
	case rangeStartStop2, rangeVirtual2:
		return startStop(2)
	case rangeStartStop4, rangeVirtual4:
		return startStop(4)
	case rangeNone:
		return 0, 0, true, true
	case rangeCount1, rangeFreeFormat:
		return countOf(1)
	case rangeCount2:
		return countOf(2)
	case rangeCount4:
		return countOf(4)
	default:
		return 0, 0, false, true
	}
}

func readUint(b []byte) uint32 {
	switch len(b) {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(b))
	default:
		return binary.LittleEndian.Uint32(b)
	}
}

// objectsLen returns the bytes that oh's objects occupy at the start of b.
func objectsLen(b []byte, oh ObjectHeader, fc uint8) (int, objectWalkStop) {
	if oh.Qualifier&0x0F == rangeNone || oh.Count == 0 {
		return 0, walkComplete
	}
	prefix := int(oh.Qualifier>>4) & 0x07
	switch {
	case prefix >= prefixSize1 && prefix <= prefixSize1+2:
		n, stop := sizePrefixedLen(b, oh.Count, 1<<(prefix-prefixSize1))
		if stop != walkComplete {
			return n, stop
		}
		return n, walkUnsupported // size is readable, but the value schema is not inspected
	case prefix > prefixSize1+2:
		return 0, walkInvalid // reserved prefix code
	}
	indexLen := 0
	if prefix != prefixNone {
		indexLen = 1 << (prefix - 1)
	}
	count := uint64(oh.Count)
	if headerOnlyFunction(fc) {
		return fit(b, count*uint64(indexLen))
	}
	key := uint16(oh.Group)<<8 | uint16(oh.Variation)
	if bits, ok := packedObjectBits[key]; ok {
		if prefix != prefixNone {
			return 0, walkInvalid
		}
		return fit(b, (count*uint64(bits)+7)/8)
	}
	size, ok := fixedObjectSize[key]
	if !ok {
		return 0, walkUnsupported
	}
	return fit(b, count*uint64(indexLen+size))
}

// sizePrefixedLen walks count objects that each start with a width-octet
// object size (free-format objects such as group 70).
func sizePrefixedLen(b []byte, count uint64, width int) (int, objectWalkStop) {
	pos := 0
	for i := uint64(0); i < count; i++ {
		if len(b)-pos < width {
			return 0, walkTruncated
		}
		size := uint64(readUint(b[pos : pos+width]))
		pos += width
		if size > uint64(len(b)-pos) {
			return 0, walkTruncated
		}
		pos += int(size)
	}
	return pos, walkComplete
}

func fit(b []byte, n uint64) (int, objectWalkStop) {
	if n > uint64(len(b)) {
		return 0, walkTruncated
	}
	return int(n), walkComplete
}

// headerOnlyFunction reports request function codes whose object headers
// name points without carrying values: read, the freeze family without time,
// enable/disable unsolicited and assign class.
func headerOnlyFunction(fc uint8) bool {
	switch fc {
	case FuncRead, FuncImmediateFreeze, FuncImmediateFreezeNR, FuncFreezeClear, FuncFreezeClearNR,
		FuncEnableUnsolicited, FuncDisableUnsolicited, FuncAssignClass:
		return true
	default:
		return false
	}
}

// fixedObjectSize is the value size in octets of common fixed-size object
// variations (IEEE 1815-2012 object library). Variations not listed stop the
// header walk.
var fixedObjectSize = map[uint16]int{
	0x0102: 1,  // g1v2 binary input with flags
	0x0201: 1,  // g2v1 binary input event
	0x0202: 7,  // g2v2 binary input event with absolute time
	0x0203: 3,  // g2v3 binary input event with relative time
	0x0A02: 1,  // g10v2 binary output status with flags
	0x0C01: 11, // g12v1 control relay output block
	0x1401: 5,  // g20v1 32-bit counter with flag
	0x1402: 3,  // g20v2 16-bit counter with flag
	0x1405: 4,  // g20v5 32-bit counter
	0x1406: 2,  // g20v6 16-bit counter
	0x1601: 5,  // g22v1 32-bit counter event
	0x1602: 3,  // g22v2 16-bit counter event
	0x1E01: 5,  // g30v1 32-bit analog input with flag
	0x1E02: 3,  // g30v2 16-bit analog input with flag
	0x1E03: 4,  // g30v3 32-bit analog input
	0x1E04: 2,  // g30v4 16-bit analog input
	0x1E05: 5,  // g30v5 single-precision analog input with flag
	0x1E06: 9,  // g30v6 double-precision analog input with flag
	0x2001: 5,  // g32v1 32-bit analog input event
	0x2002: 3,  // g32v2 16-bit analog input event
	0x2003: 11, // g32v3 32-bit analog input event with time
	0x2004: 9,  // g32v4 16-bit analog input event with time
	0x2005: 5,  // g32v5 single-precision analog input event
	0x2007: 11, // g32v7 single-precision analog input event with time
	0x2801: 5,  // g40v1 32-bit analog output status
	0x2802: 3,  // g40v2 16-bit analog output status
	0x2803: 5,  // g40v3 single-precision analog output status
	0x2901: 5,  // g41v1 32-bit analog output block
	0x2902: 3,  // g41v2 16-bit analog output block
	0x2903: 5,  // g41v3 single-precision analog output block
	0x2904: 9,  // g41v4 double-precision analog output block
	0x3201: 6,  // g50v1 absolute time
	0x3401: 2,  // g52v1 coarse time delay
	0x3402: 2,  // g52v2 fine time delay
}

// packedObjectBits lists bit-packed variations and their bits per object.
var packedObjectBits = map[uint16]int{
	0x0101: 1, // g1v1 binary input packed
	0x0301: 2, // g3v1 double-bit binary input packed
	0x0A01: 1, // g10v1 binary output packed
	0x5001: 1, // g80v1 internal indications
}
