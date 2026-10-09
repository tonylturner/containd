// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// ASDU layout with the IEC 104 field widths (IEC 60870-5-104 clause 9 fixes
// COT 2, CA 2 and IOA 3 octets): Type ID (1), VSQ (1), COT (2), CA (2), then
// the information objects (IEC 60870-5-101 7.2).
const (
	asduHeaderLen = 6
	ioaLen        = 3
	maxIOA        = 1<<24 - 1
)

// Causes of transmission a server must not originate (IEC 60870-5-101
// 7.2.3): activation and deactivation.
const (
	causeActivation   = 6
	causeDeactivation = 8
)

type asduHeader struct {
	typeID     uint8
	vsq        uint8
	sq         bool  // VSQ bit 7
	count      uint8 // VSQ bits 0-6
	cause      uint8 // COT bits 0-5
	negative   bool  // COT bit 6 (P/N)
	test       bool  // COT bit 7 (T)
	originator uint8 // COT octet 2
	ca         uint16
}

func decodeASDUHeader(b []byte) asduHeader {
	return asduHeader{
		typeID:     b[0],
		vsq:        b[1],
		sq:         b[1]&0x80 != 0,
		count:      b[1] & 0x7F,
		cause:      b[2] & 0x3F,
		negative:   b[2]&0x40 != 0,
		test:       b[2]&0x80 != 0,
		originator: b[3],
		ca:         binary.LittleEndian.Uint16(b[4:6]),
	}
}

// attrs returns the header attributes every event of the ASDU carries.
func (h asduHeader) attrs(a map[string]any) {
	a[eventfields.KeyTypeID] = h.typeID
	a[eventfields.KeyClass] = ClassOf(h.typeID)
	a[eventfields.KeyVSQ] = h.vsq
	a[eventfields.KeyObjectCount] = h.count
	a[eventfields.KeySQ] = h.sq
	a[eventfields.KeyCause] = h.cause
	a[eventfields.KeyCOTNegative] = h.negative
	a[eventfields.KeyCOTTest] = h.test
	a[eventfields.KeyOriginator] = h.originator
	a[eventfields.KeyCA] = h.ca
}

// profileError marks a B profile restriction: the standard allows it, B
// rejects it (spec §7.2, §7.3, W6).
func profileError(format string, args ...any) error {
	return fmt.Errorf("profile: "+format, args...)
}

// checkProfile applies the B SQ/count restrictions: SQ=1 only for types 3
// and 13; control and system types need SQ=0 and one object.
func checkProfile(h asduHeader, d descriptor) error {
	switch {
	case d.single && (h.sq || h.count != 1):
		return profileError("type %d needs SQ=0 and one object, got SQ=%d with %d", h.typeID, b2i(h.sq), h.count)
	case h.sq && !d.sqOK:
		return profileError("SQ=1 is not accepted for type %d", h.typeID)
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// checkRole applies the B role restrictions (spec §7.3): the client must not
// send monitor-direction types (1..44), and the server must not originate
// control or system commands (cause 6 activation or 8 deactivation).
func checkRole(h asduHeader, direction string) error {
	class := ClassOf(h.typeID)
	switch {
	case direction == DirectionRequest && monitorDirectionType(h.typeID):
		return profileError("client sent monitor-direction type %d", h.typeID)
	case direction == DirectionResponse && (class == ClassControl || class == ClassSystem) &&
		(h.cause == causeActivation || h.cause == causeDeactivation):
		return profileError("server sent %s type %d with cause %d", class, h.typeID, h.cause)
	}
	return nil
}

// decodeObjects decodes the information objects of an ASDU body (the bytes
// after the 6-octet header). SQ=0: every object has its own IOA. SQ=1: one
// base IOA, then consecutive IOAs. The body must hold exactly count objects.
func decodeObjects(h asduHeader, d descriptor, body []byte) ([]map[string]any, error) {
	size := d.objectSize()
	want := int(h.count) * (ioaLen + size)
	if h.sq {
		want = ioaLen + int(h.count)*size
	}
	if len(body) != want {
		return nil, fmt.Errorf("ASDU body is %d octets, want %d for %d objects of type %d", len(body), want, h.count, h.typeID)
	}
	objects := make([]map[string]any, 0, h.count)
	var base uint32
	pos := 0
	for i := 0; i < int(h.count); i++ {
		var ioa uint32
		switch {
		case !h.sq:
			ioa = readIOA(body[pos:])
			pos += ioaLen
		case i == 0:
			base = readIOA(body)
			if uint64(base)+uint64(h.count)-1 > maxIOA {
				return nil, fmt.Errorf("SQ=1 IOA range %d+%d overflows 24 bits", base, h.count)
			}
			pos += ioaLen
			ioa = base
		default:
			ioa = base + uint32(i)
		}
		obj := map[string]any{
			eventfields.KeyIOA:         ioa,
			eventfields.KeyObjectIndex: uint8(i),
		}
		if err := decodeElement(d, body[pos:pos+size], obj); err != nil {
			return nil, fmt.Errorf("object %d (IOA %d): %w", i, ioa, err)
		}
		pos += size
		objects = append(objects, obj)
	}
	return objects, nil
}

func readIOA(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// decodeElement decodes one information element (and its CP56Time2a for
// timed types) into obj. Element layouts are IEC 60870-5-101 7.2.6.
func decodeElement(d descriptor, b []byte, obj map[string]any) error {
	n := elementSize[d.elem]
	if err := decodeValue(d.elem, b[:n], obj); err != nil {
		return err
	}
	if d.timed {
		return decodeCP56(b[n:n+cp56Len], obj)
	}
	return nil
}

func decodeValue(kind elementKind, b []byte, obj map[string]any) error {
	switch kind {
	case elemDIQ: // DIQ: DPI bits 0-1, quality (BL, SB, NT, IV) bits 4-7
		obj[eventfields.KeyValue] = b[0] & 0x03
		obj[eventfields.KeyQuality] = b[0] & 0xF0
	case elemFloatQDS: // R32-IEEE STD 754 + QDS
		shortFloat(b[0:4], obj)
		obj[eventfields.KeyQuality] = b[4]
	case elemSCO: // SCS bit 0, bit 1 reserved 0, QU bits 2-6, S/E bit 7
		if b[0]&0x02 != 0 {
			return errors.New("SCO reserved bit 1 set")
		}
		commandQualifier(b[0], b[0]&0x01, obj)
	case elemDCO, elemRCO: // DCS/RCS bits 0-1 (1 or 2), QU bits 2-6, S/E bit 7
		state := b[0] & 0x03
		if state == 0 || state == 3 {
			return fmt.Errorf("command state %d is not a command (only 1 and 2)", state)
		}
		commandQualifier(b[0], state, obj)
	case elemNVAQOS, elemSVAQOS: // NVA or SVA (int16) + QOS
		obj[eventfields.KeyValue] = int16(binary.LittleEndian.Uint16(b[0:2]))
		setpointQualifier(b[2], obj)
	case elemFloatQOS: // R32 + QOS
		shortFloat(b[0:4], obj)
		setpointQualifier(b[4], obj)
	case elemBSI: // BSI, no select bit and no qualifier
		obj[eventfields.KeyValue] = binary.LittleEndian.Uint32(b[0:4])
	case elemCOI, elemQOI, elemQCC, elemQRP:
		obj[eventfields.KeyQualifier] = b[0]
	case elemNone, elemTSC:
		// Read carries no element; the test sequence counter is not exposed.
	}
	return nil
}

// commandQualifier records a single, double or regulating step command:
// QU (bits 2-6) and S/E (bit 7, 1 = select).
func commandQualifier(octet, state uint8, obj map[string]any) {
	obj[eventfields.KeyValue] = state
	obj[eventfields.KeyQualifier] = (octet >> 2) & 0x1F
	obj[eventfields.KeySelect] = octet&0x80 != 0
}

// setpointQualifier records QOS: QL (bits 0-6) and S/E (bit 7, 1 = select).
func setpointQualifier(qos uint8, obj map[string]any) {
	obj[eventfields.KeyQualifier] = qos & 0x7F
	obj[eventfields.KeySelect] = qos&0x80 != 0
}

// shortFloat records R32-IEEE STD 754 as value. The standard allows NaN and
// infinities, but JSON cannot carry them: such an object keeps its kind and
// other attributes, omits value and sets value_invalid (contracts K8).
func shortFloat(b []byte, obj map[string]any) {
	f := math.Float32frombits(binary.LittleEndian.Uint32(b))
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		obj[eventfields.KeyValueInvalid] = true
		return
	}
	obj[eventfields.KeyValue] = f
}

// decodeCP56 decodes CP56Time2a (IEC 60870-5-101 7.2.6.18): milliseconds
// (2 octets, 0..59999), minute (bits 0-5, 0..59; bit 6 GEN/RES1 ignored;
// bit 7 IV), hour (bits 0-4, 0..23; bit 7 SU), day of month (bits 0-4,
// 1..31; day of week ignored), month (bits 0-3, 1..12), year (bits 0-6,
// 0..99). Reserved bits are ignored. The century is not on the wire: year
// is 2000 + the year field (B profile assumption), and a field of 100..127
// or any date that cannot exist is malformed. source_time is ISO 8601
// without a zone; the profile, not the decoder, says the RTU runs UTC.
func decodeCP56(b []byte, obj map[string]any) error {
	ms := int(binary.LittleEndian.Uint16(b[0:2]))
	minute := int(b[2] & 0x3F)
	hour := int(b[3] & 0x1F)
	day := int(b[4] & 0x1F)
	month := int(b[5] & 0x0F)
	year := int(b[6] & 0x7F)
	switch {
	case ms > 59999:
		return fmt.Errorf("CP56Time2a milliseconds %d above 59999", ms)
	case minute > 59:
		return fmt.Errorf("CP56Time2a minute %d", minute)
	case hour > 23:
		return fmt.Errorf("CP56Time2a hour %d", hour)
	case year > 99:
		return fmt.Errorf("CP56Time2a year field %d above 99", year)
	case month < 1 || month > 12:
		return fmt.Errorf("CP56Time2a month %d", month)
	case day < 1 || day > daysIn(month, 2000+year):
		return fmt.Errorf("CP56Time2a day %d in %04d-%02d", day, 2000+year, month)
	}
	obj[eventfields.KeySourceTime] = fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03d",
		2000+year, month, day, hour, minute, ms/1000, ms%1000)
	obj[eventfields.KeyTimeValid] = b[2]&0x80 == 0
	obj[eventfields.KeyTimeSummer] = b[3]&0x80 != 0
	return nil
}

func daysIn(month, year int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	default:
		return 31
	}
}
