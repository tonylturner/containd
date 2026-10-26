// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import "github.com/tonylturner/containd/pkg/dp/ics/eventfields"

// Class values of the class attribute and of policy classes.
const (
	ClassMonitor = "monitor"
	ClassControl = "control"
	ClassSystem  = "system"
	ClassUnknown = "unknown"
)

// BroadcastCA is the global common address of ASDU (IEC 60870-5-101
// 7.2.4); with the 2-octet CA of IEC 104 it is 65535.
const BroadcastCA = 0xFFFF

// Direction values: the TCP role of the sender, not act/con naming.
const (
	DirectionRequest  = "request"  // from the client (TCP opener)
	DirectionResponse = "response" // from the server (port 2404)
)

// elementKind is the information element layout that follows each IOA.
type elementKind uint8

const (
	elemNone     elementKind = iota // read command: IOA only
	elemSIQ                         // single-point information with quality
	elemDIQ                         // double-point information with quality
	elemVTI                         // step-position value with transient and quality
	elemBSIQDS                      // bitstring with QDS
	elemNVAQDS                      // normalized value with QDS
	elemSVAQDS                      // scaled value with QDS
	elemNVA                         // normalized value without quality
	elemBCR                         // binary counter reading
	elemFloatQDS                    // short float + QDS
	elemSCO                         // single command
	elemDCO                         // double command
	elemRCO                         // regulating step command
	elemNVAQOS                      // normalized value + QOS
	elemSVAQOS                      // scaled value + QOS
	elemFloatQOS                    // short float + QOS
	elemBSI                         // bitstring of 32 bits
	elemCOI                         // cause of initialization
	elemQOI                         // qualifier of interrogation
	elemQCC                         // qualifier of counter interrogation
	elemQRP                         // qualifier of reset process
	elemTSC                         // test sequence counter (2 octets)
)

var elementSize = [...]int{
	elemNone:     0,
	elemSIQ:      1,
	elemDIQ:      1,
	elemVTI:      2,
	elemBSIQDS:   5,
	elemNVAQDS:   3,
	elemSVAQDS:   3,
	elemNVA:      2,
	elemBCR:      5,
	elemFloatQDS: 5,
	elemSCO:      1,
	elemDCO:      1,
	elemRCO:      1,
	elemNVAQOS:   3,
	elemSVAQOS:   3,
	elemFloatQOS: 5,
	elemBSI:      4,
	elemCOI:      1,
	elemQOI:      1,
	elemQCC:      1,
	elemQRP:      1,
	elemTSC:      2,
}

// cp56Len is the size of CP56Time2a (IEC 60870-5-101 7.2.6.18).
const cp56Len = 7

// descriptor defines the supported decoding of one Type ID.
type descriptor struct {
	class  string
	elem   elementKind
	timed  bool // a CP56Time2a follows the element
	sqOK   bool // Decoder profile: SQ=1 accepted for this untimed monitor layout
	single bool // Decoder profile: SQ=0 and exactly one object (control and system types)
}

// objectSize is the size of one information object without its IOA.
func (d descriptor) objectSize() int {
	n := elementSize[d.elem]
	if d.timed {
		n += cp56Len
	}
	return n
}

// descriptors holds every Type ID with a decoder descriptor. Every other Type ID,
// including 104 and 106 (IEC 101 test and delay commands, not used in IEC
// 104), is unsupported and of class unknown.
var descriptors = map[uint8]descriptor{
	1:  {class: ClassMonitor, elem: elemSIQ, sqOK: true},       // M_SP_NA_1
	3:  {class: ClassMonitor, elem: elemDIQ, sqOK: true},       // M_DP_NA_1
	5:  {class: ClassMonitor, elem: elemVTI, sqOK: true},       // M_ST_NA_1
	7:  {class: ClassMonitor, elem: elemBSIQDS, sqOK: true},    // M_BO_NA_1
	9:  {class: ClassMonitor, elem: elemNVAQDS, sqOK: true},    // M_ME_NA_1
	11: {class: ClassMonitor, elem: elemSVAQDS, sqOK: true},    // M_ME_NB_1
	13: {class: ClassMonitor, elem: elemFloatQDS, sqOK: true},  // M_ME_NC_1
	15: {class: ClassMonitor, elem: elemBCR, sqOK: true},       // M_IT_NA_1
	21: {class: ClassMonitor, elem: elemNVA, sqOK: true},       // M_ME_ND_1
	30: {class: ClassMonitor, elem: elemSIQ, timed: true},      // M_SP_TB_1
	31: {class: ClassMonitor, elem: elemDIQ, timed: true},      // M_DP_TB_1
	32: {class: ClassMonitor, elem: elemVTI, timed: true},      // M_ST_TB_1
	33: {class: ClassMonitor, elem: elemBSIQDS, timed: true},   // M_BO_TB_1
	34: {class: ClassMonitor, elem: elemNVAQDS, timed: true},   // M_ME_TD_1
	35: {class: ClassMonitor, elem: elemSVAQDS, timed: true},   // M_ME_TE_1
	36: {class: ClassMonitor, elem: elemFloatQDS, timed: true}, // M_ME_TF_1
	37: {class: ClassMonitor, elem: elemBCR, timed: true},      // M_IT_TB_1

	45: {class: ClassControl, elem: elemSCO, single: true},                   // C_SC_NA_1
	46: {class: ClassControl, elem: elemDCO, single: true},                   // C_DC_NA_1
	47: {class: ClassControl, elem: elemRCO, single: true},                   // C_RC_NA_1
	48: {class: ClassControl, elem: elemNVAQOS, single: true},                // C_SE_NA_1
	49: {class: ClassControl, elem: elemSVAQOS, single: true},                // C_SE_NB_1
	50: {class: ClassControl, elem: elemFloatQOS, single: true},              // C_SE_NC_1
	51: {class: ClassControl, elem: elemBSI, single: true},                   // C_BO_NA_1
	58: {class: ClassControl, elem: elemSCO, timed: true, single: true},      // C_SC_TA_1
	59: {class: ClassControl, elem: elemDCO, timed: true, single: true},      // C_DC_TA_1
	60: {class: ClassControl, elem: elemRCO, timed: true, single: true},      // C_RC_TA_1
	61: {class: ClassControl, elem: elemNVAQOS, timed: true, single: true},   // C_SE_TA_1
	62: {class: ClassControl, elem: elemSVAQOS, timed: true, single: true},   // C_SE_TB_1
	63: {class: ClassControl, elem: elemFloatQOS, timed: true, single: true}, // C_SE_TC_1
	64: {class: ClassControl, elem: elemBSI, timed: true, single: true},      // C_BO_TA_1

	70:  {class: ClassSystem, elem: elemCOI, single: true},               // M_EI_NA_1
	100: {class: ClassSystem, elem: elemQOI, single: true},               // C_IC_NA_1
	101: {class: ClassSystem, elem: elemQCC, single: true},               // C_CI_NA_1
	102: {class: ClassSystem, elem: elemNone, single: true},              // C_RD_NA_1
	103: {class: ClassSystem, elem: elemNone, timed: true, single: true}, // C_CS_NA_1
	105: {class: ClassSystem, elem: elemQRP, single: true},               // C_RP_NA_1
	107: {class: ClassSystem, elem: elemTSC, timed: true, single: true},  // C_TS_TA_1
}

// keyTransient is the step-position VTI transient flag. It has no shared
// eventfields constant because no other current ICS decoder emits it.
const keyTransient = "transient"

// Type IDs named by the read-only set and the write classification.
const (
	typeEndOfInit       = 70
	typeInterrogation   = 100
	typeCounterInterrog = 101
	typeRead            = 102
	typeClockSync       = 103
	typeResetProcess    = 105
)

// ClassOf returns the class of a Type ID: monitor, control or system for
// the Type IDs with a decoder descriptor, unknown for every other.
func ClassOf(typeID uint8) string {
	if d, ok := descriptors[typeID]; ok {
		return d.class
	}
	return ClassUnknown
}

// monitorDirectionType reports the Type IDs that IEC 60870-5-101 7.2.1.1
// defines for process information in monitor direction (1..44).
func monitorDirectionType(typeID uint8) bool {
	return typeID >= 1 && typeID <= 44
}

// isWrite reports mutating client requests: every control-class command, and
// the system commands that change outstation state (counter interrogation
// can freeze or reset counters, clock synchronization, reset process).
func isWrite(direction string, typeID uint8) bool {
	if direction != DirectionRequest {
		return false
	}
	switch typeID {
	case typeCounterInterrog, typeClockSync, typeResetProcess:
		return true
	}
	return ClassOf(typeID) == ClassControl
}

// SafeRead reports whether a decoded IEC104 event is in the read-only set:
// S-frames; every U-frame (STARTDT, STOPDT,
// TESTFR); monitor-class I-frames in the response direction; general
// interrogation (100) in either direction; read (102) requests only; end of
// initialization (70). It is false for anything else: counter interrogation
// (101), clock sync (103), reset process (105), test with time (107),
// control commands and confirmations, broadcast CA, and every malformed or
// unsupported event (those carry an error attribute). It reads attributes
// through the strict eventfields accessors, so it accepts the in-memory and
// the JSON form.
func SafeRead(attrs map[string]any) bool {
	if _, failed := attrs[eventfields.KeyError]; failed {
		return false
	}
	apci, _ := eventfields.String(attrs, eventfields.KeyAPCIType)
	switch apci {
	case "S", "U":
		return true
	case "I":
	default:
		return false
	}
	ca, ok := eventfields.Uint16(attrs, eventfields.KeyCA)
	if !ok || ca == BroadcastCA {
		return false
	}
	typeID, ok := eventfields.Uint8(attrs, eventfields.KeyTypeID)
	if !ok {
		return false
	}
	direction, _ := eventfields.String(attrs, eventfields.KeyDirection)
	switch {
	case ClassOf(typeID) == ClassMonitor:
		return direction == DirectionResponse
	case typeID == typeInterrogation, typeID == typeEndOfInit:
		return direction == DirectionRequest || direction == DirectionResponse
	case typeID == typeRead:
		return direction == DirectionRequest
	default:
		return false
	}
}
