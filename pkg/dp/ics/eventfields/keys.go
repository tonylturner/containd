// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package eventfields owns the shared ICS event attribute keys and the
// strict accessors that read them, both in memory and after a JSON round
// trip. It depends on the standard library only.
package eventfields

// Proto values.
const (
	ProtoIEC104 = "iec104"
	ProtoModbus = "modbus"
	ProtoDNP3   = "dnp3"
	ProtoCIP    = "cip"
)

// Decoder event kinds. IEC104 uses all five; Modbus and DNP3 emit
// KindMalformed for bytes they cannot frame.
const (
	KindRequest     = "request"
	KindResponse    = "response"
	KindAPCI        = "apci"
	KindMalformed   = "malformed"
	KindUnsupported = "unsupported"
)

// Engine event kinds for decisions and their outcomes.
const (
	KindDecision = "ics.decision"
	KindVerdict  = "ics.verdict"
	KindSession  = "ics.session"
)

// Shared attribute keys used by several ICS decoders and consumers.
const (
	KeyFunctionCode = "function_code"
	KeyUnitID       = "unit_id"
	KeyIsWrite      = "is_write"
	KeyDirection    = "direction"
	KeyError        = "error"
	KeyObjectGroups = "object_groups"
	KeyMessage      = "message"
	KeyAnomalyType  = "anomaly_type"
	// KeyConformance lists stable finding codes ("<proto>.<finding>", for
	// example "modbus.pid_nonzero") on an event whose frame boundary is
	// known but whose content does not conform. Absent means conformant.
	// The value is []string, sorted and without duplicates.
	KeyConformance = "conformance"
	// KeyUndecoded lists stable codes ("<proto>.<reason>", for example
	// "cip.msp_nested") for framed content the decoder did not inspect.
	// Policy treats it like KeyConformance, with its own alert. Absent
	// means every framed byte was decoded. The value is []string, sorted
	// and without duplicates.
	KeyUndecoded = "undecoded"
)

// IEC104 event attribute keys.
const (
	KeyAPCIType        = "apci_type"
	KeyClass           = "class"
	KeySendSequence    = "send_sequence"
	KeyReceiveSequence = "receive_sequence"
	KeyUFunction       = "u_function"
	KeyTypeID          = "type_id"
	KeyVSQ             = "vsq"
	KeyObjectCount     = "object_count"
	KeyCause           = "cause"
	KeyOriginator      = "originator"
	KeySQ              = "sq"
	KeyCOTTest         = "cot_test"
	KeyCOTNegative     = "cot_negative"
	KeyCA              = "ca"
	KeyIOA             = "ioa"
	KeyObjectIndex     = "object_index"
	KeySelect          = "select"
	KeyQualifier       = "qualifier"
	KeyQuality         = "quality"
	KeyValue           = "value"
	KeyValueInvalid    = "value_invalid"
	KeySourceTime      = "source_time"
	KeyTimeValid       = "time_valid"
	KeyTimeSummer      = "time_summer"
	KeyAPDUID          = "apdu_id"
	KeySessionID       = "session_id"
	KeyRawHex          = "raw_hex"
)

// Decision and outcome event keys.
const (
	KeyDecision      = "decision"
	KeyRuleID        = "ruleId"
	KeyAction        = "action"
	KeyMode          = "mode"
	KeyReason        = "reason"
	KeyOutcome       = "outcome"
	KeyTarget        = "target"
	KeyAPDUIDs       = "apdu_ids"
	KeyTriggerAPDUID = "trigger_apdu_id"
)

// D.7 coverage and CIP target keys, shared by decoders (emitters) and the
// engine (context builder).
const (
	// KeyCoverageIncomplete (bool true) marks an event whose message was
	// not fully inspected; the engine adds an ObjectUnknown context.
	KeyCoverageIncomplete = "coverage_incomplete"
	// KeyCIPTarget is "logical", "symbolic" or "unknown".
	KeyCIPTarget = "cip_target"
	// KeyCIPSymbol is the []string of ANSI extended symbol segments.
	KeyCIPSymbol   = "cip_symbol"
	KeyObjectClass = "object_class"
	KeyInstanceID  = "instance_id"
	KeyAttributeID = "attribute_id"
)
