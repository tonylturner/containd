// SPDX-License-Identifier: Apache-2.0
package modbus

// Diagnostics is the serial-line profile in MODBUS Application Protocol
// V1.1b3 §6.8.1. TCP endpoints need not implement these operations. In
// particular, changing the ASCII delimiter (3) is not listen-only mode (4).
type diagnosticDescriptor struct {
	name     string
	write    bool
	request  diagnosticData
	response diagnosticData
}

type diagnosticData uint8

const (
	diagnosticWords     diagnosticData = iota // one or more echoed words
	diagnosticWord                            // one arbitrary word
	diagnosticZero                            // one zero word
	diagnosticRestart                         // 0000 or FF00
	diagnosticDelimiter                       // character in high byte, low byte zero
	diagnosticNoReply                         // force listen-only has no normal response
)

// One authority for names, access category and both directional layouts.
// Reserved 5–9/19 and vendor extensions (including Modbus Plus 21) are outside
// this profile, not silently certified by a generic FC8 length check.
var diagnosticSubfunctions = map[uint16]diagnosticDescriptor{
	0:  {"return_query_data", false, diagnosticWords, diagnosticWords},
	1:  {"restart_comm", true, diagnosticRestart, diagnosticRestart},
	2:  {"return_diagnostic_register", false, diagnosticZero, diagnosticWord},
	3:  {"change_ascii_input_delimiter", true, diagnosticDelimiter, diagnosticDelimiter},
	4:  {"force_listen_only", true, diagnosticZero, diagnosticNoReply},
	10: {"clear_counters", true, diagnosticZero, diagnosticZero},
	11: {"return_bus_message_count", false, diagnosticZero, diagnosticWord},
	12: {"return_bus_communication_error_count", false, diagnosticZero, diagnosticWord},
	13: {"return_bus_exception_error_count", false, diagnosticZero, diagnosticWord},
	14: {"return_device_message_count", false, diagnosticZero, diagnosticWord},
	15: {"return_device_no_response_count", false, diagnosticZero, diagnosticWord},
	16: {"return_device_nak_count", false, diagnosticZero, diagnosticWord},
	17: {"return_device_busy_count", false, diagnosticZero, diagnosticWord},
	18: {"return_bus_character_overrun_count", false, diagnosticZero, diagnosticWord},
	20: {"clear_overrun", true, diagnosticZero, diagnosticZero},
}

func validDiagnosticLayout(p []byte, response bool) bool {
	if len(p) < 2 {
		return false
	}
	desc, known := diagnosticSubfunctions[be16(p, 0)]
	if !known {
		return len(p) >= 4 && len(p)%2 == 0
	}
	rule := desc.request
	if response {
		rule = desc.response
	}
	if rule == diagnosticNoReply {
		return false
	}
	if rule == diagnosticWords {
		return len(p) >= 4 && len(p)%2 == 0
	}
	if len(p) != 4 {
		return false
	}
	data := be16(p, 2)
	switch rule {
	case diagnosticZero:
		return data == 0
	case diagnosticRestart:
		return data == 0 || data == 0xff00
	case diagnosticDelimiter:
		return data&0xff == 0
	default:
		return true
	}
}
