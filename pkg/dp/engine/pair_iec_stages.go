// SPDX-License-Identifier: Apache-2.0
package engine

// iecProcedure defines the admitted service vocabulary. Clause references use
// IEC 60870-5-101:2003 and IEC 60870-5-104:2006. Optional termination is an
// executable-command property, never permission to join select and execute.
// StandardOnly identifies rows awaiting independent peer observations.
type iecProcedure struct {
	Type                        uint8
	RequestCause                uint8
	ConfirmCause                uint8
	Termination                 bool
	DataCauseLow, DataCauseHigh uint8
	Clause                      string
	StandardOnly                bool
}

var iecProcedures = [...]iecProcedure{
	{45, 6, 7, true, 0, 0, "101 7.3.2.1; 7.2.3; 104 8.1", true},
	{46, 6, 7, true, 0, 0, "101 7.3.2.2; 7.2.3; 104 8.1", true},
	{47, 6, 7, true, 0, 0, "101 7.3.2.3; 7.2.3; 104 8.1", true},
	{48, 6, 7, true, 0, 0, "101 7.3.2.4; 7.2.3; 104 8.1", true},
	{49, 6, 7, true, 0, 0, "101 7.3.2.5; 7.2.3; 104 8.1", true},
	{50, 6, 7, true, 0, 0, "101 7.3.2.6; 7.2.3; 104 8.1", true},
	{51, 6, 7, true, 0, 0, "101 7.3.2.7; 7.2.3; 104 8.1", true},
	{58, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{59, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{60, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{61, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{62, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{63, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{64, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", true},
	{100, 6, 7, true, 20, 36, "101 7.3.4.1; 7.2.3; 104 8.1", true},
	{101, 6, 7, true, 37, 41, "101 7.3.4.2; 7.2.3; 104 8.1", true},
	{102, 5, 0, false, 5, 5, "101 7.3.4.3; 7.2.3; 104 8.1", true},
	{103, 6, 7, false, 0, 0, "101 7.3.4.4; 7.2.3; 104 8.1", true},
	{105, 6, 7, false, 0, 0, "101 7.3.4.6; 7.2.3; 104 8.1", true},
	{107, 6, 7, false, 0, 0, "104 8.1; 101 7.2.3", true},
}

// The monitored Type IDs supported by the producer. Interrogation and Read
// return only this explicit vocabulary; an unknown type is not autonomous.
var iecMonitorTypes = [...]uint8{1, 3, 5, 7, 9, 11, 13, 15, 21, 30, 31, 32, 33, 34, 35, 36, 37}

func iecProcedureFor(typ uint8) (iecProcedure, bool) {
	for _, row := range iecProcedures {
		if row.Type == typ {
			return row, true
		}
	}
	return iecProcedure{}, false
}
func iecMonitorType(typ uint8) bool {
	for _, t := range iecMonitorTypes {
		if t == typ {
			return true
		}
	}
	return false
}
