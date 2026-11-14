// SPDX-License-Identifier: Apache-2.0
package engine

// iecProcedure defines the admitted service vocabulary. Clause references use
// IEC 60870-5-101:2003 and IEC 60870-5-104:2006. Optional termination is an
// executable-command property, never permission to join select and execute.
// Variants explicitly bound observed peer stage tolerances to their request.
type iecProcedure struct {
	Type                        uint8
	RequestCause                uint8
	ConfirmCause                uint8
	Termination                 bool
	DataCauseLow, DataCauseHigh uint8
	Clause                      string
	Variants                    iecStageVariants
}

type iecStageVariants uint8

const (
	iecOptionalReadConfirm iecStageVariants = 1 << iota
	iecTerminationSelectEcho
	iecNegativeError
)

// Counter groups 1–4 permit the general cause or their own group cause;
// group 5 is the general interrogation, not a sixth cause.
var iecCounterCauses = [...][]uint8{{37, 38}, {37, 39}, {37, 40}, {37, 41}, {37}}

var iecProcedures = [...]iecProcedure{
	{45, 6, 7, true, 0, 0, "101 7.3.2.1; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{46, 6, 7, true, 0, 0, "101 7.3.2.2; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{47, 6, 7, true, 0, 0, "101 7.3.2.3; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{48, 6, 7, true, 0, 0, "101 7.3.2.4; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{49, 6, 7, true, 0, 0, "101 7.3.2.5; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{50, 6, 7, true, 0, 0, "101 7.3.2.6; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{51, 6, 7, true, 0, 0, "101 7.3.2.7; 7.2.3; 104 8.1", iecNegativeError | iecTerminationSelectEcho},
	{58, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{59, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{60, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{61, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{62, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{63, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{64, 6, 7, true, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError | iecTerminationSelectEcho},
	{100, 6, 7, true, 20, 36, "101 7.3.4.1; 7.2.3; 104 8.1", iecNegativeError},
	{101, 6, 7, true, 37, 41, "101 7.3.4.2; 7.2.3; 104 8.1", iecNegativeError},
	{102, 5, 7, false, 5, 5, "101 7.3.4.3; 7.2.3; 104 8.1", iecNegativeError | iecOptionalReadConfirm},
	{103, 6, 7, false, 0, 0, "101 7.3.4.4; 7.2.3; 104 8.1", iecNegativeError},
	{107, 6, 7, false, 0, 0, "104 8.1; 101 7.2.3", iecNegativeError},
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
