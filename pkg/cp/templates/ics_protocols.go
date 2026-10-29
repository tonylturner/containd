// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import (
	"fmt"
	"strconv"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func init() {
	register(Template{
		Name:        "modbus-read-only",
		Description: "Modbus read-only – allow read function codes (FC 1-4), deny listed write function codes",
		Rules:       ModbusReadOnly(),
	})
	register(Template{
		Name:        "dnp3-secure-operations",
		Description: "DNP3 secure operations – allow startup operations and time/IIN writes, deny restart, stop and save configuration",
		Rules:       DNP3SecureOperations(),
	})
	register(Template{
		Name:        "cip-monitor-only",
		Description: "CIP/EtherNet-IP monitor-only – allow classified reads, deny classified writes and control commands",
		Rules:       CIPMonitorOnly(),
	})
}

// ModbusReadOnly returns rules that allow Modbus read function codes (1-4) and
// deny write function codes (5, 6, 15, 16, 21, 22, 23). Other functions,
// including diagnostics and private extensions, require a default-deny policy.
//
// Log:true is set on every rule so the operator has visibility into both
// what the deny rule would block AND what the allow rule actually passes —
// essential for the monitor-first observation phase. ICSPredicate.Mode is
// left blank so the rule inherits the global DPIMode (which defaults to
// "learn"). Operators promote to enforce by setting the global mode or
// re-applying via the apply-time `mode` parameter.
func ModbusReadOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-modbus-allow-reads",
			Description: "Allow Modbus read operations (FC 1: Read Coils, FC 2: Read Discrete Inputs, FC 3: Read Holding Registers, FC 4: Read Input Registers)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.ModbusPort)}},
			ICS: config.ICSPredicate{
				Protocol:     "modbus",
				FunctionCode: []uint8{1, 2, 3, 4},
				ReadOnly:     true,
			},
			Log:    true,
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-modbus-deny-writes",
			Description: "Deny Modbus write operations (FC 5: Write Single Coil, FC 6: Write Single Register, FC 15: Write Multiple Coils, FC 16: Write Multiple Registers, FC 21: Write File Record, FC 22: Mask Write Register, FC 23: Read/Write Multiple Registers)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.ModbusPort)}},
			ICS: config.ICSPredicate{
				Protocol:     "modbus",
				FunctionCode: []uint8{5, 6, 15, 16, 21, 22, 23},
			},
			Log:    true,
			Action: config.ActionDeny,
		},
	}
}

// ModbusRegisterGuard returns rules that allow Modbus access only to the
// specified register address ranges. Each range is a string like "0-99" or
// "400-499".
func ModbusRegisterGuard(allowedRanges []string) []config.Rule {
	rules := []config.Rule{
		{
			ID:          "tpl-modbus-register-allow",
			Description: fmt.Sprintf("Allow Modbus access to register ranges %v", allowedRanges),
			Protocols:   []config.Protocol{{Name: "tcp", Port: "502"}},
			ICS: config.ICSPredicate{
				Protocol:  "modbus",
				Addresses: allowedRanges,
			},
			Log:    true,
			Action: config.ActionAllow,
		},
	}
	return rules
}

// DNP3SecureOperations returns rules that allow safe DNP3 function codes and
// deny restart, stop application and save configuration. Writes are limited to
// time and internal-indication object groups, not arbitrary output groups.
func DNP3SecureOperations() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-dnp3-allow-reads",
			Description: "Allow DNP3 startup operations (FC 0: Confirm, FC 1: Read, FC 20: Enable Unsolicited, FC 21: Disable Unsolicited, FC 23: Delay Measure, FC 24: Record Current Time)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.DNP3Port)}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{0, 1, 20, 21, 23, 24},
			},
			Log:    true,
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-dnp3-allow-time-iin-writes",
			Description: "Allow DNP3 Write (FC 2) only for time (group 50) and internal indications (group 80)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.DNP3Port)}},
			ICS:         config.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{2}, Groups: []int{50, 80}},
			Log:         true,
			Action:      config.ActionAllow,
		},
		{
			ID:          "tpl-dnp3-deny-dangerous",
			Description: "Deny DNP3 dangerous operations (FC 13: Cold Restart, FC 14: Warm Restart, FC 18: Stop Application, FC 19: Save Configuration)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.DNP3Port)}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{13, 14, 18, 19},
			},
			Log:    true,
			Action: config.ActionDeny,
		},
	}
}

// CIPMonitorOnly returns rules that allow CIP/EtherNet-IP read services and
// deny write and control commands.
func CIPMonitorOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-cip-allow-reads",
			Description: "Allow CIP requests classified as reads for their decoded target",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.CIPPort)}},
			ICS: config.ICSPredicate{
				Protocol: "cip",
				ReadOnly: true,
			},
			Log:    true,
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-cip-deny-write-control",
			Description: "Deny CIP requests classified as writes or control operations",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.CIPPort)}},
			ICS: config.ICSPredicate{
				Protocol:  "cip",
				WriteOnly: true,
			},
			Log:    true,
			Action: config.ActionDeny,
		},
	}
}
