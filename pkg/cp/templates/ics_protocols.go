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
		Description: "DNP3 example – allow read, write and enable unsolicited; deny restart and stop",
		Rules:       DNP3SecureOperations(),
	})
	register(Template{
		Name:        "cip-monitor-only",
		Description: "CIP/EtherNet-IP monitor-only – allow read services, deny writes and control commands",
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

// DNP3SecureOperations returns an example allowing read, write and enable
// unsolicited, while denying restart and stop application. It is not read-only.
func DNP3SecureOperations() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-dnp3-allow-reads",
			Description: "Allow DNP3 operations (FC 1: Read, FC 2: Write, FC 20: Enable Unsolicited); not read-only",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.DNP3Port)}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{1, 2, 20},
			},
			Log:    true,
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-dnp3-deny-dangerous",
			Description: "Deny DNP3 dangerous operations (FC 13: Cold Restart, FC 14: Warm Restart, FC 18: Stop Application)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.DNP3Port)}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{13, 14, 18},
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
			Description: "Allow CIP read services (0x01: Get_Attributes_All, 0x03: Get_Attribute_List, 0x0D: Get_Attribute_Single, 0x0E: Get_Member, 0x4C: Read_Tag, 0x4E: Read_Tag_Fragmented)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.CIPPort)}},
			ICS: config.ICSPredicate{
				Protocol:     "cip",
				FunctionCode: []uint8{0x01, 0x03, 0x0D, 0x0E, 0x4C, 0x4E},
			},
			Log:    true,
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-cip-deny-write-control",
			Description: "Deny CIP write and control services (0x05: Reset, 0x06: Start, 0x07: Stop, 0x4D: Write_Tag, 0x4F: Write_Tag_Fragmented)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: strconv.Itoa(ics.CIPPort)}},
			ICS: config.ICSPredicate{
				Protocol:     "cip",
				FunctionCode: []uint8{0x05, 0x06, 0x07, 0x4D, 0x4F},
			},
			Log:    true,
			Action: config.ActionDeny,
		},
	}
}
