// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func init() {
	register(Template{
		Name:        "modbus-read-only",
		Description: "Modbus read-only – allow read function codes (FC 1-4), deny all write operations",
		Rules:       ModbusReadOnly(),
	})
	register(Template{
		Name:        "dnp3-secure-operations",
		Description: "DNP3 secure operations – allow normal reads, deny dangerous function codes (restart, stop)",
		Rules:       DNP3SecureOperations(),
	})
	register(Template{
		Name:        "s7comm-read-only",
		Description: "S7comm read-only – allow read variable (FC 0x04), deny write and PLC control",
		Rules:       S7commReadOnly(),
	})
	register(Template{
		Name:        "cip-monitor-only",
		Description: "CIP/EtherNet-IP monitor-only – allow read services, deny writes and control commands",
		Rules:       CIPMonitorOnly(),
	})
	register(Template{
		Name:        "bacnet-read-only",
		Description: "BACnet read-only – allow read properties, deny writes and device control",
		Rules:       BACnetReadOnly(),
	})
	register(Template{
		Name:        "opcua-monitor-only",
		Description: "OPC UA monitor-only – allow browse/read/subscribe, deny writes and node management",
		Rules:       OPCUAMonitorOnly(),
	})
}

// ModbusReadOnly returns rules that allow Modbus read function codes (1-4) and
// deny write function codes (5, 6, 15, 16, 22, 23).
func ModbusReadOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-modbus-allow-reads",
			Description: "Allow Modbus read operations (FC 1: Read Coils, FC 2: Read Discrete Inputs, FC 3: Read Holding Registers, FC 4: Read Input Registers)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "502"}},
			ICS: config.ICSPredicate{
				Protocol:     "modbus",
				FunctionCode: []uint8{1, 2, 3, 4},
				ReadOnly:     true,
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-modbus-deny-writes",
			Description: "Deny Modbus write operations (FC 5: Write Single Coil, FC 6: Write Single Register, FC 15: Write Multiple Coils, FC 16: Write Multiple Registers, FC 22: Mask Write Register, FC 23: Read/Write Multiple Registers)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "502"}},
			ICS: config.ICSPredicate{
				Protocol:     "modbus",
				FunctionCode: []uint8{5, 6, 15, 16, 22, 23},
			},
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
			Action: config.ActionAllow,
		},
	}
	return rules
}

// DNP3SecureOperations returns rules that allow safe DNP3 function codes and
// deny dangerous ones (restart, stop application).
func DNP3SecureOperations() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-dnp3-allow-reads",
			Description: "Allow DNP3 safe operations (FC 1: Read, FC 2: Write for responses, FC 20: File Transport)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "20000"}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{1, 2, 20},
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-dnp3-deny-dangerous",
			Description: "Deny DNP3 dangerous operations (FC 13: Cold Restart, FC 14: Warm Restart, FC 18: Stop Application)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "20000"}},
			ICS: config.ICSPredicate{
				Protocol:     "dnp3",
				FunctionCode: []uint8{13, 14, 18},
			},
			Action: config.ActionDeny,
		},
	}
}

// S7commReadOnly returns rules that allow S7comm read variable and deny
// write and PLC control operations.
func S7commReadOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-s7comm-allow-read",
			Description: "Allow S7comm read variable (FC 0x04)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "102"}},
			ICS: config.ICSPredicate{
				Protocol:     "s7comm",
				FunctionCode: []uint8{0x04},
				ReadOnly:     true,
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-s7comm-deny-write-control",
			Description: "Deny S7comm write and control (FC 0x05: Write Variable, FC 0x28: PLC Start, FC 0x29: PLC Stop)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "102"}},
			ICS: config.ICSPredicate{
				Protocol:     "s7comm",
				FunctionCode: []uint8{0x05, 0x28, 0x29},
			},
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
			Protocols:   []config.Protocol{{Name: "tcp", Port: "44818"}},
			ICS: config.ICSPredicate{
				Protocol:     "cip",
				FunctionCode: []uint8{0x01, 0x03, 0x0D, 0x0E, 0x4C, 0x4E},
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-cip-deny-write-control",
			Description: "Deny CIP write and control services (0x05: Reset, 0x06: Start, 0x07: Stop, 0x4D: Write_Tag, 0x4F: Write_Tag_Fragmented)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "44818"}},
			ICS: config.ICSPredicate{
				Protocol:     "cip",
				FunctionCode: []uint8{0x05, 0x06, 0x07, 0x4D, 0x4F},
			},
			Action: config.ActionDeny,
		},
	}
}

// BACnetReadOnly returns rules that allow BACnet read property services and
// deny write and device control operations.
func BACnetReadOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-bacnet-allow-reads",
			Description: "Allow BACnet read services (12: ReadProperty, 14: ReadPropertyMultiple, 26: ReadRange)",
			Protocols:   []config.Protocol{{Name: "udp", Port: "47808"}},
			ICS: config.ICSPredicate{
				Protocol:     "bacnet",
				FunctionCode: []uint8{12, 14, 26},
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-bacnet-deny-write-control",
			Description: "Deny BACnet write and control services (15: WriteProperty, 16: WritePropertyMultiple, 20: ReinitializeDevice, 17: DeviceCommunicationControl)",
			Protocols:   []config.Protocol{{Name: "udp", Port: "47808"}},
			ICS: config.ICSPredicate{
				Protocol:     "bacnet",
				FunctionCode: []uint8{15, 16, 20, 17},
			},
			Action: config.ActionDeny,
		},
	}
}

// OPCUAMonitorOnly returns rules that allow OPC UA browse, read, and
// subscribe services, and deny write, call, and node management services.
// Because OPC UA service node IDs exceed uint8 range, they are stored in the
// Addresses field as string representations.
func OPCUAMonitorOnly() []config.Rule {
	return []config.Rule{
		{
			ID:          "tpl-opcua-allow-monitor",
			Description: "Allow OPC UA monitoring services (525: Browse, 629: Read, 785: CreateSubscription, 749: CreateMonitoredItems)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "4840"}},
			ICS: config.ICSPredicate{
				Protocol:  "opcua",
				Addresses: []string{"525", "629", "785", "749"},
				ReadOnly:  true,
			},
			Action: config.ActionAllow,
		},
		{
			ID:          "tpl-opcua-deny-write-control",
			Description: "Deny OPC UA write and control services (671: Write, 710: Call, 486: AddNodes, 498: DeleteNodes)",
			Protocols:   []config.Protocol{{Name: "tcp", Port: "4840"}},
			ICS: config.ICSPredicate{
				Protocol:  "opcua",
				Addresses: []string{"671", "710", "486", "498"},
			},
			Action: config.ActionDeny,
		},
	}
}
