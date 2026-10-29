// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"fmt"
)

// AccessCategory is request semantics, not whole-message authorization.
type AccessCategory uint8

const (
	AccessUnknown AccessCategory = iota
	AccessRead
	AccessWrite
	AccessControl
	AccessStructural
)

type serviceDefinition struct {
	name     string
	category AccessCategory
}

var commonServices = map[uint8]serviceDefinition{
	0x01: {"Get_Attributes_All", AccessRead},
	0x02: {"Set_Attributes_All", AccessWrite},
	0x03: {"Get_Attribute_List", AccessRead},
	0x04: {"Set_Attribute_List", AccessWrite},
	0x05: {"Reset", AccessControl},
	0x06: {"Start", AccessControl},
	0x07: {"Stop", AccessControl},
	0x08: {"Create", AccessControl},
	0x09: {"Delete", AccessControl},
	0x0a: {"Multiple_Service_Packet", AccessStructural},
	0x0d: {"Apply_Attributes", AccessWrite},
	0x0e: {"Get_Attribute_Single", AccessRead},
	0x10: {"Set_Attribute_Single", AccessWrite},
	0x11: {"Find_Next_Object_Instance", AccessUnknown}, // body not supported
	0x14: {"Error_Response", AccessUnknown},            // DeviceNet, not an EIP request
	0x15: {"Restore", AccessWrite},
	0x16: {"Save", AccessWrite},
	0x17: {"No_Operation", AccessStructural},
	0x18: {"Get_Member", AccessRead},
	0x19: {"Set_Member", AccessWrite},
	0x1a: {"Insert_Member", AccessWrite},
	0x1b: {"Remove_Member", AccessWrite},
	0x1c: {"GroupSync", AccessControl},
}

var logixServices = map[uint8]serviceDefinition{
	0x4c: {"Read_Tag", AccessRead},
	0x4d: {"Write_Tag", AccessWrite},
	0x4e: {"Read_Modify_Write_Tag", AccessWrite},
	0x52: {"Read_Tag_Fragmented", AccessRead},
	0x53: {"Write_Tag_Fragmented", AccessWrite},
	0x55: {"Get_Instance_Attribute_List", AccessRead},
}

var objectServices = map[uint16]map[uint8]serviceDefinition{
	0x06: {
		0x4e: {"Forward_Close", AccessControl},
		0x52: {"Unconnected_Send", AccessUnknown},
		0x54: {"Forward_Open", AccessControl},
		0x56: {"Get_Connection_Data", AccessUnknown},
		0x57: {"Search_Connection_Data", AccessUnknown},
		0x5a: {"Get_Connection_Owner", AccessUnknown},
		0x5b: {"Large_Forward_Open", AccessControl},
		0x5c: {"Concurrent_Forward_Open", AccessControl},
		0x5e: {"Concurrent_Forward_Close", AccessControl},
	},
	0x37: {
		0x4b: {"Initiate_Upload", AccessStructural},
		0x4c: {"Initiate_Download", AccessWrite},
		0x4d: {"Initiate_Partial_Read", AccessStructural},
		0x4e: {"Initiate_Partial_Write", AccessWrite},
		0x4f: {"Upload_Transfer", AccessUnknown},
		0x50: {"Download_Transfer", AccessWrite},
		0x51: {"Clear_File", AccessWrite},
	},
	0x44: {
		0x4b: {"Read_Discrete_Inputs", AccessUnknown},
		0x4c: {"Read_Coils", AccessUnknown},
		0x4d: {"Read_Input_Registers", AccessUnknown},
		0x4e: {"Read_Holding_Registers", AccessUnknown},
		0x4f: {"Write_Coils", AccessWrite},
		0x50: {"Write_Holding_Registers", AccessWrite},
		0x51: {"Modbus_Passthrough", AccessUnknown},
	},
	0x47: {
		0x4b: {"Verify_Fault_Location", AccessControl},
		0x4c: {"Clear_Rapid_Faults", AccessWrite},
		0x4d: {"Restart_Sign_On", AccessControl},
		0x4e: {"Clear_Gateway_Partial_Fault", AccessWrite},
	},
	0x67: {0x4b: {"Execute_PCCC", AccessUnknown}},
	0x6c: {0x4c: {"Template_Read", AccessRead}},
	0xf3: {
		0x4b: {"Kick_Timer", AccessControl},
		0x4c: {"Open_Connection", AccessControl},
		0x4d: {"Close_Connection", AccessControl},
		0x4e: {"Stop_Connection", AccessControl},
		0x4f: {"Change_Start", AccessControl},
		0x50: {"Get_Status", AccessUnknown},
		0x51: {"Change_Complete", AccessControl},
		0x52: {"Audit_Change", AccessControl},
	},
	0xf5: {
		0x4c: {"Set_Port_Admin_State", AccessWrite},
		0x4d: {"Set_Protocol_Admin_State", AccessWrite},
	},
	0xf6: {0x4c: {"Get_And_Clear", AccessWrite}},
}

func lookupService(code uint8, t serviceTarget) serviceDefinition {
	if d, ok := commonServices[code]; ok {
		return d
	}
	if !t.valid || t.connectionPoint {
		return serviceDefinition{}
	}
	if t.symbolic {
		// Symbolic segments accept tag services, not class-based attribute enumeration.
		if code == 0x55 {
			return serviceDefinition{}
		}
		return logixServices[code]
	}
	switch t.class {
	case 0x6b:
		if code == 0x55 {
			// Get_Instance_Attribute_List accepts a bare Symbol instance, including zero.
			if !t.instanceTarget() {
				return serviceDefinition{}
			}
			return logixServices[code]
		}
		// Symbol class tag services accept nonzero instances and members, not attributes.
		if !t.hasInstance || t.instance == 0 || t.attribute {
			return serviceDefinition{}
		}
		if code == 0x4e {
			return serviceDefinition{} // unverified Symbol-instance RMW form
		}
		return logixServices[code]
	case 0x06:
		// Connection Manager services accept only bare instance 1.
		if !t.instanceTarget() || t.instance != 1 {
			return serviceDefinition{}
		}
	case 0x6c:
		// Template services accept only bare nonzero instances.
		if !t.instanceTarget() || t.instance == 0 {
			return serviceDefinition{}
		}
	}
	return objectServices[t.class][code]
}

// ServiceName resolves object-specific names only from a supported request
// target. A response has no such target unless separately correlated.
func ServiceName(code uint8, path []byte) string {
	base := code & 0x7f
	if d := lookupService(base, decodeTarget(path)); d.name != "" {
		return d.name
	}
	return fmt.Sprintf("Unknown(0x%02X)", base)
}

// Classify returns conservative access semantics for one decoded request.
// Unsupported bodies and targets never become reads by elimination.
func Classify(msg *CIPMessage) AccessCategory {
	if msg == nil || msg.IsResponse || msg.ServiceCode&0x80 != 0 || len(msg.Conformance) != 0 {
		return AccessUnknown
	}
	t := decodeTarget(msg.Path)
	if !t.valid || t.connectionPoint {
		return AccessUnknown
	}
	d := lookupService(msg.ServiceCode, t)
	if msg.ServiceCode == 0x0a && (t.class != 2 || !t.instanceTarget() || t.instance != 1) {
		return AccessUnknown
	}
	if d.category == AccessRead && !validReadBody(msg.ServiceCode, t, msg.Data) {
		return AccessUnknown
	}
	return d.category
}

func validReadBody(code uint8, t serviceTarget, body []byte) bool {
	switch code {
	case 0x01, 0x0e, 0x18:
		return !t.symbolic && len(body) == 0
	case 0x03, 0x55:
		return !t.symbolic && validAttributeList(body)
	case 0x4c:
		if t.class == 0x6c {
			return len(body) == 6
		}
		return len(body) == 2 && binary.LittleEndian.Uint16(body) != 0
	case 0x52:
		return len(body) == 6 && binary.LittleEndian.Uint16(body) != 0
	default:
		return false
	}
}

func validAttributeList(body []byte) bool {
	return len(body) >= 2 && binary.LittleEndian.Uint16(body) != 0 &&
		len(body) == 2+2*int(binary.LittleEndian.Uint16(body))
}
