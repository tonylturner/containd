// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EtherNet/IP encapsulation header size in bytes.
const eipHeaderSize = 24

var (
	ErrTooShort      = errors.New("EtherNet/IP frame too short")
	ErrTruncated     = errors.New("EtherNet/IP frame truncated")
	ErrNoCIPPayload  = errors.New("no CIP payload in encapsulation")
	ErrCIPTooShort   = errors.New("CIP message too short")
)

// EIPHeader represents a parsed EtherNet/IP encapsulation header.
type EIPHeader struct {
	Command       uint16
	Length        uint16
	SessionHandle uint32
	Status        uint32
	SenderContext [8]byte
	Options       uint32
	Data          []byte // payload after the 24-byte header
}

// CIPMessage represents a parsed CIP message extracted from SendRRData/SendUnitData.
type CIPMessage struct {
	ServiceCode uint8
	ServiceName string
	IsResponse  bool
	Path        []byte
	Data        []byte
}

// commandNames maps EtherNet/IP encapsulation command codes to names.
var commandNames = map[uint16]string{
	0x0001: "ListServices",
	0x0004: "ListIdentity",
	0x0063: "ListInterfaces",
	0x0065: "RegisterSession",
	0x0066: "UnregisterSession",
	0x006F: "SendRRData",
	0x0070: "SendUnitData",
}

// serviceNames maps CIP service codes to names.
var serviceNames = map[uint8]string{
	0x01: "Get_Attributes_All",
	0x02: "Set_Attributes_All",
	0x03: "Get_Attribute_List",
	0x04: "Set_Attribute_List",
	0x05: "Reset",
	0x06: "Start",
	0x07: "Stop",
	0x08: "Create",
	0x09: "Delete",
	0x0A: "Multiple_Service_Packet",
	0x0B: "Apply_Attributes",
	0x0D: "Get_Attribute_Single",
	0x0E: "Get_Attribute_Single", // alias kept for backward compat
	0x10: "Set_Attribute_Single",
	0x14: "Find_Next_Object",
	0x15: "Error_Response",
	0x16: "Save",
	0x17: "Restore",
	0x18: "No_Operation",
	0x19: "Get_Member",
	0x1A: "Set_Member",
	0x4B: "Execute_PCCC",
	0x4C: "Read_Tag",
	0x4D: "Write_Tag",
	0x4E: "Read_Tag_Fragmented",
	0x4F: "Write_Tag_Fragmented",
	0x52: "Read_Modify_Write_Tag",
	0x53: "Forward_Close",
	0x54: "Forward_Open",
	0x5B: "Get_Instance_Attribute_List",
}

// objectClassNames maps CIP object class IDs to names.
var objectClassNames = map[uint16]string{
	0x01: "Identity",
	0x02: "Message_Router",
	0x04: "Assembly",
	0x06: "Connection_Manager",
	0x66: "EtherNet_Link",
	0x67: "QoS",
	0x68: "TCP_IP_Interface",
	0xAC: "Program",
}

// ObjectClassName returns a human-readable name for a CIP object class ID.
func ObjectClassName(classID uint16) string {
	if name, ok := objectClassNames[classID]; ok {
		return name
	}
	return fmt.Sprintf("Class(0x%04X)", classID)
}

// CommandName returns the human-readable name for an EIP command code.
func CommandName(cmd uint16) string {
	if name, ok := commandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", cmd)
}

// ServiceName returns the human-readable name for a CIP service code.
// The response bit (0x80) is masked off before lookup.
func ServiceName(code uint8) string {
	base := code & 0x7F
	if name, ok := serviceNames[base]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", base)
}

// IsReadService returns true for CIP service codes classified as read operations.
func IsReadService(code uint8) bool {
	base := code & 0x7F
	switch base {
	case 0x01, 0x03, 0x0D, 0x0E, 0x14, 0x19, 0x4C, 0x4E, 0x5B:
		return true
	default:
		return false
	}
}

// IsWriteService returns true for CIP service codes classified as write/control operations.
func IsWriteService(code uint8) bool {
	base := code & 0x7F
	switch base {
	case 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0B,
		0x10, 0x16, 0x1A,
		0x4B, 0x4D, 0x4F, 0x52, 0x54:
		return true
	default:
		return false
	}
}

// IsControlService returns true for CIP connection management and critical service codes.
func IsControlService(code uint8) bool {
	base := code & 0x7F
	switch base {
	case 0x05, 0x06, 0x07, 0x08, 0x09, 0x54:
		return true
	default:
		return false
	}
}

// EPathResult holds the fully parsed contents of a CIP EPATH.
type EPathResult struct {
	ClassID     uint16
	InstanceID  uint16
	AttributeID uint16
	MemberID    uint16
	Raw         []byte
}

// ParseEPath walks EPATH segments and extracts class, instance, attribute,
// and member IDs from all recognised segment types.
func ParseEPath(data []byte) EPathResult {
	r := EPathResult{Raw: data}
	i := 0
	for i < len(data) {
		seg := data[i]
		switch seg {
		case 0x20: // 8-bit class
			if i+1 < len(data) {
				r.ClassID = uint16(data[i+1])
			}
			i += 2
		case 0x21: // 16-bit class (padded)
			if i+3 < len(data) {
				r.ClassID = binary.LittleEndian.Uint16(data[i+2 : i+4])
			}
			i += 4
		case 0x24: // 8-bit instance
			if i+1 < len(data) {
				r.InstanceID = uint16(data[i+1])
			}
			i += 2
		case 0x25: // 16-bit instance (padded)
			if i+3 < len(data) {
				r.InstanceID = binary.LittleEndian.Uint16(data[i+2 : i+4])
			}
			i += 4
		case 0x28: // 8-bit member (sometimes used as attribute in older CIP)
			if i+1 < len(data) {
				r.MemberID = uint16(data[i+1])
			}
			i += 2
		case 0x29: // 16-bit member (padded)
			if i+3 < len(data) {
				r.MemberID = binary.LittleEndian.Uint16(data[i+2 : i+4])
			}
			i += 4
		case 0x2C, 0x30: // 8-bit attribute (standard and alternate encoding)
			if i+1 < len(data) {
				r.AttributeID = uint16(data[i+1])
			}
			i += 2
		case 0x2D, 0x31: // 16-bit attribute (standard and alternate encoding, padded)
			if i+3 < len(data) {
				r.AttributeID = binary.LittleEndian.Uint16(data[i+2 : i+4])
			}
			i += 4
		default:
			// Unknown segment; 8-bit variants use 2 bytes, 16-bit (odd) use 4.
			if seg&0x01 != 0 {
				i += 4
			} else {
				i += 2
			}
		}
	}
	return r
}

// ExtractClassFromPath scans a CIP EPATH for an 8-bit or 16-bit class segment
// and returns the class ID. Delegates to ParseEPath internally.
func ExtractClassFromPath(path []byte) (uint16, bool) {
	r := ParseEPath(path)
	if r.ClassID != 0 {
		return r.ClassID, true
	}
	return 0, false
}

// FormatAddress returns a formatted "class/instance/attribute" address string
// from an EPathResult, e.g. "0x04/10/3". Fields that are zero are still included
// so that the learner always sees a consistent three-part address.
func FormatAddress(r EPathResult) string {
	return fmt.Sprintf("0x%02X/%d/%d", r.ClassID, r.InstanceID, r.AttributeID)
}

// maxMSPServices caps the number of sub-services parsed from a Multiple_Service_Packet
// to bound CPU in the NFQUEUE hot path.
const maxMSPServices = 32

// SubService represents a single CIP service extracted from a Multiple_Service_Packet.
type SubService struct {
	ServiceCode uint8
	ServiceName string
	IsWrite     bool
	IsControl   bool
	Path        []byte
}

// ParseMSPServices parses individual sub-services from MSP data (the Data
// field of a CIP message with service code 0x0A). The data layout is:
//
//	uint16  service_count
//	uint16  offset[service_count]   (each relative to start of data)
//	...     service payloads
//
// Returns nil if the data is malformed or too short.
func ParseMSPServices(data []byte) []SubService {
	if len(data) < 2 {
		return nil
	}
	count := int(binary.LittleEndian.Uint16(data[0:2]))
	if count == 0 {
		return nil
	}
	if count > maxMSPServices {
		count = maxMSPServices
	}

	// Validate that the offset table fits.
	offsetTableEnd := 2 + count*2
	if offsetTableEnd > len(data) {
		return nil
	}

	// Read offsets.
	offsets := make([]uint16, count)
	for i := 0; i < count; i++ {
		offsets[i] = binary.LittleEndian.Uint16(data[2+i*2 : 2+i*2+2])
	}

	subs := make([]SubService, 0, count)
	for i := 0; i < count; i++ {
		off := int(offsets[i])
		if off >= len(data) || off+2 > len(data) {
			continue // skip malformed entry
		}

		// Determine the end of this sub-service payload.
		var end int
		if i+1 < count {
			end = int(offsets[i+1])
		} else {
			end = len(data)
		}
		if end > len(data) || end <= off {
			end = len(data)
		}

		subData := data[off:end]
		if len(subData) < 2 {
			continue
		}

		serviceCode := subData[0] & 0x7F
		pathSize := subData[1]
		pathBytes := int(pathSize) * 2

		sub := SubService{
			ServiceCode: serviceCode,
			ServiceName: ServiceName(serviceCode),
			IsWrite:     IsWriteService(serviceCode),
			IsControl:   IsControlService(serviceCode),
		}

		cursor := 2
		if pathBytes > 0 && cursor+pathBytes <= len(subData) {
			sub.Path = subData[cursor : cursor+pathBytes]
		}

		subs = append(subs, sub)
	}

	if len(subs) == 0 {
		return nil
	}
	return subs
}

// ParseEIPHeader parses an EtherNet/IP encapsulation header from raw bytes.
func ParseEIPHeader(data []byte) (*EIPHeader, error) {
	if len(data) < eipHeaderSize {
		return nil, ErrTooShort
	}
	command := binary.LittleEndian.Uint16(data[0:2])
	length := binary.LittleEndian.Uint16(data[2:4])
	sessionHandle := binary.LittleEndian.Uint32(data[4:8])
	status := binary.LittleEndian.Uint32(data[8:12])
	var senderCtx [8]byte
	copy(senderCtx[:], data[12:20])
	options := binary.LittleEndian.Uint32(data[20:24])

	hdr := &EIPHeader{
		Command:       command,
		Length:        length,
		SessionHandle: sessionHandle,
		Status:        status,
		SenderContext: senderCtx,
		Options:       options,
	}

	if length > 0 {
		end := eipHeaderSize + int(length)
		if len(data) < end {
			return nil, ErrTruncated
		}
		hdr.Data = data[eipHeaderSize:end]
	}

	return hdr, nil
}

// ParseCIPMessage extracts a CIP message from the data portion of a
// SendRRData or SendUnitData encapsulation. The data layout is:
//   Interface handle (4) + Timeout (2) + Item count (2) + Items...
// Each item: Type ID (2) + Length (2) + Data (Length bytes)
// We look for Unconnected Data Item (0x00B2) or Connected Data Item (0x00B1).
func ParseCIPMessage(data []byte) (*CIPMessage, error) {
	// Minimum: interface(4) + timeout(2) + count(2) = 8
	if len(data) < 8 {
		return nil, ErrCIPTooShort
	}
	// interfaceHandle := binary.LittleEndian.Uint32(data[0:4])
	// timeout := binary.LittleEndian.Uint16(data[4:6])
	itemCount := binary.LittleEndian.Uint16(data[6:8])

	offset := 8
	for i := 0; i < int(itemCount); i++ {
		if offset+4 > len(data) {
			return nil, ErrCIPTooShort
		}
		typeID := binary.LittleEndian.Uint16(data[offset : offset+2])
		itemLen := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(itemLen) > len(data) {
			return nil, ErrTruncated
		}

		// Unconnected Data Item (0x00B2) or Connected Data Item (0x00B1)
		if typeID == 0x00B2 || typeID == 0x00B1 {
			itemData := data[offset : offset+int(itemLen)]
			return parseCIPFromItem(itemData)
		}

		offset += int(itemLen)
	}

	return nil, ErrNoCIPPayload
}

// parseCIPFromItem parses the CIP service header from an item's data.
func parseCIPFromItem(data []byte) (*CIPMessage, error) {
	if len(data) < 2 {
		return nil, ErrCIPTooShort
	}
	serviceCode := data[0]
	isResponse := (serviceCode & 0x80) != 0
	baseCode := serviceCode & 0x7F

	pathSize := data[1] // path size in 16-bit words
	pathBytes := int(pathSize) * 2

	msg := &CIPMessage{
		ServiceCode: baseCode,
		ServiceName: ServiceName(baseCode),
		IsResponse:  isResponse,
	}

	offset := 2
	if pathBytes > 0 && offset+pathBytes <= len(data) {
		msg.Path = data[offset : offset+pathBytes]
		offset += pathBytes
	}

	if offset < len(data) {
		msg.Data = data[offset:]
	}

	return msg, nil
}
