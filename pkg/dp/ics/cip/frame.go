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

// maxStreamFrameSize matches the DPI manager's 64 KiB per-direction
// reassembly bound, including the encapsulation header.
const maxStreamFrameSize = 64 * 1024

// frameEncapsulation returns nil without an error for an incomplete header
// or body. Command codes and inner payload validity do not affect framing.
func frameEncapsulation(data []byte) (*EIPHeader, error) {
	if len(data) < eipHeaderSize {
		return nil, nil
	}
	size := eipHeaderSize + int(binary.LittleEndian.Uint16(data[2:4]))
	if size > maxStreamFrameSize {
		return nil, fmt.Errorf("EtherNet/IP frame length %d exceeds reassembly bound %d", size, maxStreamFrameSize)
	}
	if len(data) < size {
		return nil, nil
	}
	return ParseEIPHeader(data[:size])
}

var (
	ErrTooShort      = errors.New("EtherNet/IP frame too short")
	ErrTruncated     = errors.New("EtherNet/IP frame truncated")
	ErrNoCIPPayload  = errors.New("no CIP payload in encapsulation")
	ErrInvalidCPF    = errors.New("invalid CPF layout")
	ErrPathTruncated = errors.New("CIP path truncated")
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
	status      uint8
	hasStatus   bool
	ServiceCode uint8
	ServiceName string
	IsResponse  bool
	Path        []byte
	Data        []byte
}

// commandNames maps EtherNet/IP encapsulation command codes to names.
var commandNames = map[uint16]string{
	0x0000: "NOP",
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

// ParseEPath extracts complete recognized EPATH segments, stopping at the first
// unsupported or truncated segment rather than guessing subsequent offsets.
func ParseEPath(data []byte) EPathResult {
	attrs := make(map[string]any)
	addPathFields(data, attrs)
	r := EPathResult{Raw: data}
	r.ClassID, _ = attrs["object_class"].(uint16)
	r.InstanceID, _ = attrs["instance_id"].(uint16)
	r.AttributeID, _ = attrs["attribute_id"].(uint16)
	r.MemberID, _ = attrs["member_id"].(uint16)
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
	status      uint8
	hasStatus   bool
	findings    []string
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
	subs, _ := parseMSPServices(data)
	return subs
}

func parseMSPServices(data []byte) ([]SubService, bool) {
	if len(data) < 2 {
		return nil, true
	}
	total := int(binary.LittleEndian.Uint16(data[:2]))
	tableEnd := 2 + total*2
	if total == 0 || tableEnd > len(data) {
		return nil, true
	}
	count := min(total, maxMSPServices)
	stopped := total > count
	subs := make([]SubService, 0, count)
	for i := 0; i < count; i++ {
		off := int(binary.LittleEndian.Uint16(data[2+2*i : 4+2*i]))
		end := len(data)
		if i+1 < total {
			end = int(binary.LittleEndian.Uint16(data[4+2*i : 6+2*i]))
		}
		if off < tableEnd || end <= off || end > len(data) {
			stopped = true
			continue
		}
		msg, err := parseCIPFromItem(data[off:end])
		if msg == nil {
			stopped = true
			continue
		}
		sub := SubService{
			ServiceCode: msg.ServiceCode, ServiceName: msg.ServiceName,
			IsWrite: IsWriteService(msg.ServiceCode), IsControl: IsControlService(msg.ServiceCode),
			Path: msg.Path, status: msg.status, hasStatus: msg.hasStatus,
		}
		if err != nil {
			code := "cip.message_short"
			if errors.Is(err, ErrPathTruncated) {
				code = "cip.epath_truncated"
			}
			sub.findings = []string{code}
		}
		subs = append(subs, sub)
	}
	if len(subs) == 0 {
		return nil, stopped
	}
	return subs, stopped
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
//
//	Interface handle (4) + Timeout (2) + Item count (2) + Items...
//
// Each item: Type ID (2) + Length (2) + Data (Length bytes)
// We look for Unconnected Data Item (0x00B2) or Connected Data Item (0x00B1).
func ParseCIPMessage(data []byte) (*CIPMessage, error) {
	_, item, err := parseCPF(data)
	if item != nil {
		return parseCIPFromItem(item)
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrNoCIPPayload
}

// parseCPF walks the complete item list, retaining the first CIP data item.
// Item payload parsing is deliberately separate from CPF framing validation.
// A malformed later item retains both earlier types and the first CIP payload.
func parseCPF(data []byte) ([]string, []byte, error) {
	var cipItem []byte
	types := make([]string, 0)
	// Minimum: interface(4) + timeout(2) + count(2) = 8
	if len(data) < 8 {
		return types, cipItem, ErrCIPTooShort
	}
	types, cipItem, err := parseItems(data, 8, int(binary.LittleEndian.Uint16(data[6:8])))
	if err == nil && binary.LittleEndian.Uint32(data[:4]) != 0 {
		err = ErrInvalidCPF
	}
	return types, cipItem, err
}

func parseItems(data []byte, offset, count int) ([]string, []byte, error) {
	var cipItem []byte
	types := make([]string, 0)

	for i := 0; i < count; i++ {
		if offset+4 > len(data) {
			return types, cipItem, ErrCIPTooShort
		}
		typeID := binary.LittleEndian.Uint16(data[offset : offset+2])
		itemLen := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		types = append(types, fmt.Sprintf("0x%04x", typeID))
		if offset+int(itemLen) > len(data) {
			return types, cipItem, ErrTruncated
		}
		if cipItem == nil && (typeID == 0x00B2 || typeID == 0x00B1) {
			cipItem = data[offset : offset+int(itemLen)]
			if typeID == 0x00b1 {
				if len(cipItem) < 2 {
					return types, []byte{}, ErrCIPTooShort
				}
				cipItem = cipItem[2:] // connected explicit message sequence count
			}
		}
		offset += int(itemLen)
	}
	if offset != len(data) {
		return types, cipItem, ErrInvalidCPF
	}
	return types, cipItem, nil
}

// parseCIPFromItem parses the CIP service header from an item's data.
func parseCIPFromItem(data []byte) (*CIPMessage, error) {
	if len(data) == 0 {
		return nil, ErrCIPTooShort
	}
	code := data[0] & 0x7f
	msg := &CIPMessage{ServiceCode: code, ServiceName: ServiceName(code), IsResponse: data[0]&0x80 != 0}
	if msg.IsResponse {
		if len(data) >= 3 {
			msg.status, msg.hasStatus = data[2], true
		}
		if len(data) < 4 {
			return msg, ErrCIPTooShort
		}
		offset := 4 + 2*int(data[3]) // reserved, general status, additional status words
		if offset > len(data) {
			return msg, ErrCIPTooShort
		}
		msg.Data = data[offset:]
		return msg, nil
	}
	if len(data) < 2 {
		return msg, ErrCIPTooShort
	}
	pathBytes := int(data[1]) * 2
	if 2+pathBytes > len(data) {
		msg.Path = data[2:]
		return msg, ErrPathTruncated
	}
	msg.Path = data[2 : 2+pathBytes]
	msg.Data = data[2+pathBytes:]
	return msg, nil
}
