// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
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
	ServiceCode uint8
	ServiceName string
	IsResponse  bool
	Path        []byte
	Data        []byte
	Response    *ResponseHeader
	Conformance []string
}

// ResponseHeader retains every complete wire field, including a partial
// additional-status tail. Nil pointers mean the field was not available.
type ResponseHeader struct {
	Reserved         *uint8
	GeneralStatus    *uint8
	AdditionalCount  *uint8
	AdditionalStatus []uint16
}

// commandNames maps EtherNet/IP encapsulation command codes to names.
var commandNames = map[uint16]string{
	0x0000: "NOP",
	0x0004: "ListServices",
	0x0063: "ListIdentity",
	0x0064: "ListInterfaces",
	0x0065: "RegisterSession",
	0x0066: "UnregisterSession",
	0x006F: "SendRRData",
	0x0070: "SendUnitData",
	0x0072: "IndicateStatus",
	0x0073: "Cancel",
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
	ClassID         uint16
	InstanceID      uint16
	AttributeID     uint16
	MemberID        uint16
	ConnectionPoint uint16
	Conformance     []string
	Undecoded       []string
	Raw             []byte
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
	r.ConnectionPoint, _ = attrs["connection_point"].(uint16)
	r.Conformance, _ = eventfields.Strings(attrs, eventfields.KeyConformance)
	r.Undecoded, _ = eventfields.Strings(attrs, eventfields.KeyUndecoded)
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

// ExplicitResult retains both CPF provenance and message-header parsing errors.
// A readable selected message never hides a later malformed CPF item.
type ExplicitResult struct {
	CPF          CPFResult
	Message      *CIPMessage
	MessageError error
}

// ParseCIPMessage extracts a CIP message from the data portion of a
// SendRRData or SendUnitData encapsulation. The data layout is:
//
//	Interface handle (4) + Timeout (2) + Item count (2) + Items...
//
// Each item: Type ID (2) + Length (2) + Data (Length bytes)
// We look for Unconnected Data Item (0x00B2) or Connected Data Item (0x00B1).
func ParseCIPMessage(data []byte) ExplicitResult {
	result := ExplicitResult{CPF: parseCPF(data)}
	if result.CPF.Selected >= 0 {
		result.Message, result.MessageError = parseCIPFromItem(result.CPF.Payload)
	}
	return result
}

// parseCIPFromItem parses the CIP service header from an item's data.
func parseCIPFromItem(data []byte) (*CIPMessage, error) {
	if len(data) == 0 {
		return nil, ErrCIPTooShort
	}
	code := data[0] & 0x7f
	msg := &CIPMessage{ServiceCode: code, ServiceName: ServiceName(code), IsResponse: data[0]&0x80 != 0}
	if msg.IsResponse {
		r := &ResponseHeader{}
		msg.Response = r
		if len(data) >= 2 {
			r.Reserved = &data[1]
			if data[1] != 0 {
				msg.Conformance = append(msg.Conformance, "cip.response_reserved")
			}
		}
		if len(data) >= 3 {
			r.GeneralStatus = &data[2]
		}
		if len(data) < 4 {
			return msg, ErrCIPTooShort
		}
		r.AdditionalCount = &data[3]
		offset := 4 + 2*int(data[3])
		r.AdditionalStatus = make([]uint16, 0, data[3])
		for i := 4; i+2 <= min(offset, len(data)); i += 2 {
			r.AdditionalStatus = append(r.AdditionalStatus, binary.LittleEndian.Uint16(data[i:i+2]))
		}
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
