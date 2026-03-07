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
	0x0E: "Get_Attribute_Single",
	0x10: "Set_Attribute_Single",
	0x4C: "Read_Tag_Service",
	0x4D: "Write_Tag_Service",
	0x4E: "Read_Modify_Write_Tag/Forward_Close",
	0x52: "Unconnected_Send",
	0x54: "Forward_Open",
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
	case 0x01, 0x0E, 0x4C:
		return true
	default:
		return false
	}
}

// IsWriteService returns true for CIP service codes classified as write/control operations.
func IsWriteService(code uint8) bool {
	base := code & 0x7F
	switch base {
	case 0x10, 0x4D, 0x4E:
		return true
	default:
		return false
	}
}

// IsControlService returns true for CIP connection management service codes.
func IsControlService(code uint8) bool {
	base := code & 0x7F
	switch base {
	case 0x54:
		return true
	default:
		return false
	}
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
