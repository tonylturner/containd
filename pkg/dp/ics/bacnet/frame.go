// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package bacnet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// BVLC function codes.
const (
	BVLCResult            = 0x00
	BVLCForwardedNPDU     = 0x04
	BVLCOriginalUnicast   = 0x0A
	BVLCOriginalBroadcast = 0x0B
)

// APDU PDU types (upper 4 bits).
const (
	PDUConfirmedRequest   = 0x0
	PDUUnconfirmedRequest = 0x1
	PDUSimpleACK          = 0x2
	PDUComplexACK         = 0x3
	PDUError              = 0x5
)

// Service choice values.
const (
	ServiceIAm                        = 0
	ServiceSubscribeCOV               = 5
	ServiceRemoveListElement          = 6
	ServiceWhoHas                     = 7
	ServiceCreateObject               = 8 // confirmed service choice 8
	ServiceWhoIs                      = 8 // unconfirmed service choice 8
	ServiceDeleteObject               = 9
	ServiceReadProperty               = 12
	ServiceReadPropertyMultiple       = 14
	ServiceWriteProperty              = 15
	ServiceWritePropertyMultiple      = 16
	ServiceDeviceCommunicationControl = 17
	ServiceReinitializeDevice         = 20
	ServiceReadRange                  = 26
)

// objectTypeNames maps BACnet object type IDs to names.
var objectTypeNames = map[uint16]string{
	0:  "analog_input",
	1:  "analog_output",
	2:  "analog_value",
	3:  "binary_input",
	4:  "binary_output",
	5:  "binary_value",
	8:  "device",
	10: "file",
	13: "multi_state_input",
	14: "multi_state_output",
	19: "multi_state_value",
}

// propertyNames maps BACnet property IDs to names.
var propertyNames = map[uint8]string{
	28:  "description",
	77:  "object_name",
	85:  "present_value",
	103: "reliability",
	111: "status_flags",
}

// ObjectTypeName returns a human-readable name for a BACnet object type.
func ObjectTypeName(objType uint16) string {
	if name, ok := objectTypeNames[objType]; ok {
		return name
	}
	return fmt.Sprintf("object_type_%d", objType)
}

// PropertyName returns a human-readable name for a BACnet property ID.
func PropertyName(propID uint8) string {
	if name, ok := propertyNames[propID]; ok {
		return name
	}
	return fmt.Sprintf("property_%d", propID)
}

var (
	ErrTooShort    = errors.New("bacnet frame too short")
	ErrInvalidType = errors.New("bacnet invalid BVLC type")
)

// Frame represents a parsed BACnet/IP frame (BVLC + NPDU + APDU headers).
type Frame struct {
	// BVLC fields
	BVLCType     uint8
	BVLCFunction uint8
	BVLCLength   uint16

	// NPDU fields
	NPDUVersion uint8
	NPDUControl uint8

	// APDU fields (only populated when APDU is present)
	HasAPDU       bool
	PDUType       uint8 // upper 4 bits
	ServiceChoice uint8

	// Parsed property fields for ReadProperty/WriteProperty
	HasObjectInfo  bool
	ObjectType     uint16
	ObjectInstance uint32
	HasPropertyID  bool
	PropertyID     uint8
	IsCritical     bool // DeviceCommunicationControl, ReinitializeDevice
}

// ParseFrame parses a BACnet/IP frame from raw UDP payload bytes.
func ParseFrame(b []byte) (*Frame, error) {
	if len(b) < 4 {
		return nil, ErrTooShort
	}

	f := &Frame{
		BVLCType:     b[0],
		BVLCFunction: b[1],
		BVLCLength:   binary.BigEndian.Uint16(b[2:4]),
	}

	if f.BVLCType != 0x81 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidType, f.BVLCType)
	}

	npduOffset := bacnetNPDUOffset(f.BVLCFunction)
	if len(b) < npduOffset+2 {
		return f, nil
	}

	f.NPDUVersion = b[npduOffset]
	f.NPDUControl = b[npduOffset+1]

	apduOffset, ok := bacnetAPDUOffset(b, npduOffset, f.NPDUControl)
	if !ok || f.NPDUControl&0x80 != 0 {
		return f, nil
	}
	if len(b) <= apduOffset {
		return f, nil
	}

	f.HasAPDU = true
	f.PDUType = (b[apduOffset] >> 4) & 0x0F
	f.ServiceChoice = bacnetServiceChoice(b, apduOffset, f.PDUType)
	applyBACnetCriticalFlags(f)
	parseBACnetPropertyRequest(b, apduOffset, f)
	return f, nil
}

func bacnetNPDUOffset(fn uint8) int {
	if fn == BVLCForwardedNPDU {
		return 10
	}
	return 4
}

func bacnetAPDUOffset(b []byte, npduOffset int, ctrl uint8) (int, bool) {
	apduOffset := npduOffset + 2
	var ok bool
	apduOffset, ok = skipBACnetDNET(b, apduOffset, ctrl)
	if !ok {
		return 0, false
	}
	apduOffset, ok = skipBACnetSNET(b, apduOffset, ctrl)
	return apduOffset, ok
}

func skipBACnetDNET(b []byte, apduOffset int, ctrl uint8) (int, bool) {
	if ctrl&0x20 == 0 {
		return apduOffset, true
	}
	if len(b) < apduOffset+3 {
		return 0, false
	}
	apduOffset += 2
	dlen := int(b[apduOffset])
	apduOffset++
	apduOffset += dlen
	if len(b) > apduOffset {
		apduOffset++
	}
	return apduOffset, true
}

func skipBACnetSNET(b []byte, apduOffset int, ctrl uint8) (int, bool) {
	if ctrl&0x08 == 0 {
		return apduOffset, true
	}
	if len(b) < apduOffset+3 {
		return 0, false
	}
	apduOffset += 2
	slen := int(b[apduOffset])
	apduOffset++
	apduOffset += slen
	return apduOffset, true
}

func bacnetServiceChoice(b []byte, apduOffset int, pduType uint8) uint8 {
	switch pduType {
	case PDUConfirmedRequest:
		if len(b) > apduOffset+3 {
			return b[apduOffset+3]
		}
	case PDUUnconfirmedRequest:
		if len(b) > apduOffset+1 {
			return b[apduOffset+1]
		}
	case PDUSimpleACK, PDUComplexACK, PDUError:
		if len(b) > apduOffset+2 {
			return b[apduOffset+2]
		}
	}
	return 0
}

func applyBACnetCriticalFlags(f *Frame) {
	if f.PDUType != PDUConfirmedRequest {
		return
	}
	switch f.ServiceChoice {
	case ServiceDeviceCommunicationControl, ServiceReinitializeDevice:
		f.IsCritical = true
	}
}

func parseBACnetPropertyRequest(b []byte, apduOffset int, f *Frame) {
	if f.PDUType != PDUConfirmedRequest {
		return
	}
	if f.ServiceChoice != ServiceReadProperty && f.ServiceChoice != ServiceWriteProperty {
		return
	}
	parsePropertyRequest(b, apduOffset+4, f)
}

// parsePropertyRequest extracts object type, instance, and property ID from
// a ReadProperty or WriteProperty service request using BACnet context tags.
// This avoids allocations — all work is done on the raw slice.
func parsePropertyRequest(b []byte, offset int, f *Frame) {
	if offset >= len(b) {
		return
	}

	// Context tag 0: Object Identifier (4 bytes of content).
	// Tag format: high nibble = tag number, bit 3 = context(1)/app(0),
	// bits 0-2 = length (or 5 if extended).
	if offset < len(b) {
		tag := b[offset]
		tagNum := (tag >> 4) & 0x0F
		isContext := (tag & 0x08) != 0
		tagLen := int(tag & 0x07)

		if isContext && tagNum == 0 && tagLen == 4 && offset+5 <= len(b) {
			// Object identifier: 10-bit type + 22-bit instance packed in 4 bytes (big-endian).
			oid := binary.BigEndian.Uint32(b[offset+1 : offset+5])
			f.ObjectType = uint16(oid >> 22)
			f.ObjectInstance = oid & 0x003FFFFF
			f.HasObjectInfo = true
			offset += 5

			// Context tag 1: Property Identifier (typically 1 byte of content).
			if offset < len(b) {
				tag2 := b[offset]
				tagNum2 := (tag2 >> 4) & 0x0F
				isContext2 := (tag2 & 0x08) != 0
				tagLen2 := int(tag2 & 0x07)

				if isContext2 && tagNum2 == 1 && tagLen2 >= 1 && offset+1+tagLen2 <= len(b) {
					f.PropertyID = b[offset+1]
					f.HasPropertyID = true
				}
			}
		}
	}
}

// ServiceName returns a human-readable name for common BACnet service choices.
func ServiceName(pduType, service uint8) string {
	if pduType == PDUUnconfirmedRequest {
		switch service {
		case ServiceIAm:
			return "i-am"
		case ServiceWhoIs: // == 8
			return "who-is"
		case ServiceWhoHas:
			return "who-has"
		}
	}
	// For confirmed services, service 8 = CreateObject (distinct from unconfirmed WhoIs).
	if pduType == PDUConfirmedRequest && service == ServiceCreateObject {
		return "create-object"
	}
	switch service {
	case ServiceSubscribeCOV:
		return "subscribe-cov"
	case ServiceRemoveListElement:
		return "remove-list-element"
	case ServiceDeleteObject:
		return "delete-object"
	case ServiceReadProperty:
		return "read-property"
	case ServiceReadPropertyMultiple:
		return "read-property-multiple"
	case ServiceWriteProperty:
		return "write-property"
	case ServiceWritePropertyMultiple:
		return "write-property-multiple"
	case ServiceDeviceCommunicationControl:
		return "device-communication-control"
	case ServiceReinitializeDevice:
		return "reinitialize-device"
	case ServiceReadRange:
		return "read-range"
	default:
		return fmt.Sprintf("service-%d", service)
	}
}

// IsWriteService returns true for BACnet services that mutate state.
func IsWriteService(service uint8) bool {
	switch service {
	case ServiceWriteProperty, ServiceWritePropertyMultiple,
		ServiceRemoveListElement, ServiceDeleteObject,
		ServiceDeviceCommunicationControl, ServiceReinitializeDevice:
		return true
	default:
		return false
	}
}

// IsCriticalService returns true for BACnet services considered critical control operations.
func IsCriticalService(service uint8) bool {
	switch service {
	case ServiceDeviceCommunicationControl, ServiceReinitializeDevice:
		return true
	default:
		return false
	}
}

// IsDiscoveryService returns true for BACnet discovery services (unconfirmed).
func IsDiscoveryService(pduType, service uint8) bool {
	if pduType != PDUUnconfirmedRequest {
		return false
	}
	switch service {
	case ServiceWhoIs, ServiceIAm, ServiceWhoHas:
		return true
	default:
		return false
	}
}
