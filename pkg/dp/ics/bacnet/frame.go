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
	BVLCResult              = 0x00
	BVLCForwardedNPDU       = 0x04
	BVLCOriginalUnicast     = 0x0A
	BVLCOriginalBroadcast   = 0x0B
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
	ServiceIAm                       = 0
	ServiceSubscribeCOV              = 5
	ServiceRemoveListElement         = 6
	ServiceWhoHas                    = 7
	ServiceCreateObject              = 8 // confirmed service choice 8
	ServiceWhoIs                     = 8 // unconfirmed service choice 8
	ServiceDeleteObject              = 9
	ServiceReadProperty              = 12
	ServiceReadPropertyMultiple      = 14
	ServiceWriteProperty             = 15
	ServiceWritePropertyMultiple     = 16
	ServiceDeviceCommunicationControl = 17
	ServiceReinitializeDevice        = 20
	ServiceReadRange                 = 26
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
	ObjectInstance  uint32
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

	// Determine NPDU offset based on BVLC function.
	npduOffset := 4
	if f.BVLCFunction == BVLCForwardedNPDU {
		// Forwarded-NPDU includes 6 extra bytes (4-byte IP + 2-byte port).
		npduOffset = 10
	}

	if len(b) < npduOffset+2 {
		// No NPDU present; frame is BVLC-only (e.g., BVLC-Result).
		return f, nil
	}

	f.NPDUVersion = b[npduOffset]
	f.NPDUControl = b[npduOffset+1]

	// Parse variable-length NPDU header to find APDU start.
	apduOffset := npduOffset + 2
	ctrl := f.NPDUControl

	// DNET/DADR present (bit 5)
	if ctrl&0x20 != 0 {
		if len(b) < apduOffset+3 {
			return f, nil
		}
		// 2-byte DNET
		apduOffset += 2
		// 1-byte DLEN
		dlen := int(b[apduOffset])
		apduOffset++
		// DADR bytes
		apduOffset += dlen
		// 1-byte hop count
		if len(b) > apduOffset {
			apduOffset++
		}
	}

	// SNET/SADR present (bit 3)
	if ctrl&0x08 != 0 {
		if len(b) < apduOffset+3 {
			return f, nil
		}
		apduOffset += 2 // SNET
		slen := int(b[apduOffset])
		apduOffset++
		apduOffset += slen
	}

	// Check if APDU is present (bit 7 of control = 0 means APDU follows;
	// bit 7 = 1 means network-layer message).
	if ctrl&0x80 != 0 {
		// Network-layer message, no APDU.
		return f, nil
	}

	if len(b) <= apduOffset {
		return f, nil
	}

	f.HasAPDU = true
	f.PDUType = (b[apduOffset] >> 4) & 0x0F

	// Parse service choice based on PDU type.
	switch f.PDUType {
	case PDUConfirmedRequest:
		// Confirmed: byte0=type+flags, byte1=max-segs/max-resp, byte2=invoke-id, byte3=service
		if len(b) > apduOffset+3 {
			f.ServiceChoice = b[apduOffset+3]
		}
	case PDUUnconfirmedRequest:
		// Unconfirmed: byte0=type, byte1=service
		if len(b) > apduOffset+1 {
			f.ServiceChoice = b[apduOffset+1]
		}
	case PDUSimpleACK:
		// Simple-ACK: byte0=type, byte1=invoke-id, byte2=service
		if len(b) > apduOffset+2 {
			f.ServiceChoice = b[apduOffset+2]
		}
	case PDUComplexACK:
		// Complex-ACK: byte0=type+flags, byte1=invoke-id, byte2=service
		if len(b) > apduOffset+2 {
			f.ServiceChoice = b[apduOffset+2]
		}
	case PDUError:
		// Error: byte0=type, byte1=invoke-id, byte2=service
		if len(b) > apduOffset+2 {
			f.ServiceChoice = b[apduOffset+2]
		}
	}

	// Mark critical control operations.
	if f.PDUType == PDUConfirmedRequest {
		switch f.ServiceChoice {
		case ServiceDeviceCommunicationControl, ServiceReinitializeDevice:
			f.IsCritical = true
		}
	}

	// For ReadProperty/WriteProperty confirmed requests, parse object identifier
	// and property ID from the service request data.
	if f.PDUType == PDUConfirmedRequest &&
		(f.ServiceChoice == ServiceReadProperty || f.ServiceChoice == ServiceWriteProperty) {
		// Service data starts after the APDU header (4 bytes for confirmed request).
		svcDataOffset := apduOffset + 4
		parsePropertyRequest(b, svcDataOffset, f)
	}

	return f, nil
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
