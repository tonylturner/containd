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
	ServiceIAm                 = 0
	ServiceSubscribeCOV        = 5
	ServiceWhoHas              = 7
	ServiceWhoIs               = 8
	ServiceReadProperty        = 12
	ServiceReadPropertyMultiple = 14
	ServiceWriteProperty       = 15
	ServiceWritePropertyMultiple = 16
)

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

	return f, nil
}

// ServiceName returns a human-readable name for common BACnet service choices.
func ServiceName(pduType, service uint8) string {
	if pduType == PDUUnconfirmedRequest {
		switch service {
		case ServiceIAm:
			return "i-am"
		case ServiceWhoIs:
			return "who-is"
		case ServiceWhoHas:
			return "who-has"
		}
	}
	switch service {
	case ServiceReadProperty:
		return "read-property"
	case ServiceWriteProperty:
		return "write-property"
	case ServiceReadPropertyMultiple:
		return "read-property-multiple"
	case ServiceWritePropertyMultiple:
		return "write-property-multiple"
	case ServiceSubscribeCOV:
		return "subscribe-cov"
	default:
		return fmt.Sprintf("service-%d", service)
	}
}

// IsWriteService returns true for BACnet services that mutate state.
func IsWriteService(service uint8) bool {
	switch service {
	case ServiceWriteProperty, ServiceWritePropertyMultiple:
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
