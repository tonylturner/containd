// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TCPFrame represents a parsed Modbus/TCP frame (MBAP + PDU).
type TCPFrame struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16 // bytes following (UnitID + PDU)
	UnitID        uint8
	FunctionCode  uint8
	PDU           []byte // PDU after function code
}

// MBAP framing (Modbus Messaging on TCP/IP Implementation Guide V1.0b,
// MBAP header): the length field counts the unit identifier and the PDU,
// and a PDU is at most 253 bytes, so an ADU is 6 + length bytes with length
// in 2..254.
const (
	mbapPrefixLen = 6 // transaction id, protocol id, length
	minMBAPLength = 2 // unit id + function code
	maxMBAPLength = 254
)

var (
	ErrTooShort = errors.New("modbus tcp frame too short")
)

// frameADU returns the length of the ADU at the start of b, 0 when b holds
// only part of one, or an error when b cannot start an ADU.
func frameADU(b []byte) (int, error) {
	if len(b) < mbapPrefixLen {
		return 0, nil
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < minMBAPLength || length > maxMBAPLength {
		return 0, fmt.Errorf("invalid MBAP length %d", length)
	}
	if len(b) < mbapPrefixLen+length {
		return 0, nil
	}
	return mbapPrefixLen + length, nil
}

// decodeADU decodes one complete ADU as framed by frameADU.
func decodeADU(adu []byte) *TCPFrame {
	pdu := adu[mbapPrefixLen+1:]
	return &TCPFrame{
		TransactionID: binary.BigEndian.Uint16(adu[0:2]),
		ProtocolID:    binary.BigEndian.Uint16(adu[2:4]),
		Length:        binary.BigEndian.Uint16(adu[4:6]),
		UnitID:        adu[mbapPrefixLen],
		FunctionCode:  pdu[0],
		PDU:           pdu[1:],
	}
}

// ParseTCPFrame parses the Modbus/TCP frame at the start of b, which must
// start with the MBAP header. Bytes after the frame are ignored.
func ParseTCPFrame(b []byte) (*TCPFrame, error) {
	n, err := frameADU(b)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrTooShort
	}
	return decodeADU(b[:n]), nil
}

// IsWriteFunctionCode returns true for Modbus function codes that mutate state.
func IsWriteFunctionCode(fc uint8) bool {
	switch fc {
	case 5, 6, 15, 16, 22, 23:
		return true
	default:
		return false
	}
}
