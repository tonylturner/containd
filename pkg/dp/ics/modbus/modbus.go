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

var (
	ErrTooShort = errors.New("modbus tcp frame too short")
)

// ParseTCPFrame parses a Modbus/TCP frame from raw bytes.
// The frame should start with the MBAP header.
func ParseTCPFrame(b []byte) (*TCPFrame, error) {
	if len(b) < 8 {
		return nil, ErrTooShort
	}
	tid := binary.BigEndian.Uint16(b[0:2])
	pid := binary.BigEndian.Uint16(b[2:4])
	length := binary.BigEndian.Uint16(b[4:6])
	unitID := b[6]
	if length < 2 {
		return nil, fmt.Errorf("invalid length %d", length)
	}
	// length counts unit id + pdu bytes. We already consumed unit id.
	pduLen := int(length) - 1
	if len(b[7:]) < pduLen {
		return nil, fmt.Errorf("truncated frame: want %d pdu bytes, have %d", pduLen, len(b[7:]))
	}
	pdu := b[7 : 7+pduLen]
	fc := pdu[0]
	return &TCPFrame{
		TransactionID: tid,
		ProtocolID:    pid,
		Length:        length,
		UnitID:        unitID,
		FunctionCode:  fc,
		PDU:           pdu[1:],
	}, nil
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

