// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DNP3 data-link start bytes.
const (
	startByte1 = 0x05
	startByte2 = 0x64
)

// DNP3Frame represents a parsed DNP3 data-link layer frame.
type DNP3Frame struct {
	Length       uint8  // Data length (excluding start, length, CRC)
	Control      uint8  // Control byte
	Destination  uint16 // Destination address (little-endian)
	Source       uint16 // Source address (little-endian)
	FunctionCode uint8  // Application layer function code (0 if not available)
	Data         []byte // Payload after data-link header (CRC-stripped user data)
}

// Control byte bit masks.
const (
	ControlDIR = 0x80 // Direction bit: 1 = master, 0 = outstation
	ControlPRM = 0x40 // Primary message bit
	ControlFCB = 0x20 // Frame count bit
	ControlFCV = 0x10 // Frame count valid / Data flow control
)

// Application layer function codes.
const (
	FuncConfirm             = 0x00
	FuncRead                = 0x01
	FuncWrite               = 0x02
	FuncSelect              = 0x03
	FuncOperate             = 0x04
	FuncDirectOperate       = 0x05
	FuncDirectOperateNoAck  = 0x06
	FuncColdRestart         = 0x0D
	FuncWarmRestart         = 0x0E
	FuncStopApplication     = 0x12
	FuncSaveConfiguration   = 0x13
	FuncEnableUnsolicited   = 0x15
	FuncDisableUnsolicited  = 0x16
	FuncResponse            = 0x81
	FuncUnsolicitedResponse = 0x82
)

var (
	ErrTooShort     = errors.New("dnp3 frame too short")
	ErrInvalidStart = errors.New("dnp3 invalid start bytes")
	ErrBadHeaderCRC = errors.New("dnp3 header CRC mismatch")
)

// FunctionCodeName returns a human-readable name for a DNP3 function code.
func FunctionCodeName(fc uint8) string {
	switch fc {
	case FuncConfirm:
		return "confirm"
	case FuncRead:
		return "read"
	case FuncWrite:
		return "write"
	case FuncSelect:
		return "select"
	case FuncOperate:
		return "operate"
	case FuncDirectOperate:
		return "direct_operate"
	case FuncDirectOperateNoAck:
		return "direct_operate_no_ack"
	case FuncColdRestart:
		return "cold_restart"
	case FuncWarmRestart:
		return "warm_restart"
	case FuncStopApplication:
		return "stop_application"
	case FuncSaveConfiguration:
		return "save_configuration"
	case FuncEnableUnsolicited:
		return "enable_unsolicited"
	case FuncDisableUnsolicited:
		return "disable_unsolicited"
	case FuncResponse:
		return "response"
	case FuncUnsolicitedResponse:
		return "unsolicited_response"
	default:
		return fmt.Sprintf("unknown_0x%02x", fc)
	}
}

// IsWriteFunctionCode returns true for function codes that mutate outstation state.
func IsWriteFunctionCode(fc uint8) bool {
	switch fc {
	case FuncWrite, FuncSelect, FuncOperate, FuncDirectOperate, FuncDirectOperateNoAck,
		FuncColdRestart, FuncWarmRestart, FuncStopApplication, FuncSaveConfiguration:
		return true
	default:
		return false
	}
}

// IsControlFunctionCode returns true for function codes that perform control operations.
func IsControlFunctionCode(fc uint8) bool {
	switch fc {
	case FuncSelect, FuncOperate, FuncDirectOperate, FuncDirectOperateNoAck,
		FuncColdRestart, FuncWarmRestart, FuncStopApplication:
		return true
	default:
		return false
	}
}

// IsResponse returns true if the function code indicates a response message.
func IsResponse(fc uint8) bool {
	return fc >= 0x80
}

// ParseFrame parses a DNP3 data-link layer frame from raw bytes.
// It validates start bytes and header CRC. Data block CRCs are skipped for simplicity.
func ParseFrame(data []byte) (*DNP3Frame, error) {
	// Minimum frame: 2 start + 1 length + 1 control + 2 dest + 2 src + 2 CRC = 10 bytes
	if len(data) < 10 {
		return nil, ErrTooShort
	}
	if data[0] != startByte1 || data[1] != startByte2 {
		return nil, ErrInvalidStart
	}

	length := data[2]
	control := data[3]
	destination := binary.LittleEndian.Uint16(data[4:6])
	source := binary.LittleEndian.Uint16(data[6:8])

	// Validate header CRC (bytes 0-7, CRC at 8-9).
	headerCRC := binary.LittleEndian.Uint16(data[8:10])
	calcCRC := crc16DNP3(data[0:8])
	if headerCRC != calcCRC {
		return nil, ErrBadHeaderCRC
	}

	frame := &DNP3Frame{
		Length:      length,
		Control:     control,
		Destination: destination,
		Source:      source,
	}

	// Extract user data from data blocks (each block is up to 16 data bytes + 2 CRC bytes).
	// The length field indicates the number of bytes of user data following the header
	// (control + destination + source = 5 bytes are included in length).
	if length < 5 {
		return frame, nil
	}
	userDataLen := int(length) - 5
	remaining := data[10:]
	var userData []byte
	bytesNeeded := userDataLen
	for bytesNeeded > 0 && len(remaining) > 0 {
		blockSize := bytesNeeded
		if blockSize > 16 {
			blockSize = 16
		}
		// Need blockSize data bytes + 2 CRC bytes.
		if len(remaining) < blockSize+2 {
			// Partial block — take what we can.
			userData = append(userData, remaining[:min(blockSize, len(remaining))]...)
			break
		}
		userData = append(userData, remaining[:blockSize]...)
		remaining = remaining[blockSize+2:] // skip CRC
		bytesNeeded -= blockSize
	}
	frame.Data = userData

	// Extract application layer function code from transport + application layer.
	// Transport header is 1 byte, then application header starts.
	// Application header: control byte, then function code.
	// For requests: 1 byte app control + function code at offset 1.
	// For responses: 1 byte app control + function code at offset 1, then 2 IIN bytes.
	if len(userData) >= 2 {
		// userData[0] = transport header (FIN, FIR, sequence)
		// userData[1] = application control byte
		// userData[2] = function code (if present)
		if len(userData) >= 3 {
			frame.FunctionCode = userData[2]
		}
	}

	return frame, nil
}

// ObjectGroup extracts the first object group number from the application data, if present.
// Returns 0 if not enough data.
func (f *DNP3Frame) ObjectGroup() uint8 {
	// Transport(1) + AppControl(1) + FuncCode(1) = 3 bytes before objects.
	// For responses, there are 2 additional IIN bytes.
	offset := 3
	if IsResponse(f.FunctionCode) {
		offset = 5 // +2 IIN bytes
	}
	if len(f.Data) > offset {
		return f.Data[offset]
	}
	return 0
}

// crc16DNP3 computes the DNP3 CRC-16 (polynomial 0x3D65, reflected).
func crc16DNP3(data []byte) uint16 {
	var crc uint16 = 0x0000
	for _, b := range data {
		crc = (crc >> 8) ^ crcTable[byte(crc)^b]
	}
	return ^crc
}

// Pre-computed CRC-16/DNP table (polynomial 0xA6BC, which is 0x3D65 reflected).
var crcTable = func() [256]uint16 {
	const poly = 0xA6BC
	var table [256]uint16
	for i := 0; i < 256; i++ {
		crc := uint16(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		table[i] = crc
	}
	return table
}()
