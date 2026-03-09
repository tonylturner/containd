// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package s7comm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TPKTHeader represents a TPKT header (RFC 1006) — 4 bytes wrapping ISO-on-TCP.
type TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Length   uint16 // total packet length including TPKT header
}

// COTPHeader represents a minimal COTP (ISO 8073) header.
type COTPHeader struct {
	Length  uint8 // header length minus 1
	PDUType uint8 // 0xE0=CR, 0xD0=CC, 0x0F=DT
}

// S7Header represents the S7comm protocol header.
type S7Header struct {
	ProtocolID  uint8  // always 0x32
	MessageType uint8  // 0x01=Job, 0x02=Ack, 0x03=Ack-Data, 0x07=Userdata
	Reserved    uint16
	PDUReference uint16
	ParamLength  uint16
	DataLength   uint16
	ErrorClass   uint8 // only present for Ack-Data (message type 0x03)
	ErrorCode    uint8 // only present for Ack-Data (message type 0x03)
}

// COTP PDU types.
const (
	COTPConnectionRequest = 0xE0
	COTPConnectionConfirm = 0xD0
	COTPData              = 0x0F
)

// S7comm message types.
const (
	MsgTypeJob     = 0x01
	MsgTypeAck     = 0x02
	MsgTypeAckData = 0x03
	MsgTypeUserdata = 0x07
)

// S7comm function codes.
const (
	FuncCPUServices      = 0x00
	FuncReadVar          = 0x04
	FuncWriteVar         = 0x05
	FuncRequestDownload  = 0x1A
	FuncDownloadBlock    = 0x1B
	FuncDownloadEnded    = 0x1C
	FuncStartUpload      = 0x1D
	FuncUpload           = 0x1E
	FuncEndUpload        = 0x1F
	FuncPLCControl       = 0x28
	FuncPLCStop          = 0x29
	FuncSetupCommunication = 0xF0
)

var (
	ErrTooShort       = errors.New("s7comm frame too short")
	ErrInvalidTPKT    = errors.New("s7comm invalid TPKT version")
	ErrInvalidCOTP    = errors.New("s7comm invalid COTP header")
	ErrInvalidS7Proto = errors.New("s7comm invalid protocol ID")
)

// FunctionCodeNames maps S7comm function codes to human-readable names.
var FunctionCodeNames = map[uint8]string{
	FuncCPUServices:        "cpu_services",
	FuncReadVar:            "read_var",
	FuncWriteVar:           "write_var",
	FuncRequestDownload:    "request_download",
	FuncDownloadBlock:      "download_block",
	FuncDownloadEnded:      "download_ended",
	FuncStartUpload:        "start_upload",
	FuncUpload:             "upload",
	FuncEndUpload:          "end_upload",
	FuncPLCControl:         "plc_control",
	FuncPLCStop:            "plc_stop",
	FuncSetupCommunication: "setup_communication",
}

// FunctionCodeName returns a human-readable name for an S7comm function code.
func FunctionCodeName(fc uint8) string {
	if name, ok := FunctionCodeNames[fc]; ok {
		return name
	}
	return fmt.Sprintf("unknown_0x%02x", fc)
}

// MessageTypeName returns a human-readable name for an S7comm message type.
func MessageTypeName(mt uint8) string {
	switch mt {
	case MsgTypeJob:
		return "job"
	case MsgTypeAck:
		return "ack"
	case MsgTypeAckData:
		return "ack_data"
	case MsgTypeUserdata:
		return "userdata"
	default:
		return fmt.Sprintf("unknown_0x%02x", mt)
	}
}

// IsWriteFunctionCode returns true for function codes that mutate PLC state.
func IsWriteFunctionCode(fc uint8) bool {
	switch fc {
	case FuncWriteVar, FuncRequestDownload, FuncDownloadBlock, FuncDownloadEnded,
		FuncPLCControl, FuncPLCStop:
		return true
	default:
		return false
	}
}

// IsControlFunctionCode returns true for function codes that perform control operations.
func IsControlFunctionCode(fc uint8) bool {
	switch fc {
	case FuncPLCControl, FuncPLCStop:
		return true
	default:
		return false
	}
}

// ParseTPKT parses a TPKT header from raw bytes and returns the header
// plus the remaining payload after the TPKT header.
func ParseTPKT(data []byte) (*TPKTHeader, []byte, error) {
	if len(data) < 4 {
		return nil, nil, ErrTooShort
	}
	version := data[0]
	if version != 0x03 {
		return nil, nil, ErrInvalidTPKT
	}
	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, nil, fmt.Errorf("s7comm TPKT length %d exceeds data length %d", length, len(data))
	}
	hdr := &TPKTHeader{
		Version:  version,
		Reserved: data[1],
		Length:   length,
	}
	return hdr, data[4:length], nil
}

// ParseCOTP parses a COTP header from raw bytes (after TPKT) and returns the
// header plus the remaining payload after the COTP header.
func ParseCOTP(data []byte) (*COTPHeader, []byte, error) {
	if len(data) < 2 {
		return nil, nil, ErrTooShort
	}
	hdrLen := data[0] // length of COTP header minus this length byte
	if int(hdrLen) >= len(data) {
		return nil, nil, ErrInvalidCOTP
	}
	pduType := data[1]
	hdr := &COTPHeader{
		Length:  hdrLen,
		PDUType: pduType,
	}
	// The COTP payload starts after (hdrLen + 1) bytes.
	return hdr, data[hdrLen+1:], nil
}

// ParseS7Header parses the S7comm header from the payload inside a COTP DT PDU.
func ParseS7Header(data []byte) (*S7Header, error) {
	// Minimum S7 header: 10 bytes (proto + msg type + reserved + pdu ref + param len + data len).
	if len(data) < 10 {
		return nil, ErrTooShort
	}
	if data[0] != 0x32 {
		return nil, ErrInvalidS7Proto
	}
	hdr := &S7Header{
		ProtocolID:   data[0],
		MessageType:  data[1],
		Reserved:     binary.BigEndian.Uint16(data[2:4]),
		PDUReference: binary.BigEndian.Uint16(data[4:6]),
		ParamLength:  binary.BigEndian.Uint16(data[6:8]),
		DataLength:   binary.BigEndian.Uint16(data[8:10]),
	}
	// Ack-Data (0x03) has 2 extra bytes: error class + error code.
	if hdr.MessageType == MsgTypeAckData {
		if len(data) < 12 {
			return nil, ErrTooShort
		}
		hdr.ErrorClass = data[10]
		hdr.ErrorCode = data[11]
	}
	return hdr, nil
}

// S7ParamFunctionCode extracts the function code from the S7 parameter block.
// The parameter block starts immediately after the S7 header.
func S7ParamFunctionCode(data []byte, hdr *S7Header) (uint8, bool) {
	// Determine offset past S7 header.
	offset := 10
	if hdr.MessageType == MsgTypeAckData {
		offset = 12
	}
	if hdr.ParamLength == 0 || len(data) <= offset {
		return 0, false
	}
	return data[offset], true
}

// S7 memory area codes.
const (
	AreaInputs     = 0x81
	AreaOutputs    = 0x82
	AreaFlags      = 0x83
	AreaDataBlocks = 0x84
	AreaCounter    = 0x85
	AreaTimer      = 0x86
)

// SyntaxS7ANY is the S7ANY addressing syntax ID.
const SyntaxS7ANY = 0x10

// S7VarItem represents a single variable item in a Read/Write Variable request.
type S7VarItem struct {
	TransportSize uint8
	Length        uint16
	DBNumber      uint16
	Area          uint8
	Address       uint32 // 3-byte bit-level address (byte*8 + bit)
}

// AreaName returns a human-readable name for an S7 memory area code.
func AreaName(area uint8) string {
	switch area {
	case AreaInputs:
		return "inputs"
	case AreaOutputs:
		return "outputs"
	case AreaFlags:
		return "flags"
	case AreaDataBlocks:
		return "data_blocks"
	case AreaCounter:
		return "counter"
	case AreaTimer:
		return "timer"
	default:
		return fmt.Sprintf("unknown_0x%02x", area)
	}
}

// FormatAddress formats a 3-byte bit-level address as "byte.bit".
func FormatAddress(addr uint32) string {
	byteAddr := addr / 8
	bitAddr := addr % 8
	return fmt.Sprintf("%d.%d", byteAddr, bitAddr)
}

// ParseS7VarItems parses variable items from the parameter block of a
// Read/Write Variable request. data is the full COTP payload, hdr is the
// parsed S7 header. Returns the items and the item count byte.
func ParseS7VarItems(data []byte, hdr *S7Header) ([]S7VarItem, uint8) {
	// Parameter block offset past S7 header.
	offset := 10
	if hdr.MessageType == MsgTypeAckData {
		offset = 12
	}
	// Minimum: FC(1) + ItemCount(1) = 2 bytes in parameter block.
	if int(hdr.ParamLength) < 2 || len(data) < offset+2 {
		return nil, 0
	}
	// data[offset] = function code (already parsed).
	itemCount := data[offset+1]
	if itemCount == 0 {
		return nil, 0
	}

	pos := offset + 2
	items := make([]S7VarItem, 0, itemCount)

	for i := uint8(0); i < itemCount; i++ {
		// Each item starts with: VarSpec(1) + AddrLen(1) + SyntaxID(1) = 3 bytes minimum.
		if pos+3 > len(data) {
			break
		}
		// varSpec := data[pos]
		addrLen := data[pos+1]
		syntaxID := data[pos+2]

		if syntaxID != SyntaxS7ANY {
			// Skip non-S7ANY items by their declared length.
			pos += int(addrLen) + 2 // addrLen + varSpec + addrLen byte itself
			continue
		}

		// S7ANY: TransportSize(1) + Length(2) + DBNumber(2) + Area(1) + Address(3) = 10 bytes after syntaxID.
		// Total from varSpec: 3 (header) + 9 (payload) = 12.
		if pos+12 > len(data) {
			break
		}
		item := S7VarItem{
			TransportSize: data[pos+3],
			Length:        binary.BigEndian.Uint16(data[pos+4 : pos+6]),
			DBNumber:      binary.BigEndian.Uint16(data[pos+6 : pos+8]),
			Area:          data[pos+8],
		}
		// 3-byte address (big-endian, bit-level).
		item.Address = uint32(data[pos+9])<<16 | uint32(data[pos+10])<<8 | uint32(data[pos+11])
		items = append(items, item)
		pos += 12
	}
	return items, itemCount
}
