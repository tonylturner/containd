// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"errors"
	"fmt"
	"strings"
)

// DNP3Frame represents a parsed DNP3 data-link layer frame.
type DNP3Frame struct {
	badDataCRC   bool
	Length       uint8  // Data length (excluding start, length, CRC)
	Control      uint8  // Control byte
	Destination  uint16 // Destination address (little-endian)
	Source       uint16 // Source address (little-endian)
	FunctionCode uint8  // Application layer function code (0 if not available)
	Data         []byte // Payload after data-link header (CRC-stripped user data)
}

// DataCRCValid reports whether all data-block CRCs passed when ParseFrame
// decoded this frame. Link-only frames have no data blocks and return true.
// It says nothing about the application payload's validity.
func (f *DNP3Frame) DataCRCValid() bool {
	return f != nil && !f.badDataCRC
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
	FuncImmediateFreeze     = 0x07
	FuncImmediateFreezeNR   = 0x08
	FuncFreezeClear         = 0x09
	FuncFreezeClearNR       = 0x0A
	FuncColdRestart         = 0x0D
	FuncWarmRestart         = 0x0E
	FuncStopApplication     = 0x12
	FuncSaveConfiguration   = 0x13
	FuncEnableUnsolicited   = 0x14
	FuncDisableUnsolicited  = 0x15
	FuncAssignClass         = 0x16
	FuncResponse            = 0x81
	FuncUnsolicitedResponse = 0x82
)

var (
	ErrTooShort     = errors.New("dnp3 frame too short")
	ErrInvalidStart = errors.New("dnp3 invalid start bytes")
	ErrBadHeaderCRC = errors.New("dnp3 header CRC mismatch")
	ErrBadLength    = errors.New("dnp3 link length below 5")
)

type accessCategory uint8

const (
	accessUnknown accessCategory = iota
	accessRead
	accessWrite
	accessControl
)

type functionDefinition struct {
	name   string
	access accessCategory
}

// IEEE 1815 application functions. The read allowlist includes confirmation
// and delay measurement, not just data reads. Known
// responses retain their historical non-write classification; this table does
// not infer their access from a correlated request.
var applicationFunctions = map[uint8]functionDefinition{
	0:   {"confirm", accessRead},
	1:   {"read", accessRead},
	2:   {"write", accessWrite},
	3:   {"select", accessControl},
	4:   {"operate", accessControl},
	5:   {"direct_operate", accessControl},
	6:   {"direct_operate_no_ack", accessControl},
	7:   {"immediate_freeze", accessControl},
	8:   {"immediate_freeze_no_ack", accessControl},
	9:   {"freeze_clear", accessControl},
	10:  {"freeze_clear_no_ack", accessControl},
	11:  {"freeze_at_time", accessControl},
	12:  {"freeze_at_time_no_ack", accessControl},
	13:  {"cold_restart", accessControl},
	14:  {"warm_restart", accessControl},
	15:  {"initialize_data", accessControl},
	16:  {"initialize_application", accessControl},
	17:  {"start_application", accessControl},
	18:  {"stop_application", accessControl},
	19:  {"save_configuration", accessControl},
	20:  {"enable_unsolicited", accessControl},
	21:  {"disable_unsolicited", accessControl},
	22:  {"assign_class", accessControl},
	23:  {"delay_measure", accessRead},
	24:  {"record_current_time", accessControl},
	25:  {"open_file", accessControl},
	26:  {"close_file", accessControl},
	27:  {"delete_file", accessControl},
	28:  {"get_file_info", accessControl},
	29:  {"authenticate_file", accessControl},
	30:  {"abort_file", accessControl},
	31:  {"activate_configuration", accessControl},
	32:  {"authenticate_request", accessControl},
	33:  {"authenticate_request_no_ack", accessControl},
	129: {"response", accessRead},
	130: {"unsolicited_response", accessRead},
	131: {"authenticate_response", accessRead},
}

// FunctionCodeName returns a human-readable name for a DNP3 function code.
func FunctionCodeName(fc uint8) string {
	if def, ok := applicationFunctions[fc]; ok {
		return def.name
	}
	return fmt.Sprintf("unknown_0x%02x", fc)
}

// IsWriteFunctionCode reports write/control operations. False is not proof of
// a read: an unlisted function has unknown access semantics.
func IsWriteFunctionCode(fc uint8) bool {
	access := applicationFunctions[fc].access
	return access == accessWrite || access == accessControl
}

// IsControlFunctionCode reports state-changing control operations.
func IsControlFunctionCode(fc uint8) bool {
	return applicationFunctions[fc].access == accessControl
}

// IsRestartFunctionCode returns true for restart function codes.
func IsRestartFunctionCode(fc uint8) bool {
	return fc == FuncColdRestart || fc == FuncWarmRestart
}

// IsResponse returns true if the function code indicates a response message.
func IsResponse(fc uint8) bool {
	return fc >= 0x80
}

// IIN bit definitions for DNP3 Internal Indications.
// IIN1 bits (first byte).
const (
	IINAllStations   = 0x01 // IIN1.0
	IINClass1        = 0x02 // IIN1.1
	IINClass2        = 0x04 // IIN1.2
	IINClass3        = 0x08 // IIN1.3
	IINNeedTime      = 0x10 // IIN1.4
	IINLocalControl  = 0x20 // IIN1.5
	IINDeviceTrouble = 0x40 // IIN1.6
	IINDeviceRestart = 0x80 // IIN1.7
)

// IIN2 bits (second byte).
const (
	IINNoFuncSupport    = 0x01 // IIN2.0
	IINObjectUnknown    = 0x02 // IIN2.1
	IINParameterError   = 0x04 // IIN2.2
	IINEventOverflow    = 0x08 // IIN2.3
	IINAlreadyExecuting = 0x10 // IIN2.4
	IINConfigCorrupt    = 0x20 // IIN2.5
)

// iinFlagName pairs for IIN1 byte.
var iin1Flags = [8]struct {
	mask uint8
	name string
}{
	{IINAllStations, "all_stations"},
	{IINClass1, "class_1"},
	{IINClass2, "class_2"},
	{IINClass3, "class_3"},
	{IINNeedTime, "need_time"},
	{IINLocalControl, "local_control"},
	{IINDeviceTrouble, "device_trouble"},
	{IINDeviceRestart, "device_restart"},
}

// iinFlagName pairs for IIN2 byte.
var iin2Flags = [6]struct {
	mask uint8
	name string
}{
	{IINNoFuncSupport, "no_func_support"},
	{IINObjectUnknown, "object_unknown"},
	{IINParameterError, "parameter_error"},
	{IINEventOverflow, "event_overflow"},
	{IINAlreadyExecuting, "already_executing"},
	{IINConfigCorrupt, "config_corrupt"},
}

// FormatIINFlags returns a comma-separated string of set IIN flags.
// Returns "" if no flags are set.
func FormatIINFlags(iin1, iin2 uint8) string {
	var b strings.Builder
	for i := range iin1Flags {
		if iin1&iin1Flags[i].mask != 0 {
			if b.Len() > 0 {
				b.WriteByte(',')
			}
			b.WriteString(iin1Flags[i].name)
		}
	}
	for i := range iin2Flags {
		if iin2&iin2Flags[i].mask != 0 {
			if b.Len() > 0 {
				b.WriteByte(',')
			}
			b.WriteString(iin2Flags[i].name)
		}
	}
	return b.String()
}

// IIN extracts Internal Indication bytes from response data.
// Returns (iin1, iin2, ok).
func (f *DNP3Frame) IIN() (uint8, uint8, bool) {
	if !IsResponse(f.FunctionCode) {
		return 0, 0, false
	}
	// Transport(1) + AppControl(1) + FuncCode(1) + IIN1(1) + IIN2(1) = need 5 bytes
	if len(f.Data) < 5 {
		return 0, 0, false
	}
	return f.Data[3], f.Data[4], true
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
