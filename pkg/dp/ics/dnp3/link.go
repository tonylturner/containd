// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import "encoding/binary"

// Data link layer frame (IEEE 1815-2012 data link layer frame format): start
// octets 0x05 0x64, a length octet that counts control, destination and
// source (5 octets) plus the user data, then control, destination, source
// and a header CRC. User data follows in blocks of up to 16 octets, each
// with its own CRC. The length octet is 5..255, so a frame is 10..292 octets.
const (
	startByte1 = 0x05
	startByte2 = 0x64

	linkHeaderLen = 10 // start(2) length(1) control(1) dest(2) src(2) crc(2)
	linkFixedLen  = 5  // control + destination + source, counted by the length octet
	blockLen      = 16
	crcLen        = 2
)

// TransportFIR marks the first transport segment of an application fragment;
// only that segment starts with the application header.
const TransportFIR = 0x40

// frameLinkFrame returns the length of the link frame at the start of b, 0
// when b holds only part of one, or an error when b cannot start a frame.
// The header CRC covers the length octet, so a header CRC mismatch is
// unframeable. Data block CRCs are not checked.
func frameLinkFrame(b []byte) (int, error) {
	if (len(b) >= 1 && b[0] != startByte1) || (len(b) >= 2 && b[1] != startByte2) {
		return 0, ErrInvalidStart
	}
	if len(b) < linkHeaderLen {
		return 0, nil
	}
	if binary.LittleEndian.Uint16(b[8:10]) != crc16DNP3(b[0:8]) {
		return 0, ErrBadHeaderCRC
	}
	if b[2] < linkFixedLen {
		return 0, ErrBadLength
	}
	userLen := int(b[2]) - linkFixedLen
	n := linkHeaderLen + userLen + crcLen*((userLen+blockLen-1)/blockLen)
	if len(b) < n {
		return 0, nil
	}
	return n, nil
}

// decodeLinkFrame decodes one complete frame as framed by frameLinkFrame and
// strips the data block CRCs from its user data.
func decodeLinkFrame(raw []byte) *DNP3Frame {
	frame := &DNP3Frame{
		Length:      raw[2],
		Control:     raw[3],
		Destination: binary.LittleEndian.Uint16(raw[4:6]),
		Source:      binary.LittleEndian.Uint16(raw[6:8]),
	}
	userLen := int(raw[2]) - linkFixedLen
	data := make([]byte, 0, userLen)
	for rest := raw[linkHeaderLen:]; len(rest) > 0; {
		size := min(blockLen, len(rest)-crcLen)
		data = append(data, rest[:size]...)
		rest = rest[size+crcLen:]
	}
	frame.Data = data
	// Data[0] is the transport header, Data[1] the application control
	// octet and Data[2] the function code, when the segment carries the
	// application header.
	if len(data) >= 3 {
		frame.FunctionCode = data[2]
	}
	return frame
}

// HasApplicationHeader reports whether the frame's user data starts an
// application fragment (transport FIR set) and holds its function code.
// Continuation segments and link-only frames carry no application header.
func (f *DNP3Frame) HasApplicationHeader() bool {
	return len(f.Data) >= 3 && f.Data[0]&TransportFIR != 0
}

// ParseFrame parses the DNP3 link frame at the start of data. It validates
// the start octets, the header CRC and the length, and requires the whole
// frame. Bytes after the frame are ignored.
func ParseFrame(data []byte) (*DNP3Frame, error) {
	n, err := frameLinkFrame(data)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrTooShort
	}
	return decodeLinkFrame(data[:n]), nil
}
