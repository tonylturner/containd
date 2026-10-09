// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"encoding/binary"
	"fmt"
)

// APCI framing (IEC 60870-5-104 clause 5): start octet 0x68, a length octet
// that counts the four control octets plus the ASDU (4..253), then the
// control field. An APDU is 2 + length octets, at most 255.
const (
	startOctet    = 0x68
	minAPDULength = 4
	maxAPDULength = 253
	apciLen       = 6 // start, length, four control octets
)

// U-format functions: exactly one of STARTDT, STOPDT and TESTFR, act or con,
// in control octet 1 (bits 0-1 = 11).
var uFunctions = map[byte]string{
	0x07: "startdt_act",
	0x0B: "startdt_con",
	0x13: "stopdt_act",
	0x23: "stopdt_con",
	0x43: "testfr_act",
	0x83: "testfr_con",
}

// apci is a decoded control field.
type apci struct {
	format    string // "I", "S" or "U"
	length    int    // the length octet
	sendSeq   uint16 // N(S), I-format only
	recvSeq   uint16 // N(R), I- and S-format
	uFunction string // U-format only
}

// frameAPDU returns the size of the APDU at the start of b, 0 when b holds
// only part of it, or an error when b cannot start an APDU: a start octet
// other than 0x68, a length outside 4..253, or reserved control bits. It
// reports an error as soon as the octets that prove it are present and
// never scans forward for a later start octet.
func frameAPDU(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, nil
	}
	if b[0] != startOctet {
		return 0, fmt.Errorf("start octet 0x%02x, want 0x68", b[0])
	}
	if len(b) < 2 {
		return 0, nil
	}
	length := int(b[1])
	if length < minAPDULength || length > maxAPDULength {
		return 0, fmt.Errorf("APDU length %d outside 4..253", length)
	}
	if len(b) < apciLen {
		return 0, nil
	}
	if err := checkControl(b[2:apciLen]); err != nil {
		return 0, err
	}
	if len(b) < 2+length {
		return 0, nil
	}
	return 2 + length, nil
}

// checkControl validates the reserved bits of the control field:
//   - I-format (octet 1 bit 0 = 0): octet 3 bit 0 is reserved 0;
//   - S-format (octet 1 bits 0-1 = 01): octet 1 is exactly 0x01, octet 2 is 0
//     and octet 3 bit 0 is reserved 0;
//   - U-format (octet 1 bits 0-1 = 11): octet 1 holds exactly one function
//     and octets 2-4 are 0.
func checkControl(c []byte) error {
	switch {
	case c[0]&0x01 == 0:
		if c[2]&0x01 != 0 {
			return fmt.Errorf("reserved bit set in I-format control octet 3 (0x%02x)", c[2])
		}
	case c[0]&0x03 == 0x01:
		if c[0] != 0x01 || c[1] != 0 || c[2]&0x01 != 0 {
			return fmt.Errorf("reserved bits set in S-format control field % x", c)
		}
	default:
		if _, ok := uFunctions[c[0]]; !ok || c[1] != 0 || c[2] != 0 || c[3] != 0 {
			return fmt.Errorf("control field % x is not exactly one U-format function", c)
		}
	}
	return nil
}

// decodeAPCI decodes the control field of an APDU that frameAPDU accepted.
// N(S) and N(R) are 15-bit sequence numbers, little-endian, shifted left by
// one bit.
func decodeAPCI(apdu []byte) apci {
	c := apdu[2:apciLen]
	a := apci{length: int(apdu[1])}
	switch {
	case c[0]&0x01 == 0:
		a.format = "I"
		a.sendSeq = binary.LittleEndian.Uint16(c[0:2]) >> 1
		a.recvSeq = binary.LittleEndian.Uint16(c[2:4]) >> 1
	case c[0]&0x03 == 0x01:
		a.format = "S"
		a.recvSeq = binary.LittleEndian.Uint16(c[2:4]) >> 1
	default:
		a.format = "U"
		a.uFunction = uFunctions[c[0]]
	}
	return a
}
