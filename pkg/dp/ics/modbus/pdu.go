// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import "encoding/binary"

// Attribute keys of the data-access fields. They name only values that are
// on the wire in the PDU's layout for its function code and direction
// (MODBUS Application Protocol Specification V1.1b3, section 6).
const (
	attrAddress       = "address"
	attrQuantity      = "quantity"
	attrValue         = "value"
	attrByteCount     = "byte_count"
	attrRegisterCount = "register_count"
	attrAndMask       = "and_mask"
	attrOrMask        = "or_mask"
	attrReadAddress   = "read_address"
	attrReadQuantity  = "read_quantity"
	attrWriteAddress  = "write_address"
	attrWriteQuantity = "write_quantity"
)

// addRequestFields adds the data-access fields of a request PDU (data after
// the function code). A PDU whose length does not fit its function code's
// layout adds none: it is malformed for that function code, and the server
// rejects it rather than reading any field at a guessed offset.
func addRequestFields(fc uint8, pdu []byte, attrs map[string]any) {
	switch fc {
	case 1, 2, 3, 4: // read coils, discrete inputs, holding or input registers
		if len(pdu) == 4 {
			attrs[attrAddress] = be16(pdu, 0)
			attrs[attrQuantity] = be16(pdu, 2)
		}
	case 5, 6: // write single coil or register: the second word is the value
		if len(pdu) == 4 {
			attrs[attrAddress] = be16(pdu, 0)
			attrs[attrValue] = be16(pdu, 2)
		}
	case 15, 16: // write multiple coils or registers
		if len(pdu) >= 5 && len(pdu) == 5+int(pdu[4]) {
			attrs[attrAddress] = be16(pdu, 0)
			attrs[attrQuantity] = be16(pdu, 2)
			attrs[attrByteCount] = pdu[4]
		}
	case 22: // mask write register
		if len(pdu) == 6 {
			addMaskWrite(pdu, attrs)
		}
	case 23: // read/write multiple registers
		if len(pdu) >= 9 && len(pdu) == 9+int(pdu[8]) {
			attrs[attrReadAddress] = be16(pdu, 0)
			attrs[attrReadQuantity] = be16(pdu, 2)
			attrs[attrWriteAddress] = be16(pdu, 4)
			attrs[attrWriteQuantity] = be16(pdu, 6)
			attrs[attrByteCount] = pdu[8]
		}
	}
}

// addResponseFields adds the data-access fields of a normal response PDU.
// Read responses carry a byte count and data, never the request's address
// or quantity; write responses echo the request's address with its value
// (FC 5, 6), quantity (FC 15, 16) or masks (FC 22).
func addResponseFields(fc uint8, pdu []byte, attrs map[string]any) {
	switch fc {
	case 1, 2, 3, 4, 23:
		if len(pdu) < 1 || len(pdu) != 1+int(pdu[0]) {
			return
		}
		attrs[attrByteCount] = pdu[0]
		if fc != 1 && fc != 2 && pdu[0]%2 == 0 {
			attrs[attrRegisterCount] = uint16(pdu[0] / 2)
		}
	case 5, 6:
		if len(pdu) == 4 {
			attrs[attrAddress] = be16(pdu, 0)
			attrs[attrValue] = be16(pdu, 2)
		}
	case 15, 16:
		if len(pdu) == 4 {
			attrs[attrAddress] = be16(pdu, 0)
			attrs[attrQuantity] = be16(pdu, 2)
		}
	case 22:
		if len(pdu) == 6 {
			addMaskWrite(pdu, attrs)
		}
	}
}

func addMaskWrite(pdu []byte, attrs map[string]any) {
	attrs[attrAddress] = be16(pdu, 0)
	attrs[attrAndMask] = be16(pdu, 2)
	attrs[attrOrMask] = be16(pdu, 4)
}

func be16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off : off+2]) }
