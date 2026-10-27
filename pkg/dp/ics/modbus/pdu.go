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

// addRequestFields retains each complete scalar at its specified wire offset,
// even if later bytes or the overall layout are nonconformant.
func addRequestFields(fc uint8, pdu []byte, attrs map[string]any) {
	switch fc {
	case 1, 2, 3, 4, 15, 16:
		addWords(pdu, attrs, attrAddress, attrQuantity)
		if (fc == 15 || fc == 16) && len(pdu) >= 5 {
			attrs[attrByteCount] = pdu[4]
		}
	case 5, 6:
		addWords(pdu, attrs, attrAddress, attrValue)
	case 22:
		addWords(pdu, attrs, attrAddress, attrAndMask, attrOrMask)
	case 23:
		addWords(pdu, attrs, attrReadAddress, attrReadQuantity, attrWriteAddress, attrWriteQuantity)
		if len(pdu) >= 9 {
			attrs[attrByteCount] = pdu[8]
		}
	}
}

// Read responses carry counts, never the request's address or quantity.
func addResponseFields(fc uint8, pdu []byte, attrs map[string]any) {
	switch fc {
	case 1, 2, 3, 4, 23:
		if len(pdu) >= 1 {
			attrs[attrByteCount] = pdu[0]
			if fc != 1 && fc != 2 && pdu[0]%2 == 0 {
				attrs[attrRegisterCount] = uint16(pdu[0] / 2)
			}
		}
	case 5, 6:
		addWords(pdu, attrs, attrAddress, attrValue)
	case 15, 16:
		addWords(pdu, attrs, attrAddress, attrQuantity)
	case 22:
		addWords(pdu, attrs, attrAddress, attrAndMask, attrOrMask)
	}
}

func addWords(pdu []byte, attrs map[string]any, keys ...string) {
	for i, key := range keys {
		if len(pdu) < 2*i+2 {
			return
		}
		attrs[key] = be16(pdu, 2*i)
	}
}

func be16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off : off+2]) }
