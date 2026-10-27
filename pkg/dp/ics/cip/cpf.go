// SPDX-License-Identifier: Apache-2.0
package cip

import "encoding/binary"

type cpfItem struct {
	typeID   uint16
	length   uint16
	data     []byte
	complete bool
}

// walkCPFItems shares length validation between encapsulated explicit messages
// and native I/O datagrams. A partial final item retains its available bytes;
// callers decide which complete fields can be read without guessing offsets.
func walkCPFItems(data []byte, offset, count int, visit func(cpfItem)) error {
	for i := 0; i < count; i++ {
		if len(data)-offset < 4 {
			return ErrCIPTooShort
		}
		item := cpfItem{
			typeID: binary.LittleEndian.Uint16(data[offset : offset+2]),
			length: binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
		size := int(item.length)
		item.complete = size <= len(data)-offset
		item.data = data[offset : offset+min(size, len(data)-offset)]
		visit(item)
		if !item.complete {
			return ErrTruncated
		}
		offset += size
	}
	if offset != len(data) {
		return ErrInvalidCPF
	}
	return nil
}
