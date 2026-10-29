// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"errors"
)

// CPFItem retains the available body even if its declared length is truncated.
type CPFItem struct {
	TypeID   uint16
	Length   uint16
	Data     []byte
	Complete bool
}

func knownCPFItem(id uint16) bool {
	switch id {
	case 0, 0xc, 0xa1, 0xb1, 0xb2, 0x100, 0x8000, 0x8001, 0x8002:
		return true
	default:
		return false
	}
}

// walkCPFItems shares length validation between encapsulated explicit messages
// and native I/O datagrams. A partial final item retains its available bytes;
// callers decide which complete fields can be read without guessing offsets.
func walkCPFItems(data []byte, offset, count int, visit func(CPFItem)) error {
	for i := 0; i < count; i++ {
		if len(data)-offset < 4 {
			return ErrCIPTooShort
		}
		item := CPFItem{
			TypeID: binary.LittleEndian.Uint16(data[offset : offset+2]),
			Length: binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
		size := int(item.Length)
		item.Complete = size <= len(data)-offset
		item.Data = data[offset : offset+min(size, len(data)-offset)]
		visit(item)
		if !item.Complete {
			return ErrTruncated
		}
		offset += size
	}
	if offset != len(data) {
		return ErrInvalidCPF
	}
	return nil
}

// CPFResult retains item order, declared lengths and the selected explicit
// message's provenance. Payload excludes only the explicit B1 sequence prefix.
// Selected is -1 when there is no complete data item.
type CPFResult struct {
	Count             uint16
	Items             []CPFItem
	Selected          int
	Payload           []byte
	ConnectionID      *uint32
	ConnectedSequence *uint16
	Conformance       []string
	Undecoded         []string
	Err               error
}

func parseCPF(data []byte) CPFResult {
	r := CPFResult{Selected: -1}
	if len(data) < 8 {
		r.Err = ErrCIPTooShort
		r.Conformance = []string{"cip.cpf_layout"}
		return r
	}
	r.Count = binary.LittleEndian.Uint16(data[6:8])
	var itemErr error
	r.Err = walkCPFItems(data, 8, int(r.Count), func(item CPFItem) {
		r.Items = append(r.Items, item)
		if (item.TypeID == 0xb1 || item.TypeID == 0xb2) && r.Selected >= 0 {
			r.Undecoded = append(r.Undecoded, "cip.extra_data_item")
			return
		}
		if !item.Complete {
			return
		}
		switch item.TypeID {
		case 0:
			if item.Length != 0 {
				itemErr = ErrInvalidCPF
			}
		case 0xa1:
			if item.Length != 4 {
				itemErr = ErrInvalidCPF
			}
		case 0x8000, 0x8001:
			if item.Length != 16 {
				itemErr = ErrInvalidCPF
			}
		case 0x8002:
			if item.Length != 8 {
				itemErr = ErrInvalidCPF
			}
		case 0xc, 0x100:
			// ListIdentity/ListServices metadata, not a CIP message.
		case 0xb1, 0xb2:
			r.Selected = len(r.Items) - 1
			r.Payload = item.Data
			var address *CPFItem
			if r.Selected > 0 {
				address = &r.Items[r.Selected-1]
			}
			if item.TypeID == 0xb1 {
				if address == nil || address.TypeID != 0xa1 || !address.Complete || address.Length != 4 {
					itemErr = ErrInvalidCPF
				} else {
					id := binary.LittleEndian.Uint32(address.Data)
					r.ConnectionID = &id
				}
				if len(item.Data) < 2 {
					itemErr = ErrCIPTooShort
					r.Payload = nil
					return
				}
				seq := binary.LittleEndian.Uint16(item.Data)
				r.ConnectedSequence = &seq
				r.Payload = item.Data[2:]
			} else if address == nil || address.TypeID != 0 || address.Length != 0 {
				itemErr = ErrInvalidCPF
			}
		default:
			r.Undecoded = append(r.Undecoded, "cip.cpf_item_unsupported")
		}
	})
	if itemErr != nil {
		r.Conformance = append(r.Conformance, "cip.cpf_layout")
	}
	if r.Err != nil {
		code := "cip.cpf_layout"
		if errors.Is(r.Err, ErrTruncated) {
			code = "cip.item_truncated"
		}
		r.Conformance = append(r.Conformance, code)
	}
	r.Err = errors.Join(r.Err, itemErr)
	if binary.LittleEndian.Uint32(data[:4]) != 0 {
		r.Err = errors.Join(r.Err, ErrInvalidCPF)
		r.Conformance = append(r.Conformance, "cip.cpf_layout")
	}
	if r.Err == nil && r.Selected < 0 {
		r.Err = ErrNoCIPPayload
		r.Conformance = append(r.Conformance, "cip.cpf_layout")
	}
	return r
}
