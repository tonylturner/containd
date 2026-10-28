// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// ioEvent decodes one implicit I/O datagram. UDP/2222 carries a bare CPF with
// no encapsulation header: an item count, a sequenced address item (connection
// id and sequence number) and a connected data item holding opaque I/O bytes.
// Neither item is a CIP service, so the event never carries service fields.
// data_length is the whole connected data item, including the transport
// class 1 sequence count when the connection uses one: the datagram does not
// say which transport class it belongs to. Any other layout is content the
// decoder cannot read inside the datagram's known boundary: it keeps the
// fields that were read and reports cip.cpf_layout.
func ioEvent(state *flow.State, data []byte) dpi.Event {
	attrs := map[string]any{"io_context_known": false}
	valid := len(data) >= 2
	if valid {
		count := int(binary.LittleEndian.Uint16(data[:2]))
		attrs["cpf_item_count"] = uint16(count)
		valid = count == 2
		types := make([]string, 0, 2)
		err := walkCPFItems(data, 2, count, func(item CPFItem) {
			types = append(types, fmt.Sprintf("0x%04x", item.TypeID))
			switch {
			case len(types) == 1 && item.TypeID == 0x8002:
				if len(item.Data) >= 4 {
					attrs["connection_id"] = binary.LittleEndian.Uint32(item.Data[:4])
				}
				if len(item.Data) >= 8 {
					attrs["sequence"] = binary.LittleEndian.Uint32(item.Data[4:8])
				}
				valid = valid && item.Length == 8
			case len(types) == 2 && item.TypeID == 0x00b1:
				if item.Complete {
					attrs["data_length"] = item.Length
					attrs["io_data_hex"] = hex.EncodeToString(item.Data[:min(len(item.Data), 512)])
					attrs["io_data_truncated"] = len(item.Data) > 512
				}
			default:
				valid = false
				addUndecoded(attrs, "cip.cpf_item_unsupported")
			}
		})
		attrs["cpf_item_types"] = strings.Join(types, ",")
		valid = valid && err == nil
	}
	if !valid {
		addFinding(attrs, "cip.cpf_layout")
	}
	return newEvent(state, "session", attrs)
}
