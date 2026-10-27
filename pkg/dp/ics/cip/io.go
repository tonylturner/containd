// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

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
	attrs := make(map[string]any)
	valid := len(data) >= 2
	if valid {
		count := int(binary.LittleEndian.Uint16(data[:2]))
		valid = count == 2
		types := make([]string, 0, 2)
		err := walkCPFItems(data, 2, count, func(item cpfItem) {
			types = append(types, fmt.Sprintf("0x%04x", item.typeID))
			switch {
			case len(types) == 1 && item.typeID == 0x8002:
				if len(item.data) >= 4 {
					attrs["connection_id"] = binary.LittleEndian.Uint32(item.data[:4])
				}
				if len(item.data) >= 8 {
					attrs["sequence"] = binary.LittleEndian.Uint32(item.data[4:8])
				}
				valid = valid && item.length == 8
			case len(types) == 2 && item.typeID == 0x00b1:
				if item.complete {
					attrs["data_length"] = item.length
				}
			default:
				valid = false
			}
		})
		attrs["cpf_item_types"] = strings.Join(types, ",")
		valid = valid && err == nil
	}
	if !valid {
		addFinding(attrs, "cip.cpf_layout")
	}
	return dpi.Event{
		FlowID: state.Key.Hash(), Proto: "cip", Kind: "session",
		Attributes: attrs, Timestamp: time.Now().UTC(),
	}
}
