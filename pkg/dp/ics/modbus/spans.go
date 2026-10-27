// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import (
	"math"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Span is an inclusive run of data addresses (coils or registers) that a
// message reads or writes.
type Span struct {
	First, Last uint16
}

// Quantity limits per function code (MODBUS Application Protocol
// Specification V1.1b3, section 6). A server answers a quantity outside them
// with exception 3, so such a request has no specified span.
const (
	maxReadBits       = 2000 // FC 1, 2
	maxReadRegisters  = 125  // FC 3, 4; FC 23 read
	maxWriteBits      = 1968 // FC 15
	maxWriteRegisters = 123  // FC 16
	maxRWWrite        = 121  // FC 23 write
)

// AddressSpans returns the data address spans named by the attributes of a
// decoded Modbus event, so it reads the decoder's own events and the stored
// JSON form of them alike.
//
// ok is false when the message's function code may address data but the
// attributes do not bound it: a function code without a decoded layout, a
// PDU whose layout did not fit its function code, a quantity outside the
// specification's limits, a byte count that
// disagrees with the quantity, or a span past address 65535. A read response
// carries no address and is ok false as well; callers that know the message
// is a reply treat that as touching nothing.
//
// Function codes that name no data address (exception status, diagnostics,
// comm event counter and log, report server ID, read device
// identification) return no spans with ok true.
func AddressSpans(attrs map[string]any) (spans []Span, ok bool) {
	// A partial layout retains readable scalars for policy, but does not
	// establish the complete access span. PID findings alone do not affect it.
	if codes, _ := eventfields.Strings(attrs, eventfields.KeyConformance); slices.Contains(codes, "modbus.pdu_layout") {
		return nil, false
	}
	fc, ok := eventfields.Uint8(attrs, eventfields.KeyFunctionCode)
	if !ok {
		return nil, false
	}
	switch fc {
	case 1, 2:
		return quantitySpan(attrs, attrAddress, attrQuantity, maxReadBits)
	case 3, 4:
		return quantitySpan(attrs, attrAddress, attrQuantity, maxReadRegisters)
	case 5, 6, 22:
		addr, ok := eventfields.Uint16(attrs, attrAddress)
		if !ok {
			return nil, false
		}
		return []Span{{First: addr, Last: addr}}, true
	case 15:
		return writeMultipleSpan(attrs, maxWriteBits, func(q uint16) int { return (int(q) + 7) / 8 })
	case 16:
		return writeMultipleSpan(attrs, maxWriteRegisters, func(q uint16) int { return 2 * int(q) })
	case 23:
		return readWriteSpans(attrs)
	case 7, 8, 11, 12, 17:
		return nil, true
	case 43:
		mei, ok := eventfields.Uint8(attrs, "mei_type")
		return nil, ok && mei == 14
	default:
		return nil, false
	}
}

// writeMultipleSpan is the span of FC 15/16. A request always carries its
// byte count, which must match the quantity; a response echoes only address
// and quantity.
func writeMultipleSpan(attrs map[string]any, maxQty uint16, wantBytes func(uint16) int) ([]Span, bool) {
	spans, ok := quantitySpan(attrs, attrAddress, attrQuantity, maxQty)
	if !ok {
		return nil, false
	}
	if _, present := attrs[attrByteCount]; present {
		bc, okBC := eventfields.Uint8(attrs, attrByteCount)
		qty, _ := eventfields.Uint16(attrs, attrQuantity)
		if !okBC || int(bc) != wantBytes(qty) {
			return nil, false
		}
	}
	return spans, true
}

func readWriteSpans(attrs map[string]any) ([]Span, bool) {
	read, okRead := quantitySpan(attrs, attrReadAddress, attrReadQuantity, maxReadRegisters)
	write, okWrite := quantitySpan(attrs, attrWriteAddress, attrWriteQuantity, maxRWWrite)
	bc, okBC := eventfields.Uint8(attrs, attrByteCount)
	wq, _ := eventfields.Uint16(attrs, attrWriteQuantity)
	if !okRead || !okWrite || !okBC || int(bc) != 2*int(wq) {
		return nil, false
	}
	return append(read, write...), true
}

// quantitySpan is the span of quantity addresses from address, with the
// quantity in 1..maxQty and the span ending at or before 65535.
func quantitySpan(attrs map[string]any, addrKey, qtyKey string, maxQty uint16) ([]Span, bool) {
	addr, okAddr := eventfields.Uint16(attrs, addrKey)
	qty, okQty := eventfields.Uint16(attrs, qtyKey)
	if !okAddr || !okQty || qty == 0 || qty > maxQty {
		return nil, false
	}
	last := int(addr) + int(qty) - 1
	if last > math.MaxUint16 {
		return nil, false
	}
	return []Span{{First: addr, Last: uint16(last)}}, true
}
