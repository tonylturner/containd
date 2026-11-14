// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"errors"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

var (
	ErrIncompleteShape  = errors.New("modbus: incomplete shape")
	ErrUnsupportedShape = errors.New("modbus: unsupported shape")
	ErrInvalidShape     = errors.New("modbus: invalid shape")
)

// PairShape contains wire semantics only. Read replies deliberately have no
// address/span: those belong to the retained request, not the response wire.
// Slices are owned by the result and read-only to consumers.
type PairShape struct {
	TransactionID                                          uint16
	UnitID, FunctionCode                                   uint8
	Response, Exception                                    bool
	ExceptionCode                                          uint8
	Address, Quantity, Value, AndMask, OrMask              uint16
	ReadAddress, ReadQuantity, WriteAddress, WriteQuantity uint16
	ByteCount                                              uint8
	Values                                                 []uint16
	Spans                                                  []Span
	SubFunction                                            uint16
	MEIType                                                uint8
}

// Unit is a decoder-validated ADU. Consumers must not mutate its fields.
type Unit struct {
	PairShape
	shapeErr error
}

func (*Unit) Protocol() string { return "modbus" }

// PairingShape returns the exact supported pairing shape, never a generic
// permission for an unknown function, malformed PDU or broadcast request.
func PairingShape(u *Unit) (PairShape, error) {
	if u == nil {
		return PairShape{}, ErrIncompleteShape
	}
	if u.shapeErr != nil {
		return PairShape{}, u.shapeErr
	}
	s := u.PairShape
	if s.UnitID == 0 {
		return s, ErrUnsupportedShape
	}
	switch s.FunctionCode {
	case 1, 2, 3, 4, 5, 6, 15, 16, 22, 23:
	default:
		return s, ErrUnsupportedShape
	}
	if s.Exception {
		if !s.Response || exceptionName(s.ExceptionCode) == "unknown" {
			return s, ErrInvalidShape
		}
		return s, nil
	}
	if s.Response && (s.FunctionCode == 1 || s.FunctionCode == 2 || s.FunctionCode == 3 || s.FunctionCode == 4 || s.FunctionCode == 23) {
		if s.ByteCount == 0 || ((s.FunctionCode != 1 && s.FunctionCode != 2) && s.ByteCount%2 != 0) {
			return s, ErrInvalidShape
		}
	}
	return s, nil
}

func decodeUnit(f *TCPFrame, st *flow.State, dir dpi.StreamDir) *Unit {
	u := &Unit{PairShape: PairShape{TransactionID: f.TransactionID, UnitID: f.UnitID, FunctionCode: f.FunctionCode & 127, Exception: f.FunctionCode&128 != 0}}
	u.Response = dir == dpi.ServerToClient
	if dir == dpi.DirUnknown {
		u.Response = st != nil && st.ServiceKey().Dir == flow.DirReverse
	}
	p := f.PDU
	invalid := func() *Unit { u.shapeErr = ErrInvalidShape; return u }
	if f.ProtocolID != 0 || !validLayout(f.FunctionCode, p, u.Response) {
		return invalid()
	}
	if u.Exception {
		if len(p) != 1 {
			return invalid()
		}
		u.ExceptionCode = p[0]
	} else {
		switch u.FunctionCode {
		case 1, 2, 3, 4, 23:
			if u.Response {
				u.ByteCount = p[0]
				if u.FunctionCode != 1 && u.FunctionCode != 2 {
					u.Values = make([]uint16, (len(p)-1)/2)
					for i := range u.Values {
						u.Values[i] = be16(p, 1+2*i)
					}
				} else {
					u.Values = make([]uint16, len(p)-1)
					for i := range u.Values {
						u.Values[i] = uint16(p[i+1])
					}
				}
				break
			}
			if u.FunctionCode == 23 {
				u.ReadAddress, u.ReadQuantity, u.WriteAddress, u.WriteQuantity = be16(p, 0), be16(p, 2), be16(p, 4), be16(p, 6)
				u.ByteCount = p[8]
				if !u.addSpan(u.ReadAddress, u.ReadQuantity, maxReadRegisters) || !u.addSpan(u.WriteAddress, u.WriteQuantity, maxRWWrite) {
					return invalid()
				}
				u.Values = words(p[9:])
			} else {
				u.Address, u.Quantity = be16(p, 0), be16(p, 2)
				limit := uint16(maxReadRegisters)
				if u.FunctionCode <= 2 {
					limit = maxReadBits
				}
				if !u.addSpan(u.Address, u.Quantity, limit) {
					return invalid()
				}
			}
		case 5, 6:
			u.Address, u.Value = be16(p, 0), be16(p, 2)
			if u.FunctionCode == 5 && u.Value != 0 && u.Value != 0xff00 {
				return invalid()
			}
			u.Spans = []Span{{u.Address, u.Address}}
		case 15, 16:
			u.Address, u.Quantity = be16(p, 0), be16(p, 2)
			limit := uint16(maxWriteRegisters)
			if u.FunctionCode == 15 {
				limit = maxWriteBits
			}
			if !u.addSpan(u.Address, u.Quantity, limit) {
				return invalid()
			}
			if !u.Response {
				u.ByteCount = p[4]
				if u.FunctionCode == 16 {
					u.Values = words(p[5:])
				} else {
					u.Values = make([]uint16, u.Quantity)
					for i := range u.Values {
						u.Values[i] = uint16((p[5+i/8] >> (i % 8)) & 1)
					}
				}
			}
		case 22:
			u.Address, u.AndMask, u.OrMask = be16(p, 0), be16(p, 2), be16(p, 4)
			u.Spans = []Span{{u.Address, u.Address}}
		case 8:
			if len(p) >= 2 {
				u.SubFunction = be16(p, 0)
			}
		case 43:
			if len(p) > 0 {
				u.MEIType = p[0]
			}
		}
	}
	_, err := PairingShape(u)
	if err != nil {
		u.shapeErr = fmt.Errorf("%w: FC %d", err, u.FunctionCode)
	}
	return u
}
func (u *Unit) addSpan(address, quantity, limit uint16) bool {
	if quantity == 0 || quantity > limit || uint32(address)+uint32(quantity) > 65536 {
		return false
	}
	u.Spans = append(u.Spans, Span{address, address + quantity - 1})
	return true
}
func words(b []byte) []uint16 {
	w := make([]uint16, len(b)/2)
	for i := range w {
		w[i] = be16(b, 2*i)
	}
	return w
}
