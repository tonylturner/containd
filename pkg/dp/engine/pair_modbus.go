// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"slices"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type modbusPairKey struct {
	Dir      dpi.StreamDir
	TID      uint16
	Unit, FC uint8
}

type modbusPairAdapter struct{}

func (modbusPairAdapter) Classify(f dpi.DecodedFrame, dir dpi.StreamDir) (rules.MessageClass, modbusPairKey, modbus.PairShape, pairReason) {
	u, ok := f.Unit.(*modbus.Unit)
	if !ok {
		return rules.ClassUnknown, modbusPairKey{}, modbus.PairShape{}, pairUnsupported
	}
	s, err := modbus.PairingShape(u)
	k := modbusPairKey{dpi.ClientToServer, s.TransactionID, s.UnitID, s.FunctionCode}
	if err != nil || dir == dpi.DirUnknown || s.Response != (dir == dpi.ServerToClient) {
		return rules.ClassUnknown, k, s, pairUnsupported
	}
	if s.Response {
		return rules.ClassSolicited, k, s, pairOK
	}
	return rules.ClassRequest, k, s, pairOK
}

func (modbusPairAdapter) Matches(a, b modbusPairKey) bool { return a == b }
func (modbusPairAdapter) Conflicts(a, b modbusPairKey) bool {
	return a.Dir == b.Dir && a.TID == b.TID && a.Unit == b.Unit
}
func (modbusPairAdapter) Lifetime(modbus.PairShape) time.Duration { return 30 * time.Second }
func (modbusPairAdapter) Grants(modbus.PairShape) bool            { return true }
func (modbusPairAdapter) Copy(s modbus.PairShape) modbus.PairShape {
	s.Values, s.Spans = slices.Clone(s.Values), slices.Clone(s.Spans)
	return s
}
func (modbusPairAdapter) Charge(s modbus.PairShape) int64 {
	return 128 + int64(len(s.Values))*2 + int64(len(s.Spans))*4
}
func (modbusPairAdapter) Advance(q modbus.PairShape, p pairProgress, r modbus.PairShape) (pairProgress, bool, pairReason) {
	if q.FunctionCode != r.FunctionCode || q.UnitID != r.UnitID || q.TransactionID != r.TransactionID || !r.Response {
		return p, false, pairMismatch
	}
	if r.Exception {
		return p, true, pairOK
	}
	ok := false
	switch q.FunctionCode {
	case 1, 2:
		ok = uint16(r.ByteCount) == (q.Quantity+7)/8
	case 3, 4:
		ok = uint16(r.ByteCount) == 2*q.Quantity
	case 23:
		ok = uint16(r.ByteCount) == 2*q.ReadQuantity
	case 5, 6:
		ok = q.Address == r.Address && q.Value == r.Value
	case 15, 16:
		ok = q.Address == r.Address && q.Quantity == r.Quantity
	case 22:
		ok = q.Address == r.Address && q.AndMask == r.AndMask && q.OrMask == r.OrMask
	}
	if !ok {
		return p, false, pairMismatch
	}
	return p, true, pairOK
}
