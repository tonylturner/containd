// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"errors"
	"fmt"
)

var (
	ErrIncompleteShape  = errors.New("dnp3: incomplete shape")
	ErrUnsupportedShape = errors.New("dnp3: unsupported shape")
	ErrInvalidShape     = errors.New("dnp3: invalid shape")
)

// LinkProvenance identifies every carrying link of an application fragment.
// The decoder rejects inconsistent controls rather than merging their authority.
type LinkProvenance struct {
	Source, Destination uint16
	Master, Confirmed   bool
}

// PairShape is one application fragment, not an assembled whole response.
// Object headers, indices and values are owned and read-only to consumers.
type PairShape struct {
	Link                   LinkProvenance
	LinkOnly, LinkPrimary  bool
	LinkFunction           uint8
	FunctionCode, Sequence uint8
	FIR, FIN, CON, UNS     bool
	IIN1, IIN2             uint8
	Objects                []ObjectHeader
}

type Unit struct {
	PairShape
	shapeErr error
}

func (*Unit) Protocol() string { return "dnp3" }

// PairingShape never maps an unknown application function to generic response
// permission. Family/index compatibility and sequence cursors belong to callers.
func PairingShape(u *Unit) (PairShape, error) {
	if u == nil {
		return PairShape{}, ErrIncompleteShape
	}
	s := u.PairShape
	if u.shapeErr != nil {
		return s, u.shapeErr
	}
	if s.LinkOnly {
		// Primary reset/test/status and secondary ACK/NACK/status/not-supported.
		if s.LinkPrimary {
			switch s.LinkFunction {
			case 0, 1, 2, 9:
				return s, nil
			}
		} else {
			switch s.LinkFunction {
			case 0, 1, 11, 15:
				return s, nil
			}
		}
		return s, ErrUnsupportedShape
	}
	// Confirmed user data is not enabled until peer dependency proofs exist.
	if s.Link.Confirmed {
		return s, ErrUnsupportedShape
	}
	if s.Sequence > 15 {
		return s, ErrInvalidShape
	}
	if s.FunctionCode == FuncConfirm {
		if !s.FIR || !s.FIN || s.CON || len(s.Objects) > 0 {
			return s, ErrInvalidShape
		}
		return s, nil
	}
	for _, h := range s.Objects {
		if !h.HasQualifier || !h.HasVariation || !h.HasCount {
			return s, ErrIncompleteShape
		}
		if !headerOnlyFunction(s.FunctionCode) {
			key := uint16(h.Group)<<8 | uint16(h.Variation)
			if _, ok := fixedObjectSize[key]; !ok && packedObjectBits[key] == 0 {
				return s, ErrUnsupportedShape
			}
			if h.Addressing == "all" || h.Addressing == "virtual" {
				return s, ErrUnsupportedShape
			}
		}
		for _, p := range h.Points {
			if p.CROB != nil && !p.CROB.validEncoding() {
				return s, ErrInvalidShape
			}
			if h.Group == 41 && p.Value != nil && p.Value.Status > 18 && p.Value.Status != 126 {
				return s, ErrInvalidShape
			}
		}
	}
	if IsResponse(s.FunctionCode) {
		if s.FunctionCode != FuncResponse && s.FunctionCode != FuncUnsolicitedResponse {
			return s, ErrUnsupportedShape
		}
		if (s.FunctionCode == FuncUnsolicitedResponse) != s.UNS {
			return s, ErrInvalidShape
		}
		return s, nil
	}
	if !s.FIR || !s.FIN {
		return s, ErrUnsupportedShape
	}
	if s.UNS {
		return s, ErrInvalidShape
	}
	switch s.FunctionCode {
	case FuncRead:
		if len(s.Objects) == 0 {
			return s, ErrInvalidShape
		}
		for _, h := range s.Objects {
			if h.Group == 60 {
				if h.Variation < 1 || h.Variation > 4 || h.Addressing != "all" {
					return s, ErrUnsupportedShape
				}
			} else if h.Variation != 0 {
				key := uint16(h.Group)<<8 | uint16(h.Variation)
				if _, ok := fixedObjectSize[key]; !ok && packedObjectBits[key] == 0 {
					return s, ErrUnsupportedShape
				}
			} else {
				switch h.Group {
				case 1, 2, 3, 10, 20, 22, 30, 32, 40:
				default:
					return s, ErrUnsupportedShape
				}
			}
		}
	case FuncWrite:
		if len(s.Objects) == 0 {
			return s, ErrInvalidShape
		}
		for _, h := range s.Objects {
			if h.Group != 50 && h.Group != 80 {
				return s, ErrUnsupportedShape
			}
		}
	case FuncSelect, FuncOperate, FuncDirectOperate, FuncDirectOperateNoAck:
		if len(s.Objects) == 0 {
			return s, ErrInvalidShape
		}
		for _, h := range s.Objects {
			if h.Group != 12 && h.Group != 41 {
				return s, ErrUnsupportedShape
			}
		}
	case FuncColdRestart, FuncWarmRestart, 23, 24:
		if len(s.Objects) != 0 {
			return s, ErrUnsupportedShape
		}
	case FuncEnableUnsolicited, FuncDisableUnsolicited:
		if len(s.Objects) == 0 {
			return s, ErrInvalidShape
		}
		for _, h := range s.Objects {
			if h.Group != 60 || h.Variation < 2 || h.Variation > 4 || h.Addressing != "all" {
				return s, ErrUnsupportedShape
			}
		}
	case FuncImmediateFreezeNR, FuncFreezeClearNR:
		if len(s.Objects) == 0 {
			return s, ErrInvalidShape
		}
		for _, h := range s.Objects {
			if h.Group != 20 {
				return s, ErrUnsupportedShape
			}
		}
	default:
		return s, ErrUnsupportedShape
	}
	return s, nil
}

func linkUnit(f *DNP3Frame) *Unit {
	return &Unit{PairShape: PairShape{Link: LinkProvenance{f.Source, f.Destination, f.Control&ControlDIR != 0, f.Control&ControlPRM != 0 && f.Control&15 == 3}, LinkOnly: true, LinkPrimary: f.Control&ControlPRM != 0, LinkFunction: f.Control & 15}}
}
func decodeUnit(f *DNP3Frame) *Unit {
	u := linkUnit(f)
	u.LinkOnly = false
	if len(f.Data) < 3 {
		u.shapeErr = ErrIncompleteShape
		return u
	}
	h := f.Data[1]
	u.FunctionCode, u.Sequence, u.FIR, u.FIN, u.CON, u.UNS = f.Data[2], h&15, h&128 != 0, h&64 != 0, h&32 != 0, h&16 != 0
	off := 3
	if IsResponse(u.FunctionCode) {
		if len(f.Data) < 5 {
			u.shapeErr = ErrIncompleteShape
			return u
		}
		u.IIN1, u.IIN2 = f.Data[3], f.Data[4]
		off = 5
	}
	var stopped objectWalkStop
	u.Objects, stopped = parseObjectHeaders(f.Data, off, u.FunctionCode)
	switch stopped {
	case walkTruncated:
		u.shapeErr = ErrIncompleteShape
	case walkInvalid:
		u.shapeErr = ErrInvalidShape
	case walkUnsupported, walkLimited:
		u.shapeErr = ErrUnsupportedShape
	}
	if f.badDataCRC {
		u.shapeErr = fmt.Errorf("%w: data CRC", ErrInvalidShape)
	}
	for _, o := range u.Objects {
		for _, p := range o.Points {
			if p.CROB != nil && !p.CROB.validEncoding() {
				u.shapeErr = ErrInvalidShape
			}
		}
	}
	_, err := PairingShape(u)
	u.shapeErr = err
	return u
}
