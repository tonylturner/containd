// SPDX-License-Identifier: Apache-2.0
package iec104

import (
	"errors"
	"fmt"
)

var (
	ErrIncompleteShape  = errors.New("iec104: incomplete shape")
	ErrUnsupportedShape = errors.New("iec104: unsupported shape")
	ErrInvalidShape     = errors.New("iec104: invalid shape")
)

// Object retains exact typed information-element semantics. ValueBits is the
// integer or IEEE754 encoding, not a rounded JSON value. Time retains all seven
// CP56Time2a octets, including flags. Presence follows the TypeID descriptor.
type Object struct {
	IOA                uint32
	ValueBits          uint32
	Quality, Qualifier uint8
	Select, Transient  bool
	TestSequence       uint16
	Time               [7]byte
}

// PairShape contains APCI and the complete ASDU object tree. Objects are owned
// by the decode result and must not be mutated or retained without copying.
type PairShape struct {
	Format, UFunction             string
	SendSequence, ReceiveSequence uint16
	TypeID, Cause, Originator     uint8
	CA                            uint16
	Negative, Test, SQ            bool
	Objects                       []Object
}

type Unit struct {
	PairShape
	shapeErr error
}

func (*Unit) Protocol() string { return "iec104" }

// PairingShape validates the supported procedure vocabulary. It does not
// authorize a stage or infer a request from an activation confirmation.
func PairingShape(u *Unit) (PairShape, error) {
	if u == nil {
		return PairShape{}, ErrIncompleteShape
	}
	s := u.PairShape
	if u.shapeErr != nil {
		return s, u.shapeErr
	}
	switch s.Format {
	case "S":
		return s, nil
	case "U":
		for _, f := range uFunctions {
			if f == s.UFunction {
				return s, nil
			}
		}
		return s, ErrInvalidShape
	case "I":
	default:
		return s, ErrInvalidShape
	}
	if s.CA == 0 || s.CA == BroadcastCA || len(s.Objects) == 0 {
		return s, ErrUnsupportedShape
	}
	d, ok := descriptors[s.TypeID]
	if !ok {
		return s, ErrUnsupportedShape
	}
	if len(s.Objects) > 127 || checkProfile(asduHeader{typeID: s.TypeID, count: uint8(len(s.Objects)), sq: s.SQ}, d) != nil {
		return s, ErrInvalidShape
	}
	for _, o := range s.Objects {
		if o.IOA > maxIOA {
			return s, ErrInvalidShape
		}
	}
	switch {
	case d.class == ClassControl:
		if s.Cause != 6 && s.Cause != 7 && s.Cause != 10 {
			return s, ErrUnsupportedShape
		}
	case d.class == ClassMonitor:
		if !(s.Cause >= 1 && s.Cause <= 3 || s.Cause == 5 || s.Cause >= 20 && s.Cause <= 36 || s.Cause >= 37 && s.Cause <= 41) {
			return s, ErrUnsupportedShape
		}
	case s.TypeID == 70:
		if s.Cause != 4 {
			return s, ErrUnsupportedShape
		}
	case s.TypeID == 100:
		q := s.Objects[0].Qualifier
		if (s.Cause != 6 && s.Cause != 7 && s.Cause != 10) || q < 20 || q > 36 || s.Objects[0].IOA != 0 {
			return s, ErrUnsupportedShape
		}
	case s.TypeID == 101:
		q := s.Objects[0].Qualifier & 63
		if (s.Cause != 6 && s.Cause != 7 && s.Cause != 10) || q < 1 || q > 5 || s.Objects[0].IOA != 0 {
			return s, ErrUnsupportedShape
		}
	case s.TypeID == 102:
		if s.Cause != 5 {
			return s, ErrUnsupportedShape
		}
	case s.TypeID == 103, s.TypeID == 105, s.TypeID == 107:
		if (s.Cause != 6 && s.Cause != 7) || s.Objects[0].IOA != 0 {
			return s, ErrUnsupportedShape
		}
		if s.TypeID == 105 && (s.Objects[0].Qualifier < 1 || s.Objects[0].Qualifier > 2) {
			return s, ErrUnsupportedShape
		}
	default:
		return s, ErrUnsupportedShape
	}
	if s.Negative && s.Cause != 7 && s.Cause != 10 {
		return s, ErrInvalidShape
	}
	return s, nil
}

func decodeUnit(apdu []byte, direction string) *Unit {
	a := decodeAPCI(apdu)
	u := &Unit{PairShape: PairShape{Format: a.format, UFunction: a.uFunction, SendSequence: a.sendSeq, ReceiveSequence: a.recvSeq}}
	// Reserved control bits are observational conformance findings; strict
	// policy vetoes them from the events. Other APCI findings are structural.
	for _, f := range a.findings {
		if f != FindingReservedBits {
			u.shapeErr = fmt.Errorf("%w: APCI", ErrInvalidShape)
		}
	}
	if a.format != "I" {
		if a.length != 4 {
			u.shapeErr = ErrInvalidShape
		}
	} else {
		asdu := apdu[apciLen:]
		if len(asdu) < asduHeaderLen {
			u.shapeErr = ErrIncompleteShape
			return u
		}
		h := decodeASDUHeader(asdu)
		u.TypeID, u.Cause, u.Originator, u.CA, u.Negative, u.Test, u.SQ = h.typeID, h.cause, h.originator, h.ca, h.negative, h.test, h.sq
		d, ok := descriptors[h.typeID]
		if !ok {
			u.shapeErr = ErrUnsupportedShape
			return u
		}
		if h.count == 0 || checkProfile(h, d) != nil || checkRole(h, direction) != nil {
			u.shapeErr = ErrInvalidShape
			return u
		}
		objects, err := decodeTypedObjects(h, d, asdu[asduHeaderLen:])
		u.Objects = objects
		if err != nil {
			u.shapeErr = fmt.Errorf("%w: %v", ErrInvalidShape, err)
		}
	}
	_, err := PairingShape(u)
	u.shapeErr = err
	return u
}
