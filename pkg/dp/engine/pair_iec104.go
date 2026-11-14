// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"slices"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type iecPairKey struct {
	Dir                            dpi.StreamDir
	CA                             uint16
	IOA                            uint32
	Type, Originator, Stage, Cause uint8
}
type iecPairAdapter struct{}

func (iecPairAdapter) Classify(f dpi.DecodedFrame, dir dpi.StreamDir) (rules.MessageClass, iecPairKey, iec104.PairShape, pairReason) {
	u, ok := f.Unit.(*iec104.Unit)
	if !ok {
		return rules.ClassUnknown, iecPairKey{}, iec104.PairShape{}, pairUnsupported
	}
	s, err := iec104.PairingShape(u)
	k := iecPairKey{Dir: dpi.ClientToServer, CA: s.CA, Type: s.TypeID, Originator: s.Originator, Stage: s.Cause, Cause: s.Cause}
	if len(s.Objects) > 0 {
		k.IOA = s.Objects[0].IOA
	}
	if err != nil || dir == dpi.DirUnknown {
		return rules.ClassUnknown, k, s, pairUnsupported
	}
	if s.Format == "S" || s.Format == "U" {
		return rules.ClassSession, k, s, pairOK
	}
	if dir == dpi.ClientToServer {
		row, known := iecProcedureFor(s.TypeID)
		if !known || s.Cause != row.RequestCause {
			return rules.ClassUnknown, k, s, pairUnsupported
		}
		k.Stage = 0
		if s.Objects[0].Select {
			k.Stage = 1
		}
		return rules.ClassRequest, k, s, pairOK
	}
	if iecMonitorType(s.TypeID) && s.Cause >= 1 && s.Cause <= 3 || s.TypeID == 70 && s.Cause == 4 {
		return rules.ClassAutonomous, k, s, pairOK
	}
	if iecMonitorType(s.TypeID) && (s.Cause == 5 || s.Cause >= 20 && s.Cause <= 41) {
		return rules.ClassSolicited, k, s, pairOK
	}
	row, known := iecProcedureFor(s.TypeID)
	if known && (s.Cause == row.ConfirmCause || s.Cause == 10 && row.Termination || iecErrorCause(s.Cause) && row.Variants&iecNegativeError != 0) {
		k.Stage = 0
		if s.Objects[0].Select {
			k.Stage = 1
		}
		return rules.ClassSolicited, k, s, pairOK
	}
	return rules.ClassUnknown, k, s, pairUnsupported
}
func (iecPairAdapter) Matches(q, r iecPairKey) bool {
	if q.Dir != r.Dir || q.CA != r.CA || q.Originator != r.Originator {
		return false
	}
	if q.Type == r.Type {
		row, _ := iecProcedureFor(q.Type)
		return q.IOA == r.IOA && (q.Stage == r.Stage || q.Stage == 0 && r.Cause == 10 && row.Variants&iecTerminationSelectEcho != 0)
	}
	switch q.Type {
	case 100:
		return iecMonitorType(r.Type) && r.Stage >= 20 && r.Stage <= 36
	case 101:
		return (r.Type == 15 || r.Type == 37) && r.Stage >= 37 && r.Stage <= 41
	case 102:
		return iecMonitorType(r.Type) && r.Stage == 5 && q.IOA == r.IOA
	default:
		return false
	}
}
func (iecPairAdapter) Conflicts(a, b iecPairKey) bool {
	return a.Dir == b.Dir && a.CA == b.CA && a.Originator == b.Originator && a.Type == b.Type && a.IOA == b.IOA && a.Stage == b.Stage
}
func (iecPairAdapter) Lifetime(s iec104.PairShape) time.Duration {
	if s.TypeID == 100 || s.TypeID == 101 {
		return 30 * time.Second
	}
	return 15 * time.Second
}
func (iecPairAdapter) Grants(iec104.PairShape) bool    { return true }
func (iecPairAdapter) Charge(s iec104.PairShape) int64 { return 128 + int64(len(s.Objects))*40 }
func (iecPairAdapter) Copy(s iec104.PairShape) iec104.PairShape {
	s.Objects = slices.Clone(s.Objects)
	return s
}
func (iecPairAdapter) Advance(q iec104.PairShape, p pairProgress, r iec104.PairShape) (pairProgress, bool, pairReason) {
	row, ok := iecProcedureFor(q.TypeID)
	if !ok || q.CA != r.CA || q.Originator != r.Originator || q.Test != r.Test || r.Format != "I" {
		return p, false, pairMismatch
	}
	if p.Closed {
		// A negative confirmation ends data authority immediately. Retain only
		// this bounded, exact request echo for one terminal error indication.
		if row.Variants&iecNegativeError != 0 && iecErrorCause(r.Cause) && q.TypeID == r.TypeID && slices.Equal(q.Objects, r.Objects) {
			return p, true, pairOK
		}
		return p, false, pairUnpaired
	}
	if r.TypeID == q.TypeID && r.Negative && r.Cause == row.ConfirmCause && slices.Equal(q.Objects, r.Objects) {
		p.Closed = true
		return p, false, pairOK
	}
	if row.Variants&iecOptionalReadConfirm != 0 {
		if p.Phase == 0 && r.TypeID == q.TypeID && r.Cause == row.ConfirmCause && slices.Equal(q.Objects, r.Objects) {
			p.Phase = 1
			return p, false, pairOK
		}
		if r.Cause != 5 || !iecMonitorType(r.TypeID) || len(r.Objects) != 1 || q.Objects[0].IOA != r.Objects[0].IOA {
			return p, false, pairMismatch
		}
		return p, true, pairOK
	}
	if r.TypeID == q.TypeID {
		objects := r.Objects
		if p.Phase == 1 && r.Cause == 10 && row.Variants&iecTerminationSelectEcho != 0 {
			objects = slices.Clone(objects)
			for i := range objects {
				objects[i].Select = q.Objects[0].Select
			}
		}
		if !slices.Equal(q.Objects, objects) {
			return p, false, pairMismatch
		}
		if p.Phase == 0 && r.Cause == row.ConfirmCause {
			if q.Objects[0].Select || !row.Termination {
				return p, true, pairOK
			}
			p.Phase = 1
			p.Replaceable = row.DataCauseLow == 0
			return p, false, pairOK
		}
		if p.Phase == 1 && r.Cause == 10 && row.Termination {
			return p, true, pairOK
		}
		return p, false, pairMismatch
	}
	if p.Phase == 1 && r.Cause >= row.DataCauseLow && r.Cause <= row.DataCauseHigh && row.DataCauseLow != 0 {
		if q.TypeID == 100 && iecMonitorType(r.TypeID) && r.Cause == q.Objects[0].Qualifier {
			return p, false, pairOK
		}
		if q.TypeID == 101 && (r.TypeID == 15 || r.TypeID == 37) && slices.Contains(iecCounterCauses[(q.Objects[0].Qualifier&63)-1], r.Cause) {
			return p, false, pairOK
		}
	}
	return p, false, pairMismatch
}

func iecErrorCause(cause uint8) bool { return cause >= 44 && cause <= 47 }

func (iecPairAdapter) Unit(s iec104.PairShape) dpi.ParsedUnit { return &iec104.Unit{PairShape: s} }
