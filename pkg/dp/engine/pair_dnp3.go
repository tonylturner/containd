// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type dnp3PairKey struct {
	Dir                dpi.StreamDir
	Master, Outstation uint16
	Channel            uint8
}
type dnp3PairAdapter struct{}

func (dnp3PairAdapter) Classify(f dpi.DecodedFrame, dir dpi.StreamDir) (rules.MessageClass, dnp3PairKey, dnp3.PairShape, pairReason) {
	u, ok := f.Unit.(*dnp3.Unit)
	if !ok {
		return rules.ClassUnknown, dnp3PairKey{}, dnp3.PairShape{}, pairUnsupported
	}
	s, err := dnp3.PairingShape(u)
	k := dnp3PairKey{Dir: dpi.ClientToServer, Master: s.Link.Source, Outstation: s.Link.Destination}
	if !s.Link.Master {
		k.Master, k.Outstation = k.Outstation, k.Master
	}
	if s.UNS {
		k.Channel = 1
	}
	if err != nil || dir == dpi.DirUnknown || s.Link.Master != (dir == dpi.ClientToServer) {
		return rules.ClassUnknown, k, s, pairUnsupported
	}
	if s.LinkOnly || s.FunctionCode == 0 {
		return rules.ClassSession, k, s, pairOK
	}
	if s.FunctionCode == 130 && s.UNS && dir == dpi.ServerToClient {
		return rules.ClassAutonomous, k, s, pairOK
	}
	if s.FunctionCode == 129 && !s.UNS && dir == dpi.ServerToClient {
		return rules.ClassSolicited, k, s, pairOK
	}
	if s.FunctionCode < 129 && dir == dpi.ClientToServer {
		return rules.ClassRequest, k, s, pairOK
	}
	return rules.ClassUnknown, k, s, pairUnsupported
}
func (dnp3PairAdapter) Matches(a, b dnp3PairKey) bool         { return a == b }
func (dnp3PairAdapter) Conflicts(a, b dnp3PairKey) bool       { return a == b }
func (dnp3PairAdapter) Lifetime(dnp3.PairShape) time.Duration { return 30 * time.Second }
func (dnp3PairAdapter) Grants(s dnp3.PairShape) bool {
	return s.FunctionCode != 6 && s.FunctionCode != 8 && s.FunctionCode != 10
}
func (dnp3PairAdapter) Charge(s dnp3.PairShape) int64 {
	n := int64(128 + len(s.Objects)*160)
	for _, h := range s.Objects {
		n += int64(len(h.Points))*128 + int64(len(h.DataDigest)+len(h.Addressing))
	}
	return n
}
func (dnp3PairAdapter) Copy(s dnp3.PairShape) dnp3.PairShape {
	o := make([]dnp3.ObjectHeader, len(s.Objects))
	copy(o, s.Objects)
	for i := range o {
		h := &o[i]
		h.Start, h.Stop = pairCopyPtr(h.Start), pairCopyPtr(h.Stop)
		h.Points = append([]dnp3.Point(nil), h.Points...)
		for j := range h.Points {
			p := &h.Points[j]
			p.Index, p.CROB, p.Value = pairCopyPtr(p.Index), pairCopyPtr(p.CROB), pairCopyPtr(p.Value)
		}
	}
	s.Objects = o
	return s
}
func (dnp3PairAdapter) Advance(q dnp3.PairShape, p pairProgress, r dnp3.PairShape) (pairProgress, bool, pairReason) {
	if r.FunctionCode != 129 || r.UNS || r.Sequence != p.ExpectedSequence || r.FIR != (p.Fragments == 0) {
		return p, false, pairMismatch
	}
	if !dnp3ResponseObjects(q, r) {
		return p, false, pairMismatch
	}
	p.ExpectedSequence = (r.Sequence + 1) & 15
	p.Fragments++
	return p, r.FIN, pairOK
}
func dnp3ResponseObjects(q, r dnp3.PairShape) bool {
	switch q.FunctionCode {
	case 1:
		for _, rh := range r.Objects {
			found := false
			for _, qh := range q.Objects {
				family := qh.Group == rh.Group && (qh.Variation == 0 || qh.Variation == rh.Variation)
				if qh.Group == 60 {
					if qh.Variation == 1 {
						switch rh.Group {
						case 1, 3, 10, 20, 30, 40:
							family = true
						}
					} else {
						switch rh.Group {
						case 2, 4, 11, 22, 32, 42:
							family = true
						}
					}
				}
				if family && dnp3IndexesWithin(qh, rh) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case 2:
		return len(r.Objects) == 0 || dnp3Echoes(q.Objects, r.Objects, false)
	case 3, 4, 5:
		return dnp3Echoes(q.Objects, r.Objects, true)
	case 13, 14, 23:
		return len(r.Objects) == 1 && r.Objects[0].Group == 52 && (r.Objects[0].Variation == 1 || r.Objects[0].Variation == 2) && r.Objects[0].Count == 1
	case 24, 20, 21:
		return len(r.Objects) == 0
	default:
		return false
	}
}
func dnp3IndexesWithin(q, r dnp3.ObjectHeader) bool {
	if q.Addressing == "all" {
		return true
	}
	within := func(v uint32) bool {
		if q.Start != nil && q.Stop != nil {
			return v >= *q.Start && v <= *q.Stop
		}
		for _, p := range q.Points {
			if p.Index != nil && *p.Index == v {
				return true
			}
		}
		return false
	}
	if len(r.Points) == 0 {
		return r.Count == 0
	}
	for _, p := range r.Points {
		if p.Index == nil || !within(*p.Index) {
			return false
		}
	}
	return true
}
func dnp3Echoes(q, r []dnp3.ObjectHeader, status bool) bool {
	if len(q) != len(r) {
		return false
	}
	for i, a := range q {
		b := r[i]
		if a.Group != b.Group || a.Variation != b.Variation || a.Count != b.Count || len(a.Points) != len(b.Points) {
			return false
		}
		for j, x := range a.Points {
			y := b.Points[j]
			if !pairEqualPtr(x.Index, y.Index) {
				return false
			}
			if (x.CROB == nil) != (y.CROB == nil) || (x.Value == nil) != (y.Value == nil) {
				return false
			}
			if x.CROB != nil {
				u, v := *x.CROB, *y.CROB
				if status {
					u.Status, v.Status = 0, 0
				}
				if u != v {
					return false
				}
			}
			if x.Value != nil {
				u, v := *x.Value, *y.Value
				if status {
					u.Status, v.Status = 0, 0
				}
				if u != v {
					return false
				}
			}
		}
	}
	return true
}
