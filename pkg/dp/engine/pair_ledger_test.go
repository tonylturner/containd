// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func pairResources() limits.Resources { return limits.NewResources(limits.NewBudget(16<<20), nil) }
func pairMB(s modbus.PairShape) dpi.DecodedFrame {
	return dpi.DecodedFrame{Start: 0, End: 1, Unit: &modbus.Unit{PairShape: s}}
}
func pairDN(s dnp3.PairShape) dpi.DecodedFrame {
	return dpi.DecodedFrame{Start: 0, End: 1, Unit: &dnp3.Unit{PairShape: s}}
}
func pairIE(s iec104.PairShape) dpi.DecodedFrame {
	return dpi.DecodedFrame{Start: 0, End: 1, Unit: &iec104.Unit{PairShape: s}}
}
func pairRead(tid uint16) modbus.PairShape {
	return modbus.PairShape{TransactionID: tid, UnitID: 1, FunctionCode: 3, Quantity: 2, Spans: []modbus.Span{{First: 10, Last: 11}}}
}
func pairMBReply(q modbus.PairShape) modbus.PairShape {
	q.Response = true
	q.ByteCount = uint8(q.Quantity * 2)
	q.Spans = nil
	return q
}

func TestDS34Ledger(t *testing.T) {
	now := time.Unix(1000, 0)
	t.Run("release-not-classification", func(t *testing.T) {
		b := newPairing("modbus", pairResources(), false, nil)
		defer b.close()
		q := pairRead(1)
		r := pairMBReply(q)
		if c, why := b.inspect(pairMB(q), dpi.ClientToServer, now); c != rules.ClassRequest || why != pairOK {
			t.Fatal(c, why)
		}
		if _, why := b.inspect(pairMB(r), dpi.ServerToClient, now); why != pairUnpaired {
			t.Fatal(why)
		}
		if why := b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		if _, why := b.inspect(pairMB(r), dpi.ServerToClient, now); why != pairOK {
			t.Fatal(why)
		}
		if why := b.apply(pairMB(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		if _, why := b.inspect(pairMB(r), dpi.ServerToClient, now); why != pairUnpaired {
			t.Fatal("double consumption", why)
		}
	})
	t.Run("cap-oldest-expiry", func(t *testing.T) {
		total := 0
		r := pairResources()
		b := newPairing("modbus", r, false, &total)
		defer b.close()
		for i := range 65 {
			if why := b.apply(pairMB(pairRead(uint16(i))), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(i, why)
			}
		}
		if total != 64 {
			t.Fatal(total)
		}
		if _, why := b.inspect(pairMB(pairMBReply(pairRead(0))), dpi.ServerToClient, now); why != pairExpired {
			t.Fatal(why)
		}
		if _, why := b.inspect(pairMB(pairMBReply(pairRead(64))), dpi.ServerToClient, now.Add(30*time.Second)); why != pairExpired {
			t.Fatal(why)
		}
		b.close()
		if total != 0 || r.Budget.Status().InUse != 0 {
			t.Fatal(total, r.Budget.Status())
		}
	})
	t.Run("tid-reuse-other-function", func(t *testing.T) {
		b := newPairing("modbus", pairResources(), false, nil)
		defer b.close()
		q := pairRead(7)
		b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now)
		q.FunctionCode = 4
		if why := b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now); why != pairAmbiguous {
			t.Fatal(why)
		}
		for _, fc := range []uint8{3, 4} {
			q.FunctionCode = fc
			if _, why := b.inspect(pairMB(pairMBReply(q)), dpi.ServerToClient, now); why != pairAmbiguous {
				t.Fatal(fc, why)
			}
		}
	})
	t.Run("owned-request-context", func(t *testing.T) {
		r := pairResources()
		b := newPairing("modbus", r, false, nil).(*pairLedger[modbusPairKey, modbus.PairShape])
		defer b.close()
		q := pairRead(1)
		unit := uint8(1)
		permit := requestPermit{Contexts: []rules.EvalContext{{ICS: &rules.ICSContext{UnitID: &unit, Spans: []rules.AddressSpan{{Low: 10, High: 11}}}}}}
		b.apply(pairMB(q), dpi.ClientToServer, permit, now)
		q.Spans[0].Last = 999
		unit = 9
		permit.Contexts[0].ICS.Spans[0].High = 999
		g := b.grants[0]
		if g.Request.Spans[0].Last != 11 || *g.Permit.Contexts[0].ICS.UnitID != 1 || g.Permit.Contexts[0].ICS.Spans[0].High != 11 {
			t.Fatal(g)
		}
	})
}

func TestDS34Modbus(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, fc := range []uint8{1, 2, 3, 4, 5, 6, 15, 16, 22, 23} {
		t.Run(string(rune('A'+fc)), func(t *testing.T) {
			q := pairRead(uint16(fc))
			q.FunctionCode = fc
			q.Address, q.Value, q.AndMask, q.OrMask, q.ReadQuantity = 10, 0xff00, 0x1234, 0x5678, 2
			r := pairMBReply(q)
			switch fc {
			case 1, 2:
				r.ByteCount = 1
			case 23:
				r.ByteCount = 4
			}
			b := newPairing("modbus", pairResources(), false, nil)
			defer b.close()
			if _, why := b.inspect(pairMB(r), dpi.ServerToClient, now); why != pairUnpaired {
				t.Fatal(why)
			}
			if why := b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			if why := b.apply(pairMB(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			for _, exception := range []uint8{1, 2, 3, 4, 5, 6, 8, 10, 11} {
				b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now)
				x := r
				x.Exception = true
				x.ExceptionCode = exception
				if why := b.apply(pairMB(x), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
					t.Fatal(exception, why)
				}
			}
			b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now)
			bad := r
			switch fc {
			case 1, 2, 3, 4, 23:
				bad.ByteCount += 2
			case 5, 6:
				bad.Value ^= 1
			case 15, 16:
				bad.Quantity++
			case 22:
				bad.AndMask ^= 1
			}
			if _, why := b.inspect(pairMB(bad), dpi.ServerToClient, now); why != pairMismatch {
				t.Fatal("mismatch", why)
			}
		})
	}
	for _, fc := range []uint8{8, 43, 99} {
		q := pairRead(1)
		q.FunctionCode = fc
		b := newPairing("modbus", pairResources(), false, nil)
		if _, why := b.inspect(pairMB(q), dpi.ClientToServer, now); why != pairUnsupported {
			t.Fatal(fc, why)
		}
		b.close()
	}
}

func TestDS34DNP3(t *testing.T) {
	now := time.Unix(1000, 0)
	q := dnp3.PairShape{Link: dnp3.LinkProvenance{Source: 1, Destination: 2, Master: true}, FunctionCode: 1, Sequence: 15, FIR: true, FIN: true,
		Objects: []dnp3.ObjectHeader{{Group: 60, Variation: 2, HasCount: true, HasVariation: true, HasQualifier: true, Qualifier: 6, Addressing: "all"}}}
	response := func(seq uint8, fir, fin bool) dnp3.PairShape {
		return dnp3.PairShape{Link: dnp3.LinkProvenance{Source: 2, Destination: 1}, FunctionCode: 129, Sequence: seq, FIR: fir, FIN: fin}
	}
	t.Run("multiple-wraps-and-stations", func(t *testing.T) {
		b := newPairing("dnp3", pairResources(), false, nil)
		defer b.close()
		if why := b.apply(pairDN(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		for i := range 34 {
			r := response(uint8(15+i)&15, i == 0, i == 33)
			if why := b.apply(pairDN(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal(i, why)
			}
		}
		if _, why := b.inspect(pairDN(response(1, false, true)), dpi.ServerToClient, now); why != pairUnpaired {
			t.Fatal(why)
		}
		b.apply(pairDN(q), dpi.ClientToServer, requestPermit{}, now)
		r := response(15, true, true)
		r.Link.Source = 3
		if _, why := b.inspect(pairDN(r), dpi.ServerToClient, now); why != pairUnpaired {
			t.Fatal(why)
		}
		r.Link.Source = 2
		if _, why := b.inspect(pairDN(r), dpi.ServerToClient, now.Add(30*time.Second)); why != pairExpired {
			t.Fatal(why)
		}
	})
	t.Run("autonomous-and-session", func(t *testing.T) {
		b := newPairing("dnp3", pairResources(), true, nil)
		defer b.close()
		r := response(3, true, false)
		r.FunctionCode = 130
		r.UNS = true
		if class, why := b.inspect(pairDN(r), dpi.ServerToClient, now); class != rules.ClassAutonomous || why != pairOK {
			t.Fatal(class, why)
		}
		if why := b.apply(pairDN(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		r.Sequence = 4
		r.FIR = false
		r.FIN = true
		if why := b.apply(pairDN(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		r.FunctionCode = 129
		if _, why := b.inspect(pairDN(r), dpi.ServerToClient, now); why != pairUnsupported {
			t.Fatal(why)
		}
		c := q
		c.FunctionCode = 0
		c.Objects = nil
		c.UNS = true
		if class, why := b.inspect(pairDN(c), dpi.ClientToServer, now); class != rules.ClassSession || why != pairOK {
			t.Fatal(class, why)
		}
		c.Link.Confirmed = true
		c.FunctionCode = 1
		if _, why := b.inspect(pairDN(c), dpi.ClientToServer, now); why != pairUnsupported {
			t.Fatal(why)
		}
	})
}

func TestDS34Budget(t *testing.T) {
	t.Run("pairing-refusal-and-churn", func(t *testing.T) {
		now := time.Unix(1, 0)
		for _, observe := range []bool{false, true} {
			r := limits.NewResources(limits.NewBudget(1), nil)
			b := newPairing("modbus", r, observe, nil)
			if why := b.apply(pairMB(pairRead(1)), dpi.ClientToServer, requestPermit{}, now); why != stateLimit {
				t.Fatal(why)
			}
			b.close()
			if r.Budget.Status().InUse != 0 {
				t.Fatal(r.Budget.Status())
			}
		}
		r := pairResources()
		for wave := range 12 {
			b := newPairing("modbus", r, true, nil)
			for i := range 640 {
				b.apply(pairMB(pairRead(uint16(i))), dpi.ClientToServer, requestPermit{}, now.Add(time.Duration(wave)*time.Minute))
			}
			b.expire(now.Add(time.Duration(wave+1) * time.Minute))
			b.close()
			if r.Budget.Status().InUse != 0 {
				t.Fatal(wave, r.Budget.Status())
			}
		}
	})
}
