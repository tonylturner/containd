// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
)

func testDS34ModbusKeys(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newPairing("modbus", pairResources(), false, nil)
	defer b.close()
	q := pairRead(1)
	if why := b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
		t.Fatal(why)
	}
	for _, key := range []string{"tid", "unit", "fc"} {
		t.Run(key, func(t *testing.T) {
			r := pairMBReply(q)
			switch key {
			case "tid":
				r.TransactionID++
			case "unit":
				r.UnitID++
			case "fc":
				r.FunctionCode = 4
			}
			if _, why := b.inspect(pairMB(r), dpi.ServerToClient, now); why != pairUnpaired {
				t.Fatal("foreign reply borrowed a grant", why)
			}
		})
	}
	q.UnitID = 0
	if _, why := b.inspect(pairMB(q), dpi.ClientToServer, now); why != pairUnsupported {
		t.Fatal("broadcast acquired request authority", why)
	}
	q.UnitID = 1
	// Independent pipelined transactions may complete in reverse order.
	q.TransactionID = 2
	if why := b.apply(pairMB(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
		t.Fatal(why)
	}
	for _, tid := range []uint16{2, 1} {
		if why := b.apply(pairMB(pairMBReply(pairRead(tid))), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
			t.Fatal(tid, why)
		}
	}
	if _, why := b.inspect(pairMB(pairMBReply(pairRead(1))), dpi.ServerToClient, now); why != pairUnpaired {
		t.Fatal("reply consumed twice", why)
	}
}

func testDS34DNP3Families(t *testing.T) {
	now := time.Unix(1000, 0)
	header := func(group, variation uint8) dnp3.ObjectHeader {
		return dnp3.ObjectHeader{Group: group, Variation: variation, HasCount: true,
			HasVariation: true, HasQualifier: true, Count: 1, Addressing: "count"}
	}
	request := func(fc uint8) dnp3.PairShape {
		return dnp3.PairShape{Link: dnp3.LinkProvenance{Source: 1, Destination: 2, Master: true},
			FunctionCode: fc, Sequence: 15, FIR: true, FIN: true}
	}
	response := func() dnp3.PairShape {
		return dnp3.PairShape{Link: dnp3.LinkProvenance{Source: 2, Destination: 1},
			FunctionCode: 129, Sequence: 15, FIR: true, FIN: true, CON: true}
	}
	for _, fc := range []uint8{1, 2, 3, 4, 5, 13, 14, 20, 21, 23, 24} {
		t.Run(fmt.Sprintf("fc=%d", fc), func(t *testing.T) {
			q, r := request(fc), response()
			switch fc {
			case 1, 20, 21:
				h := header(60, 2)
				h.Addressing = "all"
				q.Objects = []dnp3.ObjectHeader{h}
			case 2:
				q.Objects = []dnp3.ObjectHeader{header(50, 1)}
				r.Objects = q.Objects
			case 3, 4, 5:
				h := header(12, 1)
				index := uint32(17)
				h.Points = []dnp3.Point{{Index: &index, CROB: &dnp3.CROB{
					Control: 3, Operation: 3, OperationName: "latch_on", Count: 1, OnTime: 100,
				}}}
				q.Objects = []dnp3.ObjectHeader{h}
				r.Objects = dnp3PairAdapter{}.Copy(q).Objects
				r.Objects[0].Points[0].CROB.Status = 1 // response status is not an echo mismatch
			}
			if fc == 13 || fc == 14 || fc == 23 {
				r.Objects = []dnp3.ObjectHeader{header(52, 2)}
			}
			b := newPairing("dnp3", pairResources(), false, nil)
			defer b.close()
			if why := b.apply(pairDN(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal("request", why)
			}
			bad := r
			bad.Objects = []dnp3.ObjectHeader{header(1, 2)}
			if _, why := b.inspect(pairDN(bad), dpi.ServerToClient, now); why != pairMismatch {
				t.Fatal("wrong response family", why)
			}
			if fc == 3 || fc == 4 || fc == 5 {
				for _, field := range []string{"index", "control", "count", "on-time", "off-time"} {
					bad := dnp3PairAdapter{}.Copy(r)
					p := &bad.Objects[0].Points[0]
					switch field {
					case "index":
						*p.Index++
					case "control":
						p.CROB.Control, p.CROB.Operation, p.CROB.OperationName = 4, 4, "latch_off"
					case "count":
						p.CROB.Count++
					case "on-time":
						p.CROB.OnTime++
					case "off-time":
						p.CROB.OffTime++
					}
					if _, why := b.inspect(pairDN(bad), dpi.ServerToClient, now); why != pairMismatch {
						t.Fatal("wrong control echo", field, why)
					}
				}
			}
			if why := b.apply(pairDN(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal("valid response requiring Confirm was not released", why)
			}
			confirm := request(0)
			confirm.Sequence, confirm.UNS = r.Sequence, r.UNS
			if why := b.apply(pairDN(confirm), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal("session Confirm", why)
			}
			if _, why := b.inspect(pairDN(r), dpi.ServerToClient, now); why != pairUnpaired {
				t.Fatal("Confirm created a grant", why)
			}
		})
	}
	for _, fc := range []uint8{6, 8, 10} {
		t.Run(fmt.Sprintf("no-response=%d", fc), func(t *testing.T) {
			q := request(fc)
			group := uint8(20)
			if fc == 6 {
				group = 12
			}
			q.Objects = []dnp3.ObjectHeader{header(group, 1)}
			b := newPairing("dnp3", pairResources(), false, nil)
			defer b.close()
			if why := b.apply(pairDN(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			if _, why := b.inspect(pairDN(response()), dpi.ServerToClient, now); why != pairUnpaired {
				t.Fatal("no-response request granted a response", why)
			}
		})
	}
}

func testDS34IECMismatchStages(t *testing.T) {
	now := time.Unix(1000, 0)
	base := iec104.PairShape{Format: "I", TypeID: 59, Cause: 6, CA: 1,
		Objects: []iec104.Object{{IOA: 101, ValueBits: 2, Time: [7]byte{0, 0, 1, 2, 3, 4, 26}}}}
	for _, field := range []string{"ca", "ioa", "type", "value", "time", "originator", "select", "test", "termination-first"} {
		t.Run(field, func(t *testing.T) {
			b := newPairing("iec104", pairResources(), false, nil)
			defer b.close()
			if why := b.apply(pairIE(base), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			r := iecPairAdapter{}.Copy(base)
			r.Cause = 7
			want := pairMismatch
			switch field {
			case "ca":
				r.CA++
				want = pairUnpaired
			case "ioa":
				r.Objects[0].IOA++
				want = pairUnpaired
			case "type":
				r.TypeID = 58
				want = pairUnpaired
			case "value":
				r.Objects[0].ValueBits ^= 1
			case "time":
				r.Objects[0].Time[0]++
			case "originator":
				r.Originator++
				want = pairUnpaired
			case "select":
				r.Objects[0].Select = true
				want = pairUnpaired
			case "test":
				r.Test = true
			case "termination-first":
				r.Cause = 10
			}
			if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != want {
				t.Fatal("incompatible confirmation", why, "want", want)
			}
			r = base
			r.Cause, r.Negative = 7, true
			if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal("negative confirmation", why)
			}
			r.Cause, r.Negative = 10, false
			if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != pairUnpaired {
				t.Fatal("negative confirmation was not terminal", why)
			}
		})
	}
	t.Run("select-does-not-authorize-execute", func(t *testing.T) {
		b := newPairing("iec104", pairResources(), false, nil)
		defer b.close()
		q := iecPairAdapter{}.Copy(base)
		q.Objects[0].Select = true
		if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		q.Cause = 7
		if why := b.apply(pairIE(q), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		q.Objects[0].Select = false
		if _, why := b.inspect(pairIE(q), dpi.ServerToClient, now); why != pairUnpaired {
			t.Fatal("selection authorized execute", why)
		}
	})
	t.Run("gi-order-expiry-and-ambiguity", func(t *testing.T) {
		for _, elapsed := range []time.Duration{0, 30 * time.Second} {
			b := newPairing("iec104", pairResources(), false, nil)
			q := iec104.PairShape{Format: "I", TypeID: 100, Cause: 6, CA: 1, Objects: []iec104.Object{{Qualifier: 20}}}
			if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			r := iec104.PairShape{Format: "I", TypeID: 1, Cause: 20, CA: 1, Objects: []iec104.Object{{IOA: 1}}}
			if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != pairMismatch {
				t.Fatal("GI data before confirmation", why)
			}
			confirm := q
			confirm.Cause = 7
			if why := b.apply(pairIE(confirm), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			want := pairOK
			if elapsed != 0 {
				want = pairExpired
			}
			if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now.Add(elapsed)); why != want {
				t.Fatal("GI deadline", why)
			}
			b.close()
		}
		b := newPairing("iec104", pairResources(), false, nil)
		defer b.close()
		if why := b.apply(pairIE(base), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
			t.Fatal(why)
		}
		if why := b.apply(pairIE(base), dpi.ClientToServer, requestPermit{}, now); why != pairAmbiguous {
			t.Fatal("concurrent identical procedure", why)
		}
	})
}
