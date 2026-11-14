// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestIECDirectNegativeMirrorStages(t *testing.T) {
	for _, row := range iecProcedures {
		requests := []iec104.PairShape{directIECRequest(row)}
		switch {
		case row.Type == 100:
			for group := uint8(21); group <= 36; group++ {
				q := iecPairAdapter{}.Copy(requests[0])
				q.Objects[0].Qualifier = group
				requests = append(requests, q)
			}
		case row.Type == 101:
			for group := uint8(2); group <= 5; group++ {
				q := iecPairAdapter{}.Copy(requests[0])
				q.Objects[0].Qualifier = group
				requests = append(requests, q)
			}
		case row.Type < 100:
			q := iecPairAdapter{}.Copy(requests[0])
			q.Objects[0].Select = true
			requests = append(requests, q)
		}
		for i, q := range requests {
			for cause := uint8(44); cause <= 47; cause++ {
				t.Run(fmt.Sprintf("type=%d/request=%d/cause=%d", row.Type, i, cause), func(t *testing.T) {
					now := time.Unix(1000, 0)
					b := newPairing("iec104", pairResources(), false, nil)
					defer b.close()
					if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
						t.Fatal("request", why)
					}
					r := iecPairAdapter{}.Copy(q)
					r.Cause, r.Negative = cause, true
					state, terminal, why := (iecPairAdapter{}).Advance(q, pairProgress{}, r)
					if why != pairOK || !state.Closed || state.Phase != iecDirectErrorPhase || terminal {
						t.Fatalf("mirror must close authority and retain only mismatch history: %+v %t %s", state, terminal, why)
					}
					if class, why := b.inspect(pairIE(r), dpi.ServerToClient, now); class != rules.ClassSolicited || why != pairOK {
						t.Fatal("mirror classification", class, why)
					}
					if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
						t.Fatal("mirror", why)
					}
					// Neither a second mirror nor confirmation/termination may
					// resurrect the rejected request's response authority.
					laterCauses := []uint8{cause, 7}
					if row.Termination {
						laterCauses = append(laterCauses, 10)
					}
					for _, laterCause := range laterCauses {
						later := iecPairAdapter{}.Copy(r)
						later.Cause = laterCause
						if laterCause < 44 {
							later.Negative = false
						}
						if _, _, why := (iecPairAdapter{}).Advance(q, state, later); why != pairMismatch {
							t.Fatal("closed adapter accepted later reply", laterCause, why)
						}
						if _, why := b.inspect(pairIE(later), dpi.ServerToClient, now); why != pairMismatch {
							t.Fatal("closed ledger accepted later reply", laterCause, why)
						}
					}
					if row.Type == 100 || row.Type == 101 || row.Type == 102 {
						data := iecPairAdapter{}.Copy(q)
						data.TypeID, data.Cause = 1, 5
						switch row.Type {
						case 100:
							data.Cause = q.Objects[0].Qualifier
						case 101:
							data.TypeID, data.Cause = 15, 37
						}
						if _, why := b.inspect(pairIE(data), dpi.ServerToClient, now); why != pairMismatch {
							t.Fatal("closed request authorized data", why)
						}
					}
					if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
						t.Fatal("fresh request failed to replace closed history", why)
					}
				})
			}
		}
	}
}

func directIECRequest(row iecProcedure) iec104.PairShape {
	q := iec104.PairShape{Format: "I", TypeID: row.Type, Cause: row.RequestCause, CA: 1,
		Objects: []iec104.Object{{IOA: 101, ValueBits: 1}}}
	switch row.Type {
	case 100:
		q.Objects[0].IOA, q.Objects[0].Qualifier = 0, 20
	case 101:
		q.Objects[0].IOA, q.Objects[0].Qualifier = 0, 1
	case 103, 107:
		q.Objects[0].IOA = 0
	}
	return q
}

func TestIECDirectNegativeMirrorCoverage(t *testing.T) {
	row, _ := iecProcedureFor(46)
	q := directIECRequest(row)
	for _, field := range []string{"ioa", "ca", "type", "originator", "value", "select", "time", "test", "positive", "after-confirmation"} {
		for cause := uint8(44); cause <= 47; cause++ {
			t.Run(fmt.Sprintf("%s/cause=%d", field, cause), func(t *testing.T) {
				r := iecPairAdapter{}.Copy(q)
				r.Cause, r.Negative = cause, true
				state := pairProgress{}
				switch field {
				case "ioa":
					r.Objects[0].IOA++
				case "ca":
					r.CA++
				case "type":
					r.TypeID = 47
				case "originator":
					r.Originator++
				case "value":
					r.Objects[0].ValueBits++
				case "select":
					r.Objects[0].Select = true
				case "time":
					r.Objects[0].Time[0]++
				case "test":
					r.Test = true
				case "positive":
					r.Negative = false
				case "after-confirmation":
					state.Phase = 1
				}
				if _, _, why := (iecPairAdapter{}).Advance(q, state, r); why != pairMismatch {
					t.Fatal("non-mirror or wrong stage accepted", why)
				}
			})
		}
	}
	// P/N=0 remains a mismatch for every procedure, including optional Read
	// confirmation and global interrogation stages.
	for _, row := range iecProcedures {
		t.Run("positive/type="+iecTypeName(row.Type), func(t *testing.T) {
			now := time.Unix(1000, 0)
			b := newPairing("iec104", pairResources(), false, nil)
			defer b.close()
			q := directIECRequest(row)
			if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			for cause := uint8(44); cause <= 47; cause++ {
				r := iecPairAdapter{}.Copy(q)
				r.Cause = cause
				if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != pairMismatch {
					t.Fatal("direct positive error", cause, why)
				}
			}
		})
	}
}

// Direct negative error mirrors replace activation confirmation on the wire.
func TestIECDirectErrorCauseReply(t *testing.T) {
	for _, cause := range []byte{44, 45, 46, 47} {
		t.Run(fmt.Sprint(cause), func(t *testing.T) {
			e, p := repeatedIECEngine(t)
			if d := sendInline(e, runtimePairPacket(p, false, 100, p.request)); d.Action != capture.Repeat {
				t.Fatalf("execute=%+v", d)
			}
			mirror := apdu(46, cause|0x40, 1, 101, 2)
			if d := sendInline(e, runtimePairPacket(p, true, 500, mirror)); d.Action != capture.Repeat {
				t.Fatalf("direct negative COT %d mirror=%+v", cause, d)
			}
			if d := sendInline(e, runtimePairPacket(p, true, 500+uint32(len(mirror)), p.reply)); d.Action != capture.Drop || d.Reason != string(pairMismatch) {
				t.Fatalf("reply after terminal mirror=%+v", d)
			}
		})
	}
}
