// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func testIECSettledVariants(t *testing.T) {
	now := time.Unix(1000, 0)
	t.Run("no-pending-expectations", func(t *testing.T) {
		for _, pending := range []string{`[]`, `[{"decision":"unsettled","ids":["x"]}]`, `null`} {
			var out iecOracleExpectations
			if err := decodeIECJSON(strings.NewReader(`{"version":1,"outcomes":[],"pending":`+pending+`}`), &out); err == nil {
				t.Fatal("loader accepted pending field", pending)
			}
		}
	})
	t.Run("reset-105-unsupported", func(t *testing.T) {
		p := runtimePairCases()[2]
		e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
		inlineHandshake(t, e, 41000, p.port)
		d := e.HandlePacket(runtimePairPacket(p, false, 100, apdu(105, 6, 1, 0, 1)))
		if d.Action != capture.Drop || d.Reason != string(pairUnsupported) || e.sessions.pairingTotal != 0 {
			t.Fatalf("unsupported reset acquired authority: %+v", d)
		}
	})
	for group := uint8(1); group <= 5; group++ {
		for cause := uint8(37); cause <= 41; cause++ {
			t.Run(fmt.Sprintf("counter/group=%d/cause=%d", group, cause), func(t *testing.T) {
				b := newPairing("iec104", pairResources(), false, nil)
				defer b.close()
				q := iec104.PairShape{Format: "I", TypeID: 101, Cause: 6, CA: 1, Objects: []iec104.Object{{Qualifier: group}}}
				if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
					t.Fatal(why)
				}
				r := q
				r.Cause = 7
				if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
					t.Fatal(why)
				}
				r.TypeID, r.Cause, r.Objects = 15, cause, []iec104.Object{{IOA: 100}}
				want := pairMismatch
				if cause == 37 || group < 5 && cause == 37+group {
					want = pairOK
				}
				if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != want {
					t.Fatal(why, "want", want)
				}
			})
		}
	}
	for group := uint8(21); group <= 36; group++ {
		t.Run(fmt.Sprintf("gi/group=%d", group), func(t *testing.T) {
			b := newPairing("iec104", pairResources(), false, nil)
			defer b.close()
			q := iec104.PairShape{Format: "I", TypeID: 100, Cause: 6, CA: 1, Objects: []iec104.Object{{Qualifier: group}}}
			if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			r := q
			r.Cause = 7
			if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal(why)
			}
			r.TypeID, r.Cause, r.Objects = 1, 20, []iec104.Object{{IOA: 100}}
			if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != pairMismatch {
				t.Fatal("group borrowed general GI data", why)
			}
			r.Cause = group
			if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal("matching group data", why)
			}
			r = q
			r.Cause = 10
			if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
				t.Fatal("termination", why)
			}
		})
	}
	t.Run("negative-terminal-coverage", func(t *testing.T) {
		q := iec104.PairShape{Format: "I", TypeID: 46, Cause: 6, CA: 1, Objects: []iec104.Object{{IOA: 100, ValueBits: 1}}}
		for _, field := range []string{"valid", "no-negative", "ca", "ioa", "type", "value", "test", "select", "originator", "expired", "data", "new-request"} {
			t.Run(field, func(t *testing.T) {
				total := 0
				b := newPairing("iec104", pairResources(), false, &total)
				defer b.close()
				if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
					t.Fatal(why)
				}
				negative := q
				negative.Cause, negative.Negative = 7, true
				if field != "no-negative" {
					if why := b.apply(pairIE(negative), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
						t.Fatal(why)
					}
				}
				r := iecPairAdapter{}.Copy(q)
				r.Cause, r.Negative = 44, true
				at, want := now, pairUnpaired
				switch field {
				case "valid":
					want = pairOK
				case "no-negative":
					want = pairMismatch
				case "ca":
					r.CA++
				case "ioa":
					r.Objects[0].IOA++
				case "type":
					r.TypeID = 45
				case "value":
					r.Objects[0].ValueBits++
				case "test":
					r.Test = true
					want = pairMismatch
				case "select":
					r.Objects[0].Select = true
				case "originator":
					r.Originator++
				case "expired":
					at, want = now.Add(15*time.Second), pairExpired
				case "data":
					r.Cause, r.Negative = 7, false
				case "new-request":
					if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK || total != 1 {
						t.Fatal("closed witness prevented a fresh request", why, total)
					}
					want = pairMismatch
				}
				if _, why := b.inspect(pairIE(r), dpi.ServerToClient, at); why != want {
					t.Fatal(why, "want", want)
				}
				if field == "valid" {
					if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, at); why != pairOK || total != 0 {
						t.Fatal("terminal error not consumed once", why, total)
					}
					if _, why := b.inspect(pairIE(r), dpi.ServerToClient, at); why != pairUnpaired {
						t.Fatal("terminal error consumed twice", why)
					}
				}
			})
		}
	})
	t.Run("inline-negative-error", func(t *testing.T) {
		for cause := byte(44); cause <= 47; cause++ {
			t.Run(fmt.Sprint(cause), func(t *testing.T) {
				p := runtimePairCases()[2]
				e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
				inlineHandshake(t, e, 41000, p.port)
				q := apdu(46, 6, 1, 100, 1)
				if d := e.HandlePacket(runtimePairPacket(p, false, 100, q)); d.Action != capture.Repeat {
					t.Fatal(d)
				}
				neg := apdu(46, 7|64, 1, 100, 1)
				if d := e.HandlePacket(runtimePairPacket(p, true, 500, neg)); d.Action != capture.Repeat {
					t.Fatal(d)
				}
				errReply := apdu(46, cause|64, 1, 100, 1)
				if d := e.HandlePacket(runtimePairPacket(p, true, 500+uint32(len(neg)), errReply)); d.Action != capture.Repeat {
					t.Fatalf("covered negative-terminal error: %+v", d)
				}
				if d := e.HandlePacket(runtimePairPacket(p, true, 500+uint32(len(neg)+len(errReply)), apdu(46, 7, 1, 100, 1))); d.Action != capture.Drop {
					t.Fatalf("terminal variant reopened data authority: %+v", d)
				}
			})
		}
	})
	t.Run("inline-tolerance-coverage", func(t *testing.T) {
		for _, variant := range []string{"read-confirm", "termination-select-echo"} {
			for _, wrong := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/wrong=%t", variant, wrong), func(t *testing.T) {
					p := runtimePairCases()[2]
					e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
					inlineHandshake(t, e, 41000, p.port)
					q, con, last := apdu(102, 5, 1, 100), apdu(102, 7, 1, 100), apdu(1, 5, 1, 100, 1)
					if wrong {
						last = apdu(1, 5, 1, 101, 1)
					}
					if variant == "termination-select-echo" {
						q, con, last = apdu(46, 6, 1, 100, 1), apdu(46, 7, 1, 100, 1), apdu(46, 10, 1, 100, 0x81)
						if wrong {
							last = apdu(46, 10, 1, 100, 0x82)
						}
					}
					if d := e.HandlePacket(runtimePairPacket(p, false, 100, q)); d.Action != capture.Repeat {
						t.Fatal(d)
					}
					if d := e.HandlePacket(runtimePairPacket(p, true, 500, con)); d.Action != capture.Repeat {
						t.Fatal(d)
					}
					want := capture.Repeat
					if wrong {
						want = capture.Drop
					}
					if d := e.HandlePacket(runtimePairPacket(p, true, 500+uint32(len(con)), last)); d.Action != want {
						t.Fatalf("variant changed request coverage: %+v", d)
					}
				})
			}
		}
	})
}
