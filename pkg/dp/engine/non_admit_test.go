// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestNonAdmitStreamRetries(t *testing.T) {
	protocols := append(firstCommandProtocols(), firstCommandProtocol{
		name: "cip", port: 44818, read: func(uint16) []byte { return cipStreamRead() },
	})
	for _, proto := range protocols {
		for _, action := range []rules.Action{"", rules.ActionDeny, rules.ActionReset} {
			t.Run(fmt.Sprint(proto.name, "/", action), func(t *testing.T) {
				f := newFCFlow(t, "ok", proto.port)
				scope := rules.Entry{ID: "inspect", Action: rules.ActionAllow,
					ICS: rules.ICSPredicate{Protocol: proto.name, Mode: "enforce", FunctionCode: []uint8{99}}}
				snap := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{scope}}
				if action != "" {
					snap.Default = rules.ActionAllow
					snap.Firewall = append([]rules.Entry{{ID: "plain", Action: action}}, snap.Firewall...)
				}
				f.e.LoadRules(snap)
				f.syn()
				payload := proto.read(1)
				check := func(d capture.Decision) {
					t.Helper()
					if d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark == 0 || d.Reason != reasonPolicyNonAdmit {
						t.Fatalf("lost non-admitting continuation: %+v", d)
					}
				}
				check(f.decide(0, ackPsh, payload))
				before := protoEvents(f.e, proto.name)
				f.e.verdictCache = NewVerdictCache(time.Nanosecond, 1)
				check(f.decide(0, ackPsh, payload))
				check(f.decide(1, ackPsh, payload[1:])) // resegmented retry
				check(f.establishedSyn(uint32(len(payload))))
				check(f.decide(uint32(len(payload)), ackPsh, proto.read(2)))
				if got := protoEvents(f.e, proto.name); got != before {
					t.Fatalf("denied bytes decoded again: %d -> %d", before, got)
				}
				if f.e.verdictCache.Len() != 0 {
					t.Fatal("kernel denial entered the userspace verdict cache")
				}
				// A genuinely new handshake retires the failed stream; an
				// allowed message on the new incarnation can pass.
				f.isn += 100000
				scope.ICS.FunctionCode = nil
				f.e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{scope}})
				f.syn()
				d := f.decide(0, ackPsh, proto.read(3))
				if d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark != 0 {
					t.Fatalf("new connection inherited non-admission: %+v", d)
				}
			})
		}
	}
}

func TestNonAdmitScopeRemoval(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	scope := rules.Entry{ID: "inspect", Action: rules.ActionAllow,
		ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", FunctionCode: []uint8{99}}}
	f.e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{scope}})
	f.syn()
	payload := modbusADU(1, 3, 0, 1)
	if d := f.decide(0, ackPsh, payload); d.Mark&markabi.NonAdmitMark == 0 {
		t.Fatalf("initial decision: %+v", d)
	}
	scope.ICS.Mode = "monitor"
	f.e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{scope}})
	if d := f.decide(0, ackPsh, payload); d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark != 0 {
		t.Fatalf("removed enforce scope retained admission authority: %+v", d)
	}
}
