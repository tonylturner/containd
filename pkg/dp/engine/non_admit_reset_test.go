// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestNonAdmitResetAfterVerdict(t *testing.T) {
	for _, reconnectBeforeVerdict := range []bool{false, true} {
		name := "completed"
		if reconnectBeforeVerdict {
			name = "retired"
		}
		t.Run(name, func(t *testing.T) {
			f := newResetFlow(t, 502)
			scope := rules.Entry{ID: "read", Action: rules.ActionAllow,
				ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", FunctionCode: []uint8{3}}}
			f.e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{scope}})
			f.syn()
			f.synAck()
			pkt := f.segment(false, f.isn, 9000, ackPsh, modbusADU(1, 6, 1, 1))
			pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
			d := f.e.HandlePacket(pkt)
			if d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark == 0 || !d.Notify {
				t.Fatalf("initial continuation must request completion: %+v", d)
			}
			drainResetWorker(t, f.e)
			if len(f.inj.Resets()) != 0 {
				t.Fatal("reset before continuation completion")
			}
			// Neither a retry nor otherwise allowed new bytes create another
			// follow-up job, even while the first verdict is still pending.
			for _, payload := range [][]byte{pkt.Payload, modbusADU(2, 3, 0, 1)} {
				later := f.segment(false, f.isn, 9000, ackPsh, payload)
				if d := f.handle(later); d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark == 0 || d.Notify {
					t.Fatalf("failed stream changed verdict or scheduled another reset: %+v", d)
				}
			}
			if reconnectBeforeVerdict {
				f.isn += 100000
				f.syn()
				f.synAck()
			}
			f.e.hooks.onVerdict(pkt.Token, capture.VerdictRepeat, nil)
			drainResetWorker(t, f.e)
			client, server := f.endpoints()
			want := []session.Reset{{Src: client, Dst: server, Seq: pkt.TCP.Seq}, {Src: server, Dst: client, Seq: 9000}}
			if reconnectBeforeVerdict {
				want = nil // a delayed reset must not hit the new incarnation
			} else {
				f.waitResets(2)
			}
			if got := f.inj.Resets(); !reflect.DeepEqual(got, want) {
				t.Fatalf("resets %+v, want %+v", got, want)
			}
			if !reconnectBeforeVerdict {
				f.isn += 100000
				f.syn()
				f.synAck()
			}
			if d := f.decide(0, ackPsh, modbusADU(3, 3, 0, 1)); d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark != 0 {
				t.Fatalf("reconnect inherited denial: %+v", d)
			}
			drainResetWorker(t, f.e)
			if len(f.inj.Resets()) != len(want) {
				t.Fatal("reconnect scheduled another reset")
			}
		})
	}
}
