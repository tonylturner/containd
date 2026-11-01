// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestTCP2404LifecycleOwnership(t *testing.T) {
	for _, observer := range []bool{false, true} {
		for _, scope := range []string{"no-rule", "outside", "owned"} {
			t.Run(scope+map[bool]string{false: "/without-observer", true: "/with-observer"}[observer], func(t *testing.T) {
				e := recordEngine(t)
				if !observer {
					e.observation = nil
				}
				if scope != "no-rule" {
					source := "10.0.0.1/32"
					if scope == "outside" {
						source = "192.0.2.1/32"
					}
					e.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{
						ID: "iec", Sources: []string{source},
						Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
						ICS:       rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"},
					}}})
				}
				pkt := recordPacket(100, 0, "")
				pkt.DstPort = 2404
				pkt.TCP.Flags = capture.TCPFlagSYN
				owned := scope == "owned"
				if got := e.iecOwnsPacket(pkt); got != owned {
					t.Fatalf("ownership = %v, want %v", got, owned)
				}

				unlock := e.lockGenericTCP(pkt)
				locked := 0
				for i := range e.tcpDecisions {
					if e.tcpDecisions[i].TryLock() {
						e.tcpDecisions[i].Unlock()
					} else {
						locked++
					}
				}
				unlock()
				if locked != map[bool]int{false: 1, true: 0}[owned] {
					t.Fatalf("decision stripes locked = %d, owned = %v", locked, owned)
				}

				st := e.trackFlow(pkt, pkt.Timestamp)
				e.bindTransport(st, nil)
				e.flowMu.Lock()
				e.noteTransportSYNLocked(pkt, st.Key)
				e.flowMu.Unlock()
				pkt.TCP.Seq++
				e.retireTransportIncarnation(pkt, nil)
				if retained := e.flows[st.Key.MapKey()] == st; retained != owned {
					t.Fatalf("old incarnation retained = %v, owned = %v", retained, owned)
				}

				guard := e.rememberDeniedTCP(st.Key, st.ServiceKey(), false)
				if guard == nil {
					t.Fatal("missing test tombstone")
				}
				markHandshake(&pkt)
				e.reopenDeniedTCP(pkt)
				if retained := e.deniedTCP[tcpTupleKey(st.Key)] != nil; retained != owned {
					t.Fatalf("tombstone retained = %v, owned = %v", retained, owned)
				}
			})
		}
	}
}
