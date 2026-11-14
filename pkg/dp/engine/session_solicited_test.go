// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

type runtimePairCase struct {
	protocol       string
	port           uint16
	request, reply []byte
}

func runtimePairCases() []runtimePairCase {
	return []runtimePairCase{
		{"modbus", 502, modbusADU(1, 3, 0, 2), []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2}},
		{"dnp3", dnp3Port, dnp3Read, dnp3Response},
		{"iec104", iec104Port, apdu(46, 6, 1, 101, 2), apdu(46, 7, 1, 101, 2)},
	}
}

func runtimePairRule(p runtimePairCase, mode string) rules.Entry {
	return rules.Entry{ID: "pair", Action: rules.ActionAllow, Log: true,
		Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(int(p.port))}},
		ICS:       rules.ICSPredicate{Protocol: p.protocol, Mode: mode}}
}

func runtimePairEngine(t *testing.T, snap rules.Snapshot, enabled bool) *Engine {
	t.Helper()
	e, err := New(Config{DPIEnabled: enabled, DPIMode: snap.DPIMode, ResetInjector: &session.Fake{}})
	if err != nil {
		t.Fatal(err)
	}
	startBlockWorker(t, e)
	t.Cleanup(e.Close)
	e.sessions.ctDelete = func(context.Context, conntrack.DeleteRequest) error { return nil }
	e.LoadRules(snap)
	return e
}

func runtimePairPacket(p runtimePairCase, reply bool, seq uint32, wire []byte) capture.Packet {
	pkt := connSegment(reply, 41000, p.port, seq, ackPsh, wire)
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	return pkt
}

func runtimePairOwner(t *testing.T, e *Engine, p runtimePairCase) *trackedSession {
	t.Helper()
	pkt := runtimePairPacket(p, false, 100, nil)
	client, _ := addrPort(pkt.SrcIP, pkt.SrcPort)
	server, _ := addrPort(pkt.DstIP, pkt.DstPort)
	s, _ := e.sessions.lookupLocked(client, server)
	if s == nil {
		t.Fatal("missing session owner")
	}
	return s
}

func testDS34SolicitedRuntime(t *testing.T, p runtimePairCase) {
	for _, def := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		cases := []string{"allowed", "missing", "denied", "incomplete", "monitor-only"}
		if p.protocol != iecProtocol {
			cases = append(cases, "non-admit")
		}
		for _, fate := range cases {
			t.Run(fmt.Sprintf("%s/%s", def, fate), func(t *testing.T) {
				entry := runtimePairRule(p, "enforce")
				if fate == "denied" {
					entry.Action = rules.ActionDeny
				} else if fate == "monitor-only" {
					entry.ICS.Mode = "monitor"
				} else if fate == "non-admit" {
					entry.ICS.FunctionCode = []uint8{99} // scope exists; this request has no ICS permit
				}
				snap := rules.Snapshot{Default: def, DPIMode: "enforce", Firewall: []rules.Entry{entry}}
				e := runtimePairEngine(t, snap, true)
				inlineHandshake(t, e, 41000, p.port)
				req := runtimePairPacket(p, false, 100, p.request)
				if fate == "incomplete" {
					req.Payload = req.Payload[:3]
				}
				if fate != "missing" {
					d := e.HandlePacket(req) // deliberately no verdict completion yet
					want := capture.Repeat
					if fate == "denied" {
						want = capture.Drop
					} else if fate == "incomplete" {
						want = capture.Hold
					}
					if d.Action != want || fate == "non-admit" && d.Mark&markabi.NonAdmitMark == 0 {
						t.Fatalf("request=%+v", d)
					}
				}
				if fate == "monitor-only" {
					if e.sessions.pairingTotal != 1 {
						t.Fatal("monitor did not use its observe ledger")
					}
					snap.Firewall[0].ICS.Mode = "enforce"
					e.LoadRules(snap)
				}
				if fate == "allowed" && e.sessions.pairingTotal != 1 {
					t.Fatal("release did not activate grant before callback")
				}
				reply := runtimePairPacket(p, true, 500, p.reply)
				d := e.HandlePacket(reply)
				want := capture.Drop
				// A non-admitting incarnation stays on ordinary kernel
				// policy with NonAdmit, never DPI-authorized continuation.
				if fate == "allowed" || fate == "non-admit" {
					want = capture.Repeat
				}
				if d.Action != want || fate == "non-admit" && d.Mark&markabi.NonAdmitMark == 0 {
					t.Fatalf("reply=%+v want %v", d, want)
				}
				if fate != "allowed" && e.sessions.pairingTotal != 0 {
					t.Fatal("non-authorizing request retained enforce grants")
				}
				if fate == "incomplete" && (len(d.Resolved) != 1 || d.Resolved[0].Token != req.Token || d.Resolved[0].Verdict != capture.VerdictDrop) {
					t.Fatalf("unpaired reply failed to discard request prefix: %+v", d)
				}
				if fate == "allowed" {
					// Identical TCP retries reuse decided bytes without minting
					// another grant or evaluating the decoded reply again.
					before := len(e.Events().List(0))
					retry := reply
					retry.Token = capture.NewToken(1, firstCommandTokens.Add(1))
					if got := e.HandlePacket(retry); got.Action != capture.Repeat || len(e.Events().List(0)) != before {
						t.Fatalf("identical reply retry=%+v", got)
					}
					e.hooks.onVerdict(req.Token, capture.VerdictRepeat, nil)
					e.hooks.onVerdict(reply.Token, capture.VerdictRepeat, nil)
					if runtimePairOwner(t, e, p).state != sessionEstablished {
						t.Fatal("successful completion retired the allowed session")
					}
				}
			})
		}
	}
}

func testDS34RuntimeSplits(t *testing.T) {
	for _, p := range runtimePairCases() {
		for _, reply := range []bool{false, true} {
			wire, seq := p.request, uint32(100)
			if reply {
				wire, seq = p.reply, 500
			}
			for cut := 1; cut < len(wire); cut++ {
				t.Run(fmt.Sprintf("%s/reply=%t/split=%d", p.protocol, reply, cut), func(t *testing.T) {
					e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
					inlineHandshake(t, e, 41000, p.port)
					wantGrants := 0
					if reply {
						if d := e.HandlePacket(runtimePairPacket(p, false, 100, p.request)); d.Action != capture.Repeat {
							t.Fatal(d)
						}
						wantGrants = 1
					}
					head := runtimePairPacket(p, reply, seq, wire[:cut])
					if d := e.HandlePacket(head); d.Action != capture.Hold || len(d.Resolved) != 0 || e.sessions.pairingTotal != wantGrants {
						t.Fatalf("partial message changed authority or published bytes: %+v", d)
					}
					tail := runtimePairPacket(p, reply, seq+uint32(cut), wire[cut:])
					d := e.HandlePacket(tail)
					if d.Action != capture.Repeat || len(d.Resolved) != 1 ||
						d.Resolved[0].Token != head.Token || d.Resolved[0].Verdict != capture.VerdictRepeat ||
						d.Resolved[0].Mark&markabi.NonAdmitMark != 0 {
						t.Fatalf("complete allowed message did not release all carrying tokens: %+v", d)
					}
					if e.budget.Status().ByCategory["held"] == 0 {
						t.Fatal("returning a resolution refunded resident storage")
					}
					e.hooks.onVerdict(head.Token, capture.VerdictRepeat, nil)
					if e.budget.Status().ByCategory["held"] != 0 {
						t.Fatal("successful submission retained held credit")
					}
				})
			}
		}
	}
}

func testDS34CollateralRelease(t *testing.T) {
	for _, p := range runtimePairCases() {
		for _, fate := range []string{"partial-tail", "forbidden-sibling"} {
			t.Run(p.protocol+"/"+fate, func(t *testing.T) {
				permit := runtimePairRule(p, "enforce")
				deny := permit
				deny.ID, deny.Action = "forbidden", rules.ActionDeny
				var forbidden []byte
				switch p.protocol {
				case "modbus":
					deny.ICS.FunctionCode = []uint8{6}
					forbidden = modbusADU(2, 6, 1, 3)
				case "dnp3":
					deny.ICS.FunctionCode = []uint8{5}
					forbidden = dnp3Operate(5, 9)
				case iecProtocol:
					deny.ICS.TypeIDs = []int{45}
					forbidden = apdu(45, 6, 1, 102, 1)
				}
				e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{deny, permit}}, true)
				inlineHandshake(t, e, 41000, p.port)
				sibling := forbidden
				want := capture.Drop
				if fate == "partial-tail" {
					sibling, want = p.request[:3], capture.Hold
				}
				req := runtimePairPacket(p, false, 100, concatFrames(p.request, sibling))
				if d := e.HandlePacket(req); d.Action != want || e.sessions.pairingTotal != 0 {
					t.Fatalf("coalesced packet granted before an allowed release: %+v", d)
				}
				if d := e.HandlePacket(runtimePairPacket(p, true, 500, p.reply)); d.Action != capture.Drop || e.sessions.pairingTotal != 0 {
					t.Fatalf("collateral request authorized a reply: %+v", d)
				}
			})
		}
	}
}

func testDS34DNP3Stations(t *testing.T) {
	p := runtimePairCases()[1]
	snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}
	t.Run("interleaved-stations-one-connection", func(t *testing.T) {
		e := runtimePairEngine(t, snap, true)
		inlineHandshake(t, e, 41000, p.port)
		q := append([]byte(nil), p.request...)
		r := append([]byte(nil), p.reply...)
		binary.LittleEndian.PutUint16(q[4:6], 11)
		binary.LittleEndian.PutUint16(r[6:8], 11)
		binary.LittleEndian.PutUint16(q[8:10], dnp3CRC(q[:8]))
		binary.LittleEndian.PutUint16(r[8:10], dnp3CRC(r[:8]))
		if d := e.HandlePacket(runtimePairPacket(p, false, 100, concatFrames(p.request, q))); d.Action != capture.Repeat || e.sessions.pairingTotal != 2 {
			t.Fatalf("distinct stations did not retain independent grants: %+v", d)
		}
		if d := e.HandlePacket(runtimePairPacket(p, true, 500, concatFrames(r, p.reply))); d.Action != capture.Repeat || e.sessions.pairingTotal != 0 {
			t.Fatalf("reverse-order station responses did not consume their own grants: %+v", d)
		}
	})
	t.Run("same-stations-distinct-connections", func(t *testing.T) {
		e := runtimePairEngine(t, snap, true)
		inlineHandshake(t, e, 41000, p.port)
		inlineHandshake(t, e, 41001, p.port)
		if d := e.HandlePacket(runtimePairPacket(p, false, 100, p.request)); d.Action != capture.Repeat {
			t.Fatal(d)
		}
		foreign := runtimePairPacket(p, true, 500, p.reply)
		foreign.DstPort = 41001
		if d := e.HandlePacket(foreign); d.Action != capture.Drop || d.Reason != string(pairUnpaired) {
			t.Fatalf("matching station borrowed another TCP connection's grant: %+v", d)
		}
		if d := e.HandlePacket(runtimePairPacket(p, true, 500, p.reply)); d.Action != capture.Repeat || e.sessions.pairingTotal != 0 {
			t.Fatalf("foreign connection denial retired independent authority: %+v", d)
		}
	})
}
