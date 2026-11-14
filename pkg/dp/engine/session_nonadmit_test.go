// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"testing"
)

func TestNonAdmitDropsHeldWithoutVerdict(t *testing.T) {
	for _, held := range []string{"same-direction-out-of-order", "opposite-direction-partial"} {
		t.Run(held, func(t *testing.T) {
			p := runtimePairCases()[0]
			entry := runtimePairRule(p, "enforce")
			entry.ICS.FunctionCode = []uint8{99}
			snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{entry}}
			e := runtimePairEngine(t, snap, true)
			inlineHandshake(t, e, 41000, p.port)
			var h capture.Packet
			if held == "same-direction-out-of-order" {
				h = runtimePairPacket(p, false, 100+600, []byte{0, 9, 0})
			} else {
				h = runtimePairPacket(p, true, 500, p.reply[:3])
			}
			if d := e.HandlePacket(h); d.Action != capture.Hold {
				t.Fatalf("setup hold=%+v", d)
			}
			req := runtimePairPacket(p, false, 100, p.request)
			d := e.HandlePacket(req)
			if d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark == 0 {
				t.Fatalf("setup non-admit=%+v", d)
			}
			e.hooks.onVerdict(req.Token, capture.VerdictRepeat, nil)
			resolved := false
			for _, r := range d.Resolved {
				resolved = resolved || r.Token == h.Token
				if r.Verdict != capture.VerdictDrop {
					t.Fatalf("abort resolution is not Drop: %+v", r)
				}
				e.hooks.onVerdict(r.Token, r.Verdict, nil)
			}
			tab := e.sessions
			tab.mu.Lock()
			_, pendingAbort := tab.aborts[h.Token]
			_, credit := tab.settlements[h.Token]
			_, stillHeld := tab.held[h.Token]
			tab.mu.Unlock()
			drainResetWorker(t, e)
			t.Logf("resolved=%t pendingAbort=%t credit=%t heldIndex=%t heldBudget=%d", resolved, pendingAbort, credit, stillHeld, e.budget.Status().ByCategory["held"])
			if !resolved {
				t.Errorf("held token %v got no verdict in Decision.Resolved after the abort", h.Token)
			}
			if pendingAbort {
				t.Errorf("abort transaction still waits for a completion that is never requested")
			}
		})
	}
}

// Repeated non-admission must not exhaust another session's held share.
func TestNonAdmitLeakExhaustsHoldShare(t *testing.T) {
	p := runtimePairCases()[0]
	strict := runtimePairRule(p, "enforce")
	strict.ICS.FunctionCode = []uint8{3}
	snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{strict}}
	e := runtimePairEngine(t, snap, true)
	for i := 0; i < heldProtocolShare("modbus"); i++ {
		port := uint16(42000 + i)
		inlineHandshake(t, e, port, p.port)
		ooo := connSegment(false, port, p.port, 100+600, ackPsh, []byte{0, 9, 0})
		ooo.Token = capture.NewToken(1, firstCommandTokens.Add(1))
		if d := e.HandlePacket(ooo); d.Action != capture.Hold {
			t.Fatalf("conn %d hold=%+v", i, d)
		}
		req := connSegment(false, port, p.port, 100, ackPsh, modbusADU(1, 6, 0, 2)) // not FC3: plain non-admission
		req.Token = capture.NewToken(1, firstCommandTokens.Add(1))
		d := e.HandlePacket(req)
		if d.Action != capture.Repeat || d.Mark&markabi.NonAdmitMark == 0 {
			t.Fatalf("conn %d non-admit=%+v", i, d)
		}
		e.hooks.onVerdict(req.Token, capture.VerdictRepeat, nil)
		for _, r := range d.Resolved {
			e.hooks.onVerdict(r.Token, r.Verdict, nil)
		}
		drainResetWorker(t, e) // Join old I/O before the handshake helper replaces its fakes.
	}
	e.sessions.mu.Lock()
	leaked := len(e.sessions.settlements)
	e.sessions.mu.Unlock()
	t.Logf("leaked held credits=%d heldBudget=%d", leaked, e.budget.Status().ByCategory["held"])
	// An unrelated, fully allowed client now splits one valid FC3 request.
	inlineHandshake(t, e, 43000, p.port)
	head := connSegment(false, 43000, p.port, 100, ackPsh, p.request[:5])
	head.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := e.HandlePacket(head)
	t.Logf("victim split head decision=%+v", d)
	if d.Action != capture.Hold {
		t.Errorf("victim's valid split request was not held: %+v (leaked=%d)", d, leaked)
	}
}
