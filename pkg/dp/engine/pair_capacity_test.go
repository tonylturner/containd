// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"testing"
)

func TestObserveGrantsStarveEnforce(t *testing.T) {
	mb, dnp := runtimePairCases()[0], runtimePairCases()[1]
	snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(mb, "monitor"), runtimePairRule(dnp, "enforce")}}
	e := runtimePairEngine(t, snap, true)
	for c := 0; c < pairGlobalCap/pairSessionCap; c++ {
		port := uint16(30000 + c)
		inlineHandshake(t, e, port, mb.port)
		seq := uint32(100)
		for i := 0; i < pairSessionCap; i++ {
			pkt := connSegment(false, port, mb.port, seq, ackPsh, modbusADU(uint16(i+1), 3, 0, 2))
			pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
			if d := e.HandlePacket(pkt); d.Action != capture.Repeat {
				t.Fatalf("monitor request conn %d #%d=%+v", c, i, d)
			}
			seq += 12
		}
	}
	e.sessions.mu.Lock()
	total := e.sessions.pairingObserve
	e.sessions.mu.Unlock()
	if total != pairObserveCap || e.sessions.pairingTotal != 0 {
		t.Fatalf("observe/enforce isolation: observed=%d enforce=%d", total, e.sessions.pairingTotal)
	}
	st := e.budget.Status()
	t.Logf("observe grants=%d budget inUse=%d limit=%d", total, st.InUse, st.Limit)
	inlineHandshake(t, e, 41000, dnp.port)
	d := sendInline(e, runtimePairPacket(dnp, false, 100, dnp.request))
	t.Logf("enforce DNP3 allowed request with observe-filled ledger: %+v", d)
	if d.Action != capture.Repeat {
		t.Errorf("monitor-only traffic denied an allowed enforce request: %+v", d)
	}
}

func TestDefaultBudgetSessionCapacity(t *testing.T) {
	p := runtimePairCases()[0]
	e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
	fit := 0
	for i := 0; i < sessionMaxSessions; i++ {
		port := uint16(10000 + i)
		syn := connSegment(false, port, p.port, 100, capture.TCPFlagSYN, nil)
		if d := sendInline(e, syn); d.Action != capture.Repeat {
			t.Logf("SYN %d refused: %+v", i, d)
			break
		}
		ack := connSegment(true, port, p.port, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
		ack.TCP.Ack = 100
		if d := sendInline(e, ack); d.Action != capture.Repeat {
			t.Logf("SYN-ACK %d refused: %+v", i, d)
			break
		}
		if d := sendInline(e, connSegment(false, port, p.port, 100, ackPsh, p.request)); d.Action != capture.Repeat {
			t.Logf("request %d refused: %+v", i, d)
			break
		}
		fit++
	}
	st := e.budget.Status()
	t.Logf("sessions with one grant before refusal=%d of cap %d; budget inUse=%d limit=%d byCategory=%v", fit, sessionMaxSessions, st.InUse, st.Limit, st.ByCategory)
	if fit < sessionMaxSessions {
		t.Errorf("default inspection budget refuses at %d sessions, below the %d session bound", fit, sessionMaxSessions)
	}
}
