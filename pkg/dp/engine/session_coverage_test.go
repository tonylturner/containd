// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestDS34Gate(t *testing.T) {
	t.Run("inline-direction-splits", testDS34RuntimeSplits)
	for _, dir := range []int{sessionDirClient, sessionDirSrv} {
		t.Run(dirName(dir), func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			h.handshake()
			table := h.e.sessions
			table.mu.Lock()
			defer table.mu.Unlock()
			client, _ := addrPort(h.client, h.cport)
			server, _ := addrPort(h.server, iec104Port)
			s, _ := table.lookupLocked(client, server)
			d := s.dirs[dir]
			pending := func(start, end int64) dpi.DecodedFrame {
				return dpi.DecodedFrame{Start: start, End: end, Pending: true}
			}
			complete := func(start, end int64, ranges ...dpi.CoverageRange) dpi.DecodedFrame {
				return dpi.DecodedFrame{Start: start, End: end, Coverage: ranges, Unit: &dnp3.Unit{}}
			}
			if err := table.retainFramesLocked(s, d, []dpi.DecodedFrame{pending(0, 10), pending(10, 20)}); err != nil {
				t.Fatal(err)
			}
			if d.covered(0, 20) {
				t.Fatal("pending links authorized bytes")
			}
			if err := table.retainFramesLocked(s, d, []dpi.DecodedFrame{complete(20, 30, dpi.CoverageRange{Start: 0, End: 10}, dpi.CoverageRange{Start: 20, End: 30})}); err != nil {
				t.Fatal(err)
			}
			if !d.covered(0, 10) || !d.covered(20, 30) || d.covered(0, 30) || d.covered(5, 25) {
				t.Fatal("interleaved hole became a min/max interval")
			}
			if err := table.retainFramesLocked(s, d, []dpi.DecodedFrame{complete(30, 40, dpi.CoverageRange{Start: 10, End: 20}, dpi.CoverageRange{Start: 30, End: 40})}); err != nil {
				t.Fatal(err)
			}
			if !d.covered(0, 40) || d.covered(0, 41) {
				t.Fatal("complete plus partial tail coverage")
			}
			// Complete coverage is reusable by identical TCP retries, not by a new
			// logical unit attempting to claim already-decided provenance.
			if err := table.retainFramesLocked(s, d, []dpi.DecodedFrame{complete(40, 50, dpi.CoverageRange{Start: 0, End: 10}, dpi.CoverageRange{Start: 40, End: 50})}); err == nil {
				t.Fatal("reused carrying provenance")
			}
			if len(d.frames) != 4 {
				t.Fatal("failed replacement was published")
			}
			table.resources = limits.NewResources(limits.NewBudget(1), nil)
			if err := table.retainFramesLocked(s, d, []dpi.DecodedFrame{pending(40, 50)}); !errors.Is(err, flow.ErrInspectionLimit) {
				t.Fatal(err)
			}
			if !d.covered(0, 40) || len(d.frames) != 4 {
				t.Fatal("refusal changed decided coverage")
			}
		})
	}
	t.Run("held-nonadmit", func(t *testing.T) {
		h := newIECHarness(t, "enforce")
		h.handshake()
		wire := iframe(46, 1)
		head, d := h.send(true, wire[:3])
		if d.Action != capture.Hold {
			t.Fatal(d)
		}
		table := h.e.sessions
		table.mu.Lock()
		client, _ := addrPort(h.client, h.cport)
		server, _ := addrPort(h.server, iec104Port)
		s, _ := table.lookupLocked(client, server)
		if err := table.retainFramesLocked(s, s.dirs[0], []dpi.DecodedFrame{{Start: 0, End: 16}}); err != nil {
			t.Fatal(err)
		}
		s.dirs[0].frames[0].nonAdmit = true
		tail := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, wire[3:])
		res := table.releaseLocked(s, 0, tail, table.current(s, 0, tail, h.clock), sessionResult{}, h.clock)
		table.mu.Unlock()
		want := nonAdmitDecision(tail)
		if res.decision.Action != want.Action || res.decision.Mark != want.Mark || len(res.decision.Resolved) != 1 {
			t.Fatal(res.decision)
		}
		got := res.decision.Resolved[0]
		if got.Token != head.Token || got.Verdict != capture.VerdictRepeat || got.Mark != nonAdmitDecision(head).Mark {
			t.Fatal(got)
		}
	})
}

func TestDS34Settlement(t *testing.T) {
	t.Run("inflight-rejection", testDS34InflightSettlement)
	h := newIECHarness(t, "enforce")
	table := h.e.sessions
	for _, err := range []error{capture.ErrUnknownToken, errors.New("uncertain send")} {
		tok := h.token()
		table.mu.Lock()
		ok := table.holdCreditLocked(tok, 7, true, "modbus")
		table.mu.Unlock()
		if !ok {
			t.Fatal("admission")
		}
		table.onVerdict(tok, capture.VerdictRepeat, err)
		table.mu.Lock()
		retained := table.settlements[tok] != nil
		table.mu.Unlock()
		if !retained {
			t.Fatal("uncertain submission refunded credit")
		}
		table.onVerdict(tok, capture.VerdictRepeat, nil)
		table.onVerdict(tok, capture.VerdictRepeat, nil)
	}
	if h.e.budget.Status().InUse != 0 {
		t.Fatal("completion leaked or double refunded")
	}
	for _, err := range []error{capture.ErrTokenFlushed, capture.ErrQueueClosed, capture.ErrStaleToken} {
		tok := h.token()
		table.mu.Lock()
		ok := table.holdCreditLocked(tok, 7, true, "dnp3")
		table.mu.Unlock()
		if !ok {
			t.Fatal("admission")
		}
		table.onVerdict(tok, capture.VerdictDrop, err)
	}
	if h.e.budget.Status().InUse != 0 {
		t.Fatal("flush leaked")
	}
}

func TestDS34TransportRetirement(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	table := h.e.sessions
	client := netip.AddrPortFrom(netip.MustParseAddr("10.60.60.10"), h.cport)
	server := netip.MustParseAddrPort("10.30.30.30:2404")
	old := &flow.Connection{Key: "losing"}
	survivor := &flow.Connection{Key: "surviving"}
	table.mu.Lock()
	s, _ := table.lookupLocked(client, server)
	s.flow.Connection.Store(old)
	table.mu.Unlock()
	_, d := h.send(true, iframe(46, 1)[:3])
	if d.Action != capture.Hold {
		t.Fatal(d)
	}
	acts := table.retireMergedHistory(survivor, old)
	table.mu.Lock()
	aborted := s.state == sessionAborted && len(s.held) == 0
	table.mu.Unlock()
	if !aborted || len(acts.drops) != 1 {
		t.Fatal("losing history not retired before alias publication", acts)
	}
	table.apply(acts)
}

func testDS34HeldShares(t *testing.T) {
	h := newIECHarness(t, "enforce")
	table := h.e.sessions
	table.mu.Lock()
	defer table.mu.Unlock()
	id := uint32(1)
	for _, proto := range []string{"modbus", "dnp3", "iec104"} {
		for i := 0; i < heldProtocolShare(proto); i++ {
			if !table.holdCreditLocked(capture.NewToken(1, id), 1, true, proto) {
				t.Fatalf("%s refused reserved slot %d", proto, i)
			}
			id++
		}
		if table.holdCreditLocked(capture.NewToken(1, id), 1, true, proto) {
			t.Fatalf("%s borrowed a slot", proto)
		}
	}
	if len(table.settlements) != sessionMaxHeldGlobal {
		t.Fatal(len(table.settlements))
	}
	table.flushHeldCreditsLocked(1)
	if h.e.budget.Status().InUse != 0 {
		t.Fatal("leases leaked")
	}
}
