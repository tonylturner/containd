// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

// Regression fixtures exercise dropped-only reservations and post-flood detection.
func round3FloodTuple(i int) conntrack.Tuple {
	t := natEvidence().Original
	t.Source = netip.AddrPortFrom(netip.MustParseAddr("10.10.0.9"), uint16(1024+i))
	return t
}

func TestRound3OverflowDropsLeaveUnreclaimablePlaceholders(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	// A real backlog: 512 queued packets of one connection X.
	x := natEvidence().Original
	x.Source = netip.MustParseAddrPort("10.10.0.7:40000")
	filler := transportWire(x, time.Now(), nil)
	filler.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 5}
	for r.count.Load() < transportQueueLimit {
		r.admit(e, filler)
	}
	// A short burst of new-tuple SYNs (scan or spoofed flood) is dropped.
	const burst = 100
	for i := range burst {
		p := transportWire(round3FloodTuple(i), time.Now(), nil)
		p.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1}
		r.admit(e, p)
	}
	if r.count.Load() != transportQueueLimit || r.authority.snapshot().Counters["queue_overflow"] != burst {
		t.Fatalf("fixture: burst was not dropped: count=%d counters=%v", r.count.Load(), r.authority.snapshot().Counters)
	}
	// The backlog drains normally and X expires and retires its own aliases.
	for r.count.Load() > 0 {
		processTransportAdmission(t, e, r)
	}
	e.sweepFlows(time.Now().Add(time.Hour))
	e.sweepFlows(time.Now().Add(2 * time.Hour))
	orphans := 0
	for _, entry := range r.indexed {
		if entry.connection.Key == "" && !entry.connection.Closed().Load() {
			orphans++
		}
	}
	if len(r.indexed) != 0 {
		t.Fatalf("loss index retains %d entries after every flow retired; %d are unbound placeholders from dropped packets", len(r.indexed), orphans)
	}
}

func round3LegitConnection(t *testing.T, e *Engine, r *transportResolver) {
	t.Helper()
	ev := natEvidence()
	at := time.Now().Add(-3 * time.Minute)
	syn := transportWire(ev.Original, at, nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	r.admit(e, syn)
	processTransportAdmission(t, e, r)
	req := transportWire(ev.Original, at.Add(time.Millisecond), modbusADU(1, 3, 10, 2))
	req.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 101}
	r.admit(e, req)
	processTransportAdmission(t, e, r)
	rep := transportWire(ev.Reply, at.Add(2*time.Millisecond), modbusReadReply(1))
	rep.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 2000}
	r.admit(e, rep)
	processTransportAdmission(t, e, r)
	if s := e.AnomalyDetector().PairingStats(); s.Matched != 1 {
		t.Fatalf("fixture did not pair: %+v", s)
	}
	// A genuinely unmatched reply three minutes after a continuously captured,
	// fully inspected, verified start-of-connection history.
	bogus := transportWire(ev.Reply, time.Now(), modbusReadReply(99))
	bogus.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 2013}
	r.admit(e, bogus)
	processTransportAdmission(t, e, r)
}

func TestRound3OverflowFloodPermanentlyDisablesDetection(t *testing.T) {
	// Control: without the flood the bogus reply alerts.
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	round3LegitConnection(t, e, r)
	if s := e.AnomalyDetector().PairingStats(); s.Unmatched != 1 {
		t.Fatalf("control fixture did not alert: %+v", s)
	}

	e, r, _ = newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	// Worker backlog at the limit (the state any sustained burst produces).
	r.count.Store(transportQueueLimit)
	for i := range 2 * transportAliasLimit {
		p := transportWire(round3FloodTuple(i), time.Now(), nil)
		p.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1}
		r.admit(e, p)
	}
	r.count.Store(0)
	if len(r.indexed) != transportAliasLimit {
		t.Fatalf("flood left %d index entries", len(r.indexed))
	}
	// After the flood stops and the recovery interval passes, a sweep must
	// free dropped-only placeholders without restarting the worker.
	e.sweepFlows(time.Now().Add(3 * time.Hour))
	if r.authority.snapshot().Counters["coverage_index_reclaimed"] != transportAliasLimit {
		t.Fatal("sweep did not count all expired placeholders")
	}
	round3LegitConnection(t, e, r)
	s := e.AnomalyDetector().PairingStats()
	counters := r.authority.snapshot().Counters
	if s.Unmatched != 1 {
		t.Fatalf("new connection after the burst never alerts: stats=%+v indexed=%d coverage_capacity=%d",
			s, len(r.indexed), counters["coverage_capacity"])
	}
}
