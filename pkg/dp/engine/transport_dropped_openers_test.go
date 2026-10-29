// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// Packet pressure may lose observations, but must not leave never-processed
// tuple reservations occupying every loss-index slot after all flows expire.
func TestReviewRound3DroppedOpenersReleaseAdmissionCapacity(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	r.authority.check(context.Background())
	attacker := ev.Original
	attacker.Source = netip.MustParseAddrPort("10.10.0.99:10000")
	pkt := transportWire(attacker, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 10}
	for range transportQueueLimit {
		r.admit(e, pkt)
	}
	if r.count.Load() != transportQueueLimit {
		t.Fatal("queue not full")
	}
	for i := 0; i < transportAliasLimit; i++ {
		pkt.SrcPort = uint16(10000 + i)
		pkt.TCP.Flags = capture.TCPFlagSYN
		pkt.TCP.Seq = 100
		r.admit(e, pkt)
	}
	for r.count.Load() > 0 {
		processTransportAdmission(t, e, r)
	}
	e.sweepFlows(time.Now().Add(10 * time.Minute))
	orphaned := 0
	for _, token := range r.indexed {
		if token.connection.Key == "" {
			orphaned++
		}
	}
	t.Logf("after queue drain and flow expiry: indexed=%d orphaned=%d flows=%d", len(r.indexed), orphaned, len(e.flows))
	// An unrelated legitimate, completely observed connection starts after
	// the flood stops, with healthy CT/zone evidence and no packet loss.
	syn := transportWire(ev.Original, time.Now(), nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 500}
	r.admit(e, syn)
	processTransportAdmission(t, e, r)
	req := transportWire(ev.Original, time.Now(), modbusADU(1, 3, 10, 2))
	r.admit(e, req)
	processTransportAdmission(t, e, r)
	rep := transportWire(ev.Reply, time.Now(), modbusReadReply(1))
	r.admit(e, rep)
	processTransportAdmission(t, e, r)
	bogus := transportWire(ev.Reply, time.Now(), modbusReadReply(99))
	r.admit(e, bogus)
	processTransportAdmission(t, e, r)
	stats := e.AnomalyDetector().PairingStats()
	if stats.Matched != 1 {
		t.Fatalf("fixture not paired: %+v", stats)
	}
	if stats.Unmatched != 1 {
		t.Fatalf("old dropped-openers disable unrelated healthy connection: %+v; capacity=%d", stats, r.authority.snapshot().Counters["coverage_capacity"])
	}
}
