// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportCacheHitsReuseConnectionSnapshot(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	c := r.resolve(context.Background(), pkt, false)
	e.handleTransportPacket(pkt, c, nil)
	e.flowMu.Lock()
	state := e.tupleStateLocked(natEvidence().Original)
	e.flowMu.Unlock()
	snapshot := state.Connection.Load()
	for range 100 {
		e.bindTransport(state, c)
		if state.Connection.Load() != snapshot {
			t.Fatal("cache hit allocated a new immutable connection snapshot")
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if adoptTransport(snapshot, c) != snapshot {
			t.Fatal("identical evidence was not reused")
		}
	}); allocs != 0 {
		t.Fatalf("cache-hit adoption allocations = %v", allocs)
	}
	downgraded := adoptTransport(snapshot, &flow.Connection{Status: "zone_unverified"})
	if downgraded == snapshot || snapshot.Status != "resolved" || downgraded.Key != snapshot.Key ||
		downgraded.ID != snapshot.ID || downgraded.Status != "zone_unverified" {
		t.Fatal("reusing cache hits mutated a prior evidence snapshot")
	}
}

func TestTransportCloseReclaimsOnlyItsIndexedAliases(t *testing.T) {
	evidence := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
	r.authority.check(context.Background())
	pkt := transportWire(evidence.Original, time.Now(), nil)
	e.handleTransportPacket(pkt, r.resolve(context.Background(), pkt, false), nil)
	e.flowMu.Lock()
	state := e.tupleStateLocked(evidence.Original)
	e.flowMu.Unlock()
	if len(r.indexed) != 2 {
		t.Fatal("fixture lacks both indexed CT aliases")
	}
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 2000}
	r.admit(e, pkt)
	fresh := r.indexed[evidence.Original]
	e.closeCorrelation(state, true, false)
	if len(r.indexed) != 1 || r.indexed[evidence.Original] != fresh || r.indexed[evidence.Reply] != nil {
		t.Fatal("retirement leaked aliases or reclaimed a newer admitted SYN")
	}
}

func TestTransportRegainedLossIndexWaitsFullRecovery(t *testing.T) {
	evidence := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
	r.authority.check(context.Background())
	pkt := transportWire(evidence.Original, time.Now(), nil)
	c := r.resolve(context.Background(), pkt, false)
	c.Coverage().Store(true)
	// An already-started history whose index was unavailable; any earlier
	// recovery deadline has elapsed, but losses since then were not indexed.
	state := flow.NewState(flow.TupleKey(evidence.Original, flow.DirForward), time.Now())
	state.Connection.Store(c)
	e.flows[state.Key.MapKey()] = state
	reply := transportWire(evidence.Reply, time.Now(), modbusReadReply(1))
	r.admit(e, reply)
	processTransportAdmission(t, e, r)
	e.flowMu.Lock()
	current := e.tupleStateLocked(evidence.Reply).Connection.Load()
	e.flowMu.Unlock()
	if current.CorrelationAvailable(time.Now()) || !current.CorrelationAvailable(time.Now().Add(3*time.Minute)) {
		t.Fatal("recovered index claimed its preceding unindexed interval was covered")
	}
	if stats := e.AnomalyDetector().PairingStats(); stats.Unmatched != 0 || stats.Unavailable != 1 {
		t.Fatalf("unindexed request loss became unmatched: %+v", stats)
	}
}
