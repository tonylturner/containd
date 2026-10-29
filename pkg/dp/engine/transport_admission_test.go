// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportAdmissionSkipsNonICS(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	for _, port := range []uint16{53, 80, 443} {
		pkt.DstPort = port
		r.admit(e, pkt)
	}
	if r.count.Load() != 0 || len(r.indexed) != 0 {
		t.Fatal("non-ICS traffic entered resolver")
	}
	pkt.DstPort = 502
	e.dpiExclusions = []DPIExclusion{{Type: "ip", Value: pkt.SrcIP.String()}}
	r.admit(e, pkt)
	if r.count.Load() != 0 {
		t.Fatal("excluded traffic entered resolver")
	}
	e.dpiExclusions = nil
	e.inspectAll, e.dpiEnabled = false, false
	r.admit(e, pkt)
	if r.count.Load() != 0 {
		t.Fatal("disabled DPI traffic entered resolver")
	}
	e.dpiEnabled = true
	r.admit(e, pkt)
	if r.count.Load() != 1 {
		t.Fatal("inspected ICS traffic bypassed resolver")
	}
}

func TestTransportByteCapAndOverflowRate(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), make([]byte, transportByteLimit/2+1))
	r.admit(e, pkt)
	for range 100 {
		r.admit(e, pkt)
	}
	if r.count.Load() != 1 || r.bytes.Load() != int64(len(pkt.Payload)) ||
		r.authority.snapshot().Counters["queue_overflow"] != 100 || len(e.Events().List(0)) != 1 {
		t.Fatal("byte overflow was not bounded and rate-limited")
	}
	r.overflowNext = time.Now().Add(-time.Second)
	r.admit(e, pkt)
	if r.authority.snapshot().Counters["queue_overflow"] != 101 || len(e.Events().List(0)) != 2 {
		t.Fatal("overflow rate limit did not rearm")
	}
}

func TestTransportOverflowScopesLossIncludingQueuedOpener(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	r.admit(e, pkt)
	queued := <-r.queue
	r.count.Add(-1)
	other := &flow.Connection{Key: "unrelated", Status: "resolved"}
	other.Coverage().Store(true)
	tuple := natEvidence().Original
	tuple.Source = netip.MustParseAddrPort("10.10.0.6:42000")
	r.indexed[tuple] = &transportAdmission{connection: other}
	r.admissionMu.Lock()
	r.unavailable(e, pkt, "queue_overflow")
	r.admissionMu.Unlock()
	r.authority.check(context.Background())
	c := r.resolve(context.Background(), queued.packet, false)
	e.handleTransportPacket(pkt, c, queued.history)
	e.flowMu.Lock()
	started := e.tupleStateLocked(packetKey(pkt).Tuple()).Connection.Load()
	e.flowMu.Unlock()
	if started.CorrelationAvailable(time.Now()) || !other.CorrelationAvailable(time.Now()) {
		t.Fatal("loss missed the queued opener or gapped unrelated connection")
	}
	if !started.CorrelationAvailable(time.Now().Add(3 * time.Minute)) {
		t.Fatal("tuple loss never rearmed")
	}
}

func TestTransportNegativeAliasesExpireBeforeCapacityCheck(t *testing.T) {
	evidence := natEvidence()
	f := &transportCTFake{evidence: evidence}
	_, r, _ := newTransportTest(t, f)
	r.authority.check(context.Background())
	for i := range transportAliasLimit {
		tuple := evidence.Original
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i))
		r.aliases[tuple] = &transportAlias{connection: &flow.Connection{Status: "not_found"},
			expires: time.Now().Add(-time.Millisecond)}
	}
	c := r.resolve(context.Background(), transportWire(evidence.Reply, time.Now(), nil), false)
	if !c.Verified() || f.calls != 1 || len(r.aliases) != 2 {
		t.Fatal("expired negatives denied legitimate resolution")
	}
}

func TestTransportLossIndexCapacityDoesNotClaimCoverage(t *testing.T) {
	_, r, _ := newTransportTest(t, &transportCTFake{})
	tuple := natEvidence().Original
	for i := range transportAliasLimit {
		key := tuple
		key.Source = netip.AddrPortFrom(key.Source.Addr(), uint16(i))
		r.indexed[key] = &transportAdmission{connection: &flow.Connection{Key: "occupied"}}
	}
	state := flow.NewState(flow.TupleKey(natEvidence().Reply, flow.DirReverse), time.Now())
	c := &flow.Connection{Key: "uncertain"}
	c.Coverage().Store(true)
	state.Connection.Store(c)
	r.trackConnection(state, time.Now(), nil)
	if c.CorrelationAvailable(time.Now()) || len(r.indexed) != transportAliasLimit ||
		r.authority.snapshot().Counters["coverage_capacity"] != 1 {
		t.Fatal("loss-index capacity claimed complete coverage")
	}
	// Reclaim a closed incarnation, then wait a full quiet pairing timeout.
	for _, old := range r.indexed {
		old.connection.Closed().Store(true)
		break
	}
	r.trackConnection(state, time.Now(), nil)
	if !c.CorrelationAvailable(time.Now().Add(3 * time.Minute)) {
		t.Fatal("coverage did not recover after capacity became available")
	}
}
