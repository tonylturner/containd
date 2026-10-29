// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTransportAdmissionSweepPreservesQueuedAndLiveLoss(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	r.authority.check(context.Background())
	now := time.Now()
	syn := transportWire(ev.Original, now, nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 500}
	r.admit(e, syn)
	token := r.indexed[ev.Original]
	r.admissionMu.Lock()
	r.unavailable(e, syn, "queue_overflow")
	r.admissionMu.Unlock()
	token.connection.LoseCorrelation(now.Add(time.Minute), anomaly.ModbusPairingTimeout)
	r.sweepAdmission(now.Add(2 * time.Minute))
	if r.indexed[ev.Original] != token {
		t.Fatal("sweep discarded a recent loss")
	}
	// A token stays owned while queued and while a GET/processing is in flight,
	// even if the loss deadline is in the past at the time of a sweep.
	r.sweepAdmission(now.Add(10 * time.Minute))
	p := <-r.queue
	r.sweepAdmission(now.Add(10 * time.Minute))
	if r.indexed[ev.Original] != token || token.queued != 1 {
		t.Fatal("sweep discarded a queued/in-flight opener")
	}
	e.handleTransportPacket(p.packet, r.resolve(context.Background(), p.packet, false), p.history)
	r.releaseAdmission(p)
	if token.connection.Key == "" || token.connection.CorrelationAvailable(now.Add(2*time.Minute)) {
		t.Fatal("worker failed to transfer queued loss to the live history")
	}
	r.sweepAdmission(now.Add(time.Hour))
	if r.indexed[ev.Original] != token || token.queued != 0 {
		t.Fatal("sweep reclaimed a live incarnation")
	}
	if r.authority.snapshot().Counters["coverage_index_reclaimed"] != 0 {
		t.Fatal("preserved histories counted as evictions")
	}
}

func TestTransportAdmissionSweepWaitsForLatestLoss(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{})
	p := transportWire(natEvidence().Original, time.Now(), nil)
	r.count.Store(transportQueueLimit)
	r.admit(e, p)
	r.count.Store(0)
	token := r.indexed[natEvidence().Original]
	latest := time.Now().Add(time.Minute)
	token.connection.LoseCorrelation(latest, anomaly.ModbusPairingTimeout)
	r.sweepAdmission(latest.Add(anomaly.ModbusPairingTimeout - time.Nanosecond))
	if len(r.indexed) != 1 {
		t.Fatal("loss history expired before the latest gap's deadline")
	}
	r.sweepAdmission(latest.Add(anomaly.ModbusPairingTimeout))
	if len(r.indexed) != 0 || r.authority.snapshot().Counters["coverage_index_reclaimed"] != 1 {
		t.Fatal("expired dropped-only token was not reclaimed exactly once")
	}
	r.sweepAdmission(latest.Add(time.Hour))
	if r.authority.snapshot().Counters["coverage_index_reclaimed"] != 1 {
		t.Fatal("repeated sweep recounted the same eviction")
	}
}

func TestTransportFloodRecoveryRearmsExistingConnection(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	r.authority.check(context.Background())
	r.count.Store(transportQueueLimit)
	for i := range 2 * transportAliasLimit {
		p := transportWire(round3FloodTuple(i), time.Now(), nil)
		p.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1}
		r.admit(e, p)
	}
	r.count.Store(0)
	if len(r.indexed) != transportAliasLimit {
		t.Fatal("fixture failed to exhaust the index")
	}
	round3LegitConnection(t, e, r)
	if stats := e.AnomalyDetector().PairingStats(); stats.Unmatched != 0 || stats.Unavailable != 1 {
		t.Fatalf("capacity failed to suppress uncertain unmatched claims: %+v", stats)
	}
	if r.authority.snapshot().Counters["coverage_capacity"] == 0 {
		t.Fatal("real capacity was not reported")
	}
	// The flood stops. Expired placeholders become reclaimable at a sweep;
	// this still-live connection then regains indexing on its next packet.
	r.sweepAdmission(time.Now().Add(3 * time.Minute))
	if len(r.indexed) != 0 || r.authority.snapshot().Counters["coverage_index_reclaimed"] != transportAliasLimit {
		t.Fatal("stopped flood did not release the placeholder capacity")
	}
	p := transportWire(ev.Reply, time.Now(), nil)
	r.admit(e, p)
	processTransportAdmission(t, e, r)
	state := e.tupleStateLocked(ev.Reply)
	c := state.Connection.Load()
	now := time.Now()
	if c.CorrelationAvailable(now) || !c.CorrelationAvailable(now.Add(3*time.Minute)) {
		t.Fatal("regained index did not require a full recovery interval")
	}
	capacity := r.authority.snapshot().Counters["coverage_capacity"]
	for range 5 {
		r.admit(e, p)
		processTransportAdmission(t, e, r)
	}
	if r.authority.snapshot().Counters["coverage_capacity"] != capacity {
		t.Fatal("healthy indexed traffic kept extending capacity loss")
	}
	// Explicit event time avoids sleeping through the two-minute recovery.
	event := dpi.Event{FlowID: state.Key.Hash(), Proto: "modbus", Kind: "response",
		Timestamp: now.Add(3 * time.Minute), Connection: c,
		Attributes: map[string]any{"transaction_id": uint16(100), "unit_id": uint8(1), "function_code": uint8(3)}}
	e.AnomalyDetector().Check(ev.Reply.Source.Addr().String(), ev.Reply.Destination.Addr().String(), event)
	if stats := e.AnomalyDetector().PairingStats(); stats.Unmatched != 1 {
		t.Fatalf("recovered connection never re-armed detection: %+v", stats)
	}
}
