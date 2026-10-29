// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestTransportSuccessfulChecksPreserveGeneration(t *testing.T) {
	_, r, zones := newTransportTest(t, &transportCTFake{})
	ctx := context.Background()
	r.authority.check(ctx)
	version := r.authority.version.Load()
	for range 3 {
		r.authority.check(ctx)
		if r.authority.version.Load() != version {
			t.Fatal("successful observation invalidated cache generation")
		}
	}
	for _, setters := range [][]enforce.ZoneSetter{nil, {{Family: "ip", Table: "foreign", Chain: "raw"}}} {
		var err error
		if setters == nil {
			err = errors.New("read failed")
		}
		zones.set(setters, err)
		r.authority.check(ctx)
		if v := r.authority.version.Load(); v == version || v%2 == 0 {
			t.Fatal("failed or setter-bearing read retained authority")
		}
	}
}

func modbusReadReply(tid uint16) []byte {
	return []byte{byte(tid >> 8), byte(tid), 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}
}

// An authority downgrade gates evidence, but is not itself a lost observation.
func TestTransportAuthorityWindowDoesNotDisableDetection(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	ctx := context.Background()
	r.authority.check(ctx)
	now := time.Now()
	syn := transportWire(ev.Original, now, nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	e.handleTransportPacket(syn, r.resolve(ctx, syn, false))
	req := transportWire(ev.Original, now.Add(time.Millisecond), modbusADU(1, 3, 10, 2))
	e.handleTransportPacket(req, r.resolve(ctx, req, false))
	rep := transportWire(ev.Reply, now.Add(2*time.Millisecond), modbusReadReply(1))
	e.handleTransportPacket(rep, r.resolve(ctx, rep, false))
	if s := e.AnomalyDetector().PairingStats(); s.Matched != 1 {
		t.Fatalf("fixture did not pair: %+v", s)
	}
	// Apply (or a failed read) invalidates authority until the next good read.
	r.authority.invalidate()
	req2 := transportWire(ev.Original, now.Add(3*time.Millisecond), modbusADU(2, 3, 10, 2))
	c := r.resolve(ctx, req2, false)
	if c.Status != "zone_unverified" || c.PublicID() == "" {
		t.Fatalf("cache hit during periodic check: status=%s id=%q", c.Status, c.PublicID())
	}
	e.handleTransportPacket(req2, c)
	// The read finishes with no zone setters: verified again.
	r.authority.check(ctx)
	if r.authority.snapshot().ZoneStatus != "verified" {
		t.Fatal("fixture did not re-verify")
	}
	rep2 := transportWire(ev.Reply, now.Add(4*time.Millisecond), modbusReadReply(2))
	e.handleTransportPacket(rep2, r.resolve(ctx, rep2, false))
	// A genuinely unmatched reply ten seconds later, long after the check.
	bogus := transportWire(ev.Reply, now.Add(10*time.Second), modbusReadReply(99))
	e.handleTransportPacket(bogus, r.resolve(ctx, bogus, false))
	stats := e.AnomalyDetector().PairingStats()
	var statuses []string
	for _, m := range transportModbusEvents(e) {
		statuses = append(statuses, m.CorrelationStatus)
	}
	var rollups []string
	for _, f := range e.Events().Flows(0) {
		rollups = append(rollups, f.CorrelationStatus)
	}
	if stats.Unmatched != 1 {
		t.Fatalf("periodic zone check window disabled unmatched-reply detection: stats=%+v event statuses=%v flow rollups=%v counters=%v",
			stats, statuses, rollups, r.authority.snapshot().Counters)
	}
}

// A routine read runs beside the worker without revoking verified evidence.
func TestTransportWorkerKeepsEvidenceDuringZoneRead(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	z := &transportBlockingZones{started: make(chan struct{}, 1), release: make(chan struct{})}
	r.authority.reader = z
	_, _ = runTransportTest(t, e, r)
	syn := transportWire(ev.Original, time.Now(), nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	r.admit(e, syn)
	r.admit(e, transportWire(ev.Original, time.Now(), modbusADU(1, 3, 10, 2)))
	waitTransport(t, func() bool { return len(transportModbusEvents(e)) == 1 })
	z.block.Store(true)
	r.authority.requestCheck()
	select {
	case <-z.started:
	case <-time.After(3 * time.Second):
		t.Fatal("authority read did not start")
	}
	r.admit(e, transportWire(ev.Reply, time.Now(), modbusReadReply(1)))
	waitTransport(t, func() bool { return len(transportModbusEvents(e)) == 2 })
	close(z.release)
	waitTransport(t, func() bool { return r.authority.version.Load()%2 == 0 })
	reply := transportModbusEvents(e)[0]
	e.flowMu.Lock()
	c := e.tupleStateLocked(ev.Reply).Connection.Load()
	e.flowMu.Unlock()
	if reply.CorrelationStatus != "resolved" || !c.CorrelationAvailable(time.Now()) {
		t.Fatalf("periodic zone read degraded a verified connection: reply status=%s available=%v stats=%+v",
			reply.CorrelationStatus, c.CorrelationAvailable(time.Now()), e.AnomalyDetector().PairingStats())
	}
}
