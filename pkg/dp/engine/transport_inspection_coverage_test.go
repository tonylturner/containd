// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"testing"
	"time"
)

// Exclusion applies to the original client's wire IP, not to the SNAT reply.
// Seeing its SYN must not prove that its deliberately uninspected requests
// were all entered into the transaction table.
func TestTransportNATExcludedRequestsDoNotBecomeUnmatched(t *testing.T) {
	evidence := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
	e.dpiExclusions = []DPIExclusion{{Type: "ip", Value: evidence.Original.Source.Addr().String()}}
	r.authority.check(context.Background())
	deliver := func(p capture.Packet) {
		t.Helper()
		r.admit(e, p)
		select {
		case q := <-r.queue:
			c := r.resolve(context.Background(), q.packet, false)
			e.handleTransportPacket(q.packet, c, q.history)
			r.count.Add(-1)
			r.bytes.Add(-int64(len(q.packet.Payload)))
		default:
		}
	}
	at := time.Now().Add(-3 * time.Minute)
	syn := transportWire(evidence.Original, at, nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1000}
	if e.transportEligible(syn) {
		t.Fatal("excluded opener entered resolver")
	}
	deliver(syn)
	ack := transportWire(evidence.Reply, at.Add(time.Second), nil)
	ack.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 2000}
	deliver(ack)
	for i, delta := range []time.Duration{3 * time.Minute, 3*time.Minute + time.Millisecond} {
		req := transportWire(evidence.Original, at.Add(delta), modbusADU(uint16(i+1), 3, 10, 2))
		req.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 1001 + uint32(i*12)}
		deliver(req)
		reply := transportWire(evidence.Reply, at.Add(delta+time.Millisecond), []byte{0, byte(i + 1), 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11})
		reply.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 2000 + uint32(i*13)}
		if !e.transportEligible(reply) {
			t.Fatal("translated reply unexpectedly excluded")
		}
		deliver(reply)
	}
	evs := transportModbusEvents(e)
	if len(evs) != 2 {
		t.Fatalf("decoded %d events, want two replies: %+v", len(evs), evs)
	}
	for _, ev := range evs {
		if ev.Kind != "response" {
			t.Fatalf("unexpected inspected request: %+v", ev)
		}
	}
	stats := e.AnomalyDetector().PairingStats()
	if stats.Unmatched != 0 {
		t.Fatalf("excluded NAT requests became false unmatched replies after timeout: %+v", stats)
	}
}

func TestTransportInspectionBypassExtendsRecovery(t *testing.T) {
	evidence := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
	ctx := context.Background()
	r.authority.check(ctx)
	at := time.Now()
	syn := transportWire(evidence.Original, at, nil)
	syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1000}
	e.handleTransportPacket(syn, r.resolve(ctx, syn, false), nil)
	e.flowMu.Lock()
	state := e.tupleStateLocked(evidence.Original)
	e.flowMu.Unlock()
	c := state.Connection.Load()
	if !c.CorrelationAvailable(at) {
		t.Fatal("inspected opener did not establish coverage")
	}
	e.dpiExclusions = []DPIExclusion{{Type: "ip", Value: evidence.Original.Source.Addr().String()}}
	for _, delta := range []time.Duration{time.Second, time.Minute} {
		req := transportWire(evidence.Original, at.Add(delta), modbusADU(1, 3, 10, 2))
		r.admit(e, req) // Deliberate bypass, never queued or decoded.
		if r.count.Load() != 0 || len(transportModbusEvents(e)) != 0 {
			t.Fatal("excluded request was inspected")
		}
	}
	if c.CorrelationAvailable(at.Add(2*time.Minute+time.Second)) ||
		!c.CorrelationAvailable(at.Add(3*time.Minute+time.Second)) {
		t.Fatal("inspection bypass did not extend the latest-gap deadline")
	}
	// Once inspection resumes and the full quiet timeout passes, a genuine
	// unmatched reply still alerts on this already-started incarnation.
	e.dpiExclusions = nil
	reply := transportWire(evidence.Reply, at, nil)
	e.handleTransportPacket(reply, r.resolve(ctx, reply, false), nil)
	e.flowMu.Lock()
	reverse := e.tupleStateLocked(evidence.Reply)
	e.flowMu.Unlock()
	ev := dpi.Event{FlowID: reverse.Key.Hash(), Proto: "modbus", Kind: "response",
		Timestamp:  at.Add(3*time.Minute + time.Second),
		Attributes: map[string]any{"transaction_id": uint16(99), "unit_id": uint8(1), "function_code": uint8(3)}}
	ev.Connection = reverse.Connection.Load()
	e.AnomalyDetector().Check(evidence.Reply.Source.Addr().String(), evidence.Reply.Destination.Addr().String(), ev)
	if e.AnomalyDetector().PairingStats().Unmatched != 1 {
		t.Fatalf("inspection bypass disabled detection permanently: %+v", e.AnomalyDetector().PairingStats())
	}
}
