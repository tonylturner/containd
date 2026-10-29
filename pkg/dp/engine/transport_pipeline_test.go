// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportMidstreamOutstandingReply(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	r.authority.check(context.Background())
	// Capture starts after request 1 was sent, but before pipelined request 2.
	request := transportWire(ev.Original, time.Now(), modbusADU(2, 3, 10, 2))
	request.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 1000}
	e.handleTransportPacket(request, r.resolve(context.Background(), request, false))
	reply := transportWire(ev.Reply, time.Now(), []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11})
	reply.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 2000}
	e.handleTransportPacket(reply, r.resolve(context.Background(), reply, false))
	if got := len(transportModbusEvents(e)); got != 2 {
		t.Fatalf("decoded %d events, want request and reply", got)
	}
	stats := e.AnomalyDetector().PairingStats()
	if stats.Unmatched != 0 {
		t.Fatalf("legitimate outstanding reply classified unmatched after midstream start: %+v", stats)
	}
}

func TestTransportSuccessfulRefreshDuringEventPipeline(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	ctx := context.Background()
	r.authority.check(ctx)
	p := transportWire(ev.Original, time.Now(), nil)
	c := r.resolve(ctx, p, false)
	st := flow.NewState(flow.TupleKey(ev.Original, flow.DirForward), time.Now())
	st.Connection.Store(c)
	e.flows[st.Key.Hash()] = st
	c.Coverage().Store(true) // Earlier request/reply established coverage.
	events := []dpi.Event{{FlowID: st.Key.Hash(), Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"transaction_id": uint16(7), "unit_id": uint8(1), "function_code": uint8(3)}}}
	bindEventConnections(st, events)
	// A concurrent ruleset apply can refresh authority after binding, before
	// RecordDPIEvents runs pairing. The refresh succeeds and has no zone setters.
	r.authority.check(ctx)
	e.RecordDPIEvents(st, &dpi.ParsedPacket{Proto: "tcp"}, events)
	p = transportWire(ev.Reply, time.Now(), nil)
	replyState := flow.NewState(flow.TupleKey(ev.Reply, flow.DirReverse), time.Now())
	e.flows[replyState.Key.Hash()] = replyState
	e.bindTransport(replyState, r.resolve(ctx, p, false))
	reply := events[0]
	reply.FlowID, reply.Kind, reply.Connection = replyState.Key.Hash(), "response", nil
	e.RecordDPIEvents(replyState, &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{reply})
	stats := e.AnomalyDetector().PairingStats()
	if stats.Unmatched != 0 {
		t.Fatalf("observed request lost across successful authority refresh: %+v", stats)
	}
}

func TestTransportCannotMergeIssuedHistories(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	evidence := natEvidence()
	original := flow.NewState(flow.TupleKey(evidence.Original, flow.DirForward), time.Now())
	reply := flow.NewState(flow.TupleKey(evidence.Reply, flow.DirReverse), time.Now())
	for i, st := range []*flow.State{original, reply} {
		id := flow.TransportConnectionID("issued-original")
		if i == 1 {
			id = "issued-reply"
		}
		c := &flow.Connection{ID: id, Key: string(id), Status: "resolved", Evidence: &evidence}
		c.Published().Store(true)
		st.Connection.Store(c)
		e.flows[st.Key.Hash()] = st
	}
	r.authority.check(context.Background())
	e.bindTransport(reply, r.resolve(context.Background(), transportWire(evidence.Reply, time.Now(), nil), false))
	if got := reply.Connection.Load(); got.ID != "issued-reply" || got.Key != "issued-reply" || got.Status != "ambiguous" {
		t.Fatalf("renamed issued history: %+v", got)
	}
}
