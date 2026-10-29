// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

func processTransportAdmission(t *testing.T, e *Engine, r *transportResolver) {
	t.Helper()
	select {
	case p := <-r.queue:
		c := r.resolve(context.Background(), p.packet, false)
		e.handleTransportPacket(p.packet, c, p.history)
		r.count.Add(-1)
		r.bytes.Add(-int64(len(p.packet.Payload)))
	default:
		t.Fatal("no admitted packet")
	}
}

func TestTransportReusedSYNReceivesQueuedLoss(t *testing.T) {
	for _, olderQueued := range []bool{false, true} {
		t.Run(map[bool]string{false: "opener-first", true: "older-packet-pending"}[olderQueued], func(t *testing.T) {
			evidence := natEvidence()
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
			r.authority.check(context.Background())
			syn := transportWire(evidence.Original, time.Now(), nil)
			syn.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 1000}
			r.admit(e, syn)
			processTransportAdmission(t, e, r)
			oldSlot := r.indexed[evidence.Original]
			old := oldSlot.connection
			if old.Closed().Load() || !old.CorrelationAvailable(time.Now()) {
				t.Fatal("fixture lacks an open covered predecessor")
			}
			ack := syn
			ack.TCP.Flags = capture.TCPFlagACK
			if olderQueued {
				r.admit(e, ack)
			}
			syn.TCP.Seq++
			r.admit(e, syn) // Still waiting inside the timestamp reorder window.
			freshSlot := r.indexed[evidence.Original]
			if freshSlot == oldSlot || freshSlot.connection.Key != "" {
				t.Fatal("new ISN did not reserve a fresh placeholder")
			}
			for r.count.Load() < transportQueueLimit {
				r.admit(e, ack)
			}
			req := transportWire(evidence.Original, time.Now(), modbusADU(1, 3, 10, 2))
			r.admit(e, req) // The new incarnation's first request is lost.
			r.admit(e, syn) // A SYN retransmission must retain its loss history.
			if r.indexed[evidence.Original] != freshSlot || !old.CorrelationAvailable(time.Now()) {
				t.Fatal("new-incarnation overflow landed on the predecessor")
			}
			if olderQueued {
				processTransportAdmission(t, e, r)
				if r.indexed[evidence.Original] != freshSlot {
					t.Fatal("older queued packet stole the new SYN's slot")
				}
			}
			processTransportAdmission(t, e, r)
			fresh := freshSlot.connection
			if fresh.Key == old.Key || !fresh.Coverage().Load() || fresh.CorrelationAvailable(time.Now()) {
				t.Fatal("fresh incarnation lost its queued overflow history")
			}
			reply := transportWire(evidence.Reply, time.Now(), modbusReadReply(1))
			e.handleTransportPacket(reply, r.resolve(context.Background(), reply, false), nil)
			if stats := e.AnomalyDetector().PairingStats(); stats.Unmatched != 0 || stats.Unavailable != 1 {
				t.Fatalf("lost request became an unmatched reply: %+v", stats)
			}
		})
	}
}
