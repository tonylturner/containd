// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// NewLearnerOverflowEngine exposes controlled transport admission only to the
// external integration test. No production test switches or kernel I/O exist.
func NewLearnerOverflowEngine(t *testing.T) (*Engine, func(bool)) {
	t.Helper()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	return e, func(loss bool) {
		at := time.Now()
		pkt := transportWire(natEvidence().Original, at, nil)
		pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
		r.admit(e, pkt)
		processTransportAdmission(t, e, r)
		pkt.Timestamp, pkt.Payload = at.Add(time.Millisecond), modbusADU(1, 3, 10, 2)
		pkt.TCP.Flags, pkt.TCP.Seq = capture.TCPFlagACK, 101
		r.admit(e, pkt)
		processTransportAdmission(t, e, r)
		if len(transportModbusEvents(e)) != 1 {
			t.Fatal("missing initial read")
		}
		if loss {
			pkt.Timestamp, pkt.Payload = at.Add(2*time.Millisecond), make([]byte, transportByteLimit+1)
			r.admit(e, pkt)
			select {
			case notice := <-r.losses:
				e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
			default:
				t.Fatal("real transport byte overflow failed to notify")
			}
		}
	}
}
