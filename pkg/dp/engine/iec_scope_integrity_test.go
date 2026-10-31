// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"testing"
)

func TestReverseSYNDoesNotBypassIECEnforce(t *testing.T) {
	baseline := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecTypedPolicy("enforce"))
	if _, d := baseline.send(true, apdu(46, 6, 1, 3000, 2)); d.Action != capture.Drop {
		t.Fatalf("control should deny: %+v", d)
	}
	h := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecTypedPolicy("enforce"))
	forged := h.pkt(false, capture.TCPFlagSYN, 7000, 0, nil)
	forged.Mark, forged.HasMark = enforce.EnvelopeMark, true // established conntrack: no HandshakeMark
	t.Logf("reverse SYN: %+v", h.e.HandlePacket(forged))
	pkt := h.pkt(true, ackPsh, h.cSeq, h.sSeq, apdu(46, 6, 1, 3000, 2)) // not the permitted IOA 2001
	pkt.Mark, pkt.HasMark = enforce.EnvelopeMark, true
	d := h.e.HandlePacket(pkt)
	if d.Action != capture.Drop {
		t.Fatalf("forbidden command after reverse SYN: %+v; want Drop", d)
	}
}
