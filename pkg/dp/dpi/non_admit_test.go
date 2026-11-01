// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"errors"
	"testing"
)

func TestNonAdmitStreamLifetime(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(100, true))
	wantFrames(t, "decoded frame", mgr.Inspect(st, failClosedSeg(100, 0x01, 0xaa)), frameRange{0, 2})
	mgr.FailStream(st, failClosedSeg(100), StreamNonAdmit)
	failed := func(p *ParsedPacket) {
		t.Helper()
		res := mgr.Inspect(st, p)
		var se *StreamError
		if !res.Failed || !errors.As(res.Err, &se) || se.Kind != StreamNonAdmit || len(res.Events) != 0 {
			t.Fatalf("lost non-admitting stream: %+v", res)
		}
	}
	failed(failClosedSeg(100, 0x01, 0xaa))
	failed(finSeg(102))
	rst := failClosedSeg(102)
	rst.TCPRst = true
	failed(rst)
	failed(synSeg(100, true))            // replay of the old handshake
	failed(establishedSynSeg(500, true)) // forged SYN on established CT
	withData := func(p *ParsedPacket) *ParsedPacket {
		p.Payload = []byte{0x01, 0xbb}
		return p
	}
	failed(withData(synSeg(100, true)))
	failed(withData(establishedSynSeg(500, true)))
	wantFrames(t, "new handshake with data", mgr.Inspect(st, withData(synSeg(500, true))), frameRange{0, 2})
	wantFrames(t, "handshake retransmission", mgr.Inspect(st, withData(synSeg(500, true))))
}
