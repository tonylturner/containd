// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

func TestLiveDPIEventCaptureTime(t *testing.T) {
	e := recordEngine(t)
	at := time.Unix(1234567890, 123456789)
	pkt := recordPacket(1000, capture.TCPFlagACK, "ABCD")
	pkt.Timestamp = at
	e.HandlePacket(pkt)
	if evs := e.Events().List(0); len(evs) != 1 || !evs[0].Timestamp.Equal(at) {
		t.Fatalf("live events = %+v", evs)
	}
}
