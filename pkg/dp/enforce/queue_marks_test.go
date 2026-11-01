// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package enforce

import (
	"fmt"
	"strings"
	"testing"
)

// TestICSQueueChainMarksHandshakes pins the chain every generic ICS queue
// line jumps to: a packet conntrack tracks in a connection it has not seen
// complete its handshake is queued with HandshakeMark, any other with
// containd's mark bits cleared.
// The chain is declared once, before the forward chain, and only for a
// ruleset that queues a generic ICS rule.
func TestICSQueueChainMarksHandshakes(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	for _, mark := range []uint32{0, 0x08000000, 0x09000000} {
		got := strings.Join(c.queueRules(mark), "\n")
		assertText(t, got, "ct status assured", trackedState, "0xe0ffffff", "queue num 100")
		if mark != 0 {
			assertText(t, got, fmt.Sprintf("or 0x%08x", mark), fmt.Sprintf("or 0x%08x", mark|HandshakeMark))
		}
	}
}

func TestQueueMarks(t *testing.T) {
	for _, tc := range []struct {
		mark                uint32
		envelope, handshake bool
	}{
		{0, false, false},
		{EnvelopeMark, true, false},
		{HandshakeMark, false, true},
		{HandshakeMark | 0x5, false, true},
		{EnvelopeMark | HandshakeMark, true, true},
		{EnvelopeMark | HandshakeMark | 0x5, true, true},
		{0x00ffffff, false, false},
	} {
		if EnvelopeMarked(tc.mark) != tc.envelope || HandshakeMarked(tc.mark) != tc.handshake {
			t.Fatalf("mark %#x: envelope %v, handshake %v; want %v, %v", tc.mark, EnvelopeMarked(tc.mark), HandshakeMarked(tc.mark), tc.envelope, tc.handshake)
		}
	}
}
