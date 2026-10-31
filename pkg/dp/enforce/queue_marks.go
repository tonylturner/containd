// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package enforce

import (
	"bytes"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/markabi"
)

// Queue entry replaces ContinuationSkbMask, preserving unrelated skb bits.
// EnforceScopeMark identifies enforcing scopes. Within QueueMarkMask,
// EnvelopeMark means "steered to the queue by an IEC104 envelope rule"
// and HandshakeMark "connection tracking tracks the packet in a connection
// whose handshake it has not seen complete" (ct status not assured, ct
// state neither invalid nor untracked). Both queue chains set
// HandshakeMark; an envelope packet carries both bits.
//
// A SYN or SYN-ACK of a new connection, a retransmission of one, and a SYN
// that reopens a closed connection carry HandshakeMark. One sent into a
// connection that completed its handshake does not: connection tracking
// keeps the connection assured and ignores the segment. The engine anchors
// a fail-closed stream, and opens an enforce IEC104 session, only at a
// handshake segment with the mark.
const (
	QueueMarkMask uint32 = markabi.QueueMarkMask
	EnvelopeMark  uint32 = markabi.EnvelopeMark
	HandshakeMark uint32 = markabi.HandshakeMark
	// ObservedMark skips all ICS steering on the repeated traversal.
	ObservedMark uint32 = markabi.ObservedMark
)

// EnvelopeMarked reports whether an NFQUEUE skb mark carries EnvelopeMark.
func EnvelopeMarked(mark uint32) bool {
	return mark&EnvelopeMark != 0
}

// HandshakeMarked reports whether an NFQUEUE skb mark carries
// HandshakeMark.
func HandshakeMarked(mark uint32) bool {
	return mark&HandshakeMark != 0
}

// queueRules returns the rules of a chain that queues every packet to
// c.QueueID with containd's mark bits set to mark, and HandshakeMark added
// for a packet of a connection whose handshake connection tracking has not
// seen complete.
func (c *Compiler) queueRules(mark uint32) []string {
	set := func(bits uint32) string {
		if bits == 0 {
			return fmt.Sprintf("meta mark set meta mark and 0x%08x queue num %d", ^markabi.ContinuationSkbMask, c.QueueID)
		}
		return fmt.Sprintf("meta mark set meta mark and 0x%08x or 0x%08x queue num %d", ^markabi.ContinuationSkbMask, bits, c.QueueID)
	}
	return []string{
		"ct status assured " + set(mark),
		trackedState + " " + set(mark|HandshakeMark),
		set(mark),
	}
}

// ICSQueueChain is the observation chain for generic ICS scopes. Enforcing
// scopes use enforceQueueChain. Both queue the packet to the engine with
// HandshakeMark or without containd's mark bits (queueRules).
const ICSQueueChain = "ics_queue"

// writeICSQueueChain emits ICSQueueChain.
func (c *Compiler) writeICSQueueChain(buf *bytes.Buffer) {
	buf.WriteString("  chain " + ICSQueueChain + " {\n")
	for _, rule := range c.queueRules(0) {
		buf.WriteString("    " + rule + ";\n")
	}
	buf.WriteString("  }\n")
}

// unobservedGuard prevents a repeated observation from entering any ICS queue.
var unobservedGuard = fmt.Sprintf("meta mark & 0x%08x == 0", markabi.ObservedMark)
