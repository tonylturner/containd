// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// establishedSyn sends a client SYN into the established connection: nft
// queues it without the handshake mark. Its payload sequence number is the
// stream's offset off.
func (f *fcFlow) establishedSyn(off uint32) capture.Decision {
	pkt := connSegment(false, f.client, f.port, f.isn+off, capture.TCPFlagSYN, nil)
	pkt.HasMark, pkt.Mark = false, 0
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := f.e.HandlePacket(pkt)
	v := capture.VerdictAccept
	if d.Action == capture.Drop {
		v = capture.VerdictDrop
	}
	f.e.hooks.onVerdict(pkt.Token, v, nil)
	return d
}

// TestEstablishedSYNDoesNotReanchorPickup sends, on a connection the
// engine picks up mid-connection, a SYN whose sequence number would anchor
// a new stream at the client's next byte, as a sender choosing where
// framing starts would. The kernel saw the connection's handshake
// complete, so the SYN carries no handshake mark and anchors nothing: the
// connection's next read still drops as a pickup, and once the pickup
// failed the SYN drops with it. The SYN of a new handshake still starts
// the client's next connection on the same tuple.
func TestEstablishedSYNDoesNotReanchorPickup(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		rule := p.name + "-read"
		t.Run(p.name+"/flow swept while idle", func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.syn()
			f.accept("read before the sweep", p.read(1))
			f.e.sweepFlows(time.Now().Add(time.Hour))
			if d := f.establishedSyn(f.next); d.Action != capture.Accept {
				t.Fatalf("SYN of a forgotten flow = %+v, want Accept", d)
			}
			f.pickedUp("read after the SYN", f.decide(f.next, ackPsh, p.read(2)), rule, 0)
		})
		t.Run(p.name+"/after the pickup", func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.pickedUp("read on the picked-up stream", f.decide(f.next, ackPsh, p.read(1)), rule, 0)
			if d := f.establishedSyn(f.next); d.Action != capture.Drop || d.Reason != reasonCachedDeny {
				t.Fatalf("SYN after the pickup = %+v, want Drop by %s", d, reasonCachedDeny)
			}
			f.dropCachedAt(f.next, "read after the SYN", p.read(1))
			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.pickedUp("SYN past the cached denial", f.establishedSyn(f.next), rule, 1)
			f.dropCachedAt(f.next, "read after that SYN", p.read(1))

			f.isn, f.next = 800000, 0
			f.syn()
			hits := ruleHits(f.e, rule)
			f.accept("read on the next connection", p.read(2))
			if got := ruleHits(f.e, rule); got != hits+1 {
				t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
			}
		})
	}
}
