// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"container/list"
	"hash/fnv"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// deniedTCP is a tuple tombstone, independent of verdict/reassembly cache
// expiry. Expiry, capacity eviction or a kernel-marked new handshake retires it.
// Reset jobs and retirement serialize per tuple so a delayed job cannot delete
// a reconnect's conntrack entry. Reset I/O never holds the global flow lock.
type deniedTCP struct {
	mu      sync.Mutex
	retired bool
	isn     uint32
	hasISN  bool
	key     flow.Key
	tuple   string
	expires time.Time
	order   *list.Element
}

func (e *Engine) isDeniedTCP(state *flow.State) bool {
	for {
		e.flowMu.Lock()
		d := e.deniedTCP[tcpTupleHash(state.Key)]
		e.flowMu.Unlock()
		if d == nil {
			return false
		}
		if e.deniedTCPNow().Before(d.expires) {
			return true
		}
		// Enforce the lifetime even between the periodic flow sweeps.
		e.retireDeniedTCP(d, false)
	}
}

func (e *Engine) closeDeniedTCP(pkt capture.Packet, state *flow.State, proto, reason string) {
	if !pkt.Token.Inline() || pkt.Proto != 6 {
		return
	}
	e.flowMu.Lock()
	rev := e.flows[state.Key.Reversed().Hash()]
	e.flowMu.Unlock()
	if rev != nil {
		e.dpiMgr.FailStream(rev, &dpi.ParsedPacket{Proto: "tcp", FailClosed: true}, dpi.StreamDenied)
	}
	// Publish the guard only after both streams and the verdict cache have
	// failed. An immediate capacity eviction must clear all of that state;
	// nothing may recreate it after the guard has been retired.
	if d := e.rememberDeniedTCP(state.Key); d != nil {
		e.resetDeniedTCP(pkt, state, proto, reason, d)
	}
}

func (e *Engine) reopenDeniedTCP(pkt capture.Packet) {
	if pkt.Proto != 6 || e.iecOwnsPacket(pkt) || !pkt.TCP.Valid ||
		pkt.TCP.Flags&capture.TCPFlagSYN == 0 || pkt.TCP.Flags&(capture.TCPFlagACK|capture.TCPFlagRST) != 0 ||
		!handshakeMarked(pkt) {
		return
	}
	key := flow.Key{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Proto: 6}
	e.flowMu.Lock()
	tuple := tcpTupleHash(key)
	d := e.deniedTCP[tuple]
	e.flowMu.Unlock()
	if d == nil || e.deniedTCPNow().Before(d.expires) && d.hasISN && d.isn == pkt.TCP.Seq {
		return
	}
	e.retireDeniedTCP(d, false)
}

// lockGenericTCP serializes decisions in both directions of a generic TCP
// tuple. Otherwise an already-waiting duplicate can finish DPI between the
// original packet's inspection and its denial, and pass as consumed bytes.
// Fixed stripes bound synchronization state independently of tuple retention.
func (e *Engine) lockGenericTCP(pkt capture.Packet) func() {
	if pkt.Proto != 6 || e.iecOwnsPacket(pkt) {
		return func() {}
	}
	key := flow.Key{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Proto: 6}
	h := fnv.New32a()
	_, _ = h.Write([]byte(tcpTupleHash(key))) // hash writes cannot fail
	mu := &e.tcpDecisions[h.Sum32()%uint32(len(e.tcpDecisions))]
	mu.Lock()
	return mu.Unlock
}

// tcpTupleHash is independent of wire direction and opener orientation. A
// late or forged handshake must not evade a tombstone by changing Key.Dir.
func tcpTupleHash(key flow.Key) string {
	key.Dir = flow.DirForward
	reverse := key.Reversed()
	reverse.Dir = flow.DirForward
	a, b := key.Hash(), reverse.Hash()
	if b < a {
		return b
	}
	return a
}
