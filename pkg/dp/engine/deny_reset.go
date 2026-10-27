// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"hash/fnv"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// deniedTCP is a tuple tombstone, independent of verdict/reassembly cache
// expiry. Only a kernel-marked new handshake retires it. The reset job and
// retirement serialize per tuple so a delayed job cannot delete a reconnect's
// conntrack entry. Reset I/O never holds the global flow lock.
type deniedTCP struct {
	mu      sync.Mutex
	retired bool
	isn     uint32
	hasISN  bool
}

func (e *Engine) isDeniedTCP(state *flow.State) bool {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	return e.deniedTCP[tcpTupleHash(state.Key)] != nil
}

func (e *Engine) closeDeniedTCP(pkt capture.Packet, state *flow.State, proto, reason string) {
	if !pkt.Token.Inline() || pkt.Proto != 6 {
		return
	}
	e.flowMu.Lock()
	if e.deniedTCP == nil {
		e.deniedTCP = make(map[string]*deniedTCP)
	}
	key := tcpTupleHash(state.Key)
	if e.deniedTCP[key] != nil {
		e.flowMu.Unlock()
		return
	}
	openerKey := state.Key
	if openerKey.Dir == flow.DirReverse {
		openerKey = openerKey.Reversed()
	}
	isn, hasISN := e.tcpISNs[openerKey.Hash()]
	d := &deniedTCP{isn: isn, hasISN: hasISN}
	e.deniedTCP[key] = d
	e.flowMu.Unlock()
	e.resetDeniedTCP(pkt, state, proto, reason, d)
}

func (e *Engine) reopenDeniedTCP(pkt capture.Packet) {
	if isIECPort(pkt) || pkt.Proto != 6 || !pkt.TCP.Valid ||
		pkt.TCP.Flags&capture.TCPFlagSYN == 0 || pkt.TCP.Flags&(capture.TCPFlagACK|capture.TCPFlagRST) != 0 ||
		!handshakeMarked(pkt) {
		return
	}
	key := flow.Key{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Proto: 6}
	e.flowMu.Lock()
	tuple := tcpTupleHash(key)
	d := e.deniedTCP[tuple]
	e.flowMu.Unlock()
	if d == nil || d.hasISN && d.isn == pkt.TCP.Seq {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.retired {
		return
	}
	d.retired = true
	e.flowMu.Lock()
	var forgotten []*flow.State
	delete(e.deniedTCP, tuple)
	// Orientation hints can change while the tuple is denied. Forget both
	// possible orientations of its two wire directions, never other tuples.
	reverseOrientation := key
	reverseOrientation.Dir = flow.DirReverse
	for _, k := range []flow.Key{key, key.Reversed(), reverseOrientation, reverseOrientation.Reversed()} {
		e.verdictCache.Invalidate(k.Hash())
		if st := e.dropFlowLocked(k); st != nil {
			forgotten = append(forgotten, st)
		}
	}
	e.flowMu.Unlock()
	for _, st := range forgotten {
		e.endFlowStream(st, nil)
	}
}

// lockGenericTCP serializes decisions in both directions of a generic TCP
// tuple. Otherwise an already-waiting duplicate can finish DPI between the
// original packet's inspection and its denial, and pass as consumed bytes.
// Fixed stripes bound synchronization state without expiring denied tuples.
func (e *Engine) lockGenericTCP(pkt capture.Packet) func() {
	if pkt.Proto != 6 || isIECPort(pkt) {
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
