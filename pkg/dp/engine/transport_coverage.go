// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

// Coverage markers share the admission index's lifetime, not the lookup TTL.
// All fields (including parent links) are protected by admissionMu. A marker
// can also be retained by queued packets or a live directional flow.
type transportCoverage struct {
	parent       *transportCoverage
	packet       capture.Packet // metadata only; never retains dropped payload
	at           time.Time
	lost         bool
	stopped      bool
	reported     bool
	scheduled    bool
	dirty        bool
	unindexed    bool
	epoch        uint64
	key          string // worker-resolved incarnation for a loss preceding its first flow state
	conservative bool
	reason       string
	generation   *conntrack.Evidence // passive marker; IEC legacy evidence can remain retained
}

func (c *transportCoverage) root() *transportCoverage {
	if c == nil {
		return nil
	}
	if c.parent != nil {
		c.parent = c.parent.root()
		return c.parent
	}
	return c
}

func mergeTransportCoverage(a, b *transportCoverage) *transportCoverage {
	a, b = a.root(), b.root()
	if a == nil {
		return b
	}
	if b == nil || a == b {
		return a
	}
	if b.lost && (!a.lost || b.packet.Timestamp.Before(a.packet.Timestamp)) {
		a.packet, a.at, a.reason = b.packet, b.at, b.reason
	}
	a.lost, a.stopped, a.reported = a.lost || b.lost, a.stopped || b.stopped, a.reported || b.reported
	a.scheduled = a.scheduled || b.scheduled
	a.dirty = a.dirty || b.dirty || a.stopped
	if b.unindexed && (!a.unindexed || b.epoch < a.epoch) {
		a.epoch = b.epoch
	}
	a.unindexed = a.unindexed || b.unindexed
	a.conservative = a.conservative || b.conservative
	if a.key == "" {
		a.key = b.key
	}
	if a.generation == nil {
		a.generation = b.generation
	}
	b.parent = a
	return a
}

func (r *transportResolver) noteDecodeLossLocked(pkt capture.Packet, history *transportAdmission) {
	if history == nil {
		// No tuple slot can retain this loss. A fixed-size barrier stops
		// already-started unindexed streams conservatively at their next
		// worker packet, without refusing unrelated new incarnations.
		r.unindexedLoss++
		return
	}
	if history.coverage == nil {
		history.coverage = &transportCoverage{}
	}
	c := history.coverage.root()
	if c.stopped {
		return
	}
	if !c.lost || pkt.Timestamp.Before(c.packet.Timestamp) {
		pkt.Payload = nil
		pkt.SrcIP, pkt.DstIP = bytes.Clone(pkt.SrcIP), bytes.Clone(pkt.DstIP)
		c.packet, c.at, c.lost, c.reason = pkt, time.Now(), true, "transport_queue_overflow"
	}
	if c.scheduled {
		return
	}
	notice := transportPacket{packet: c.packet, at: c.at, history: history, loss: c}
	select {
	case r.losses <- notice:
		c.scheduled = true
	default:
		// No unbounded side queue. The marker itself retains the loss.
		// The worker collects these bounded index/flow/packet owners.
		r.lossFallback = true
		c.conservative = true
	}
}

// Caller holds flowMu then admissionMu, the same order as trackConnection.
func (e *Engine) bindDecodeCoverageLocked(st *flow.State, history *transportAdmission) {
	// A packet can retain its state after concurrent denial retirement or
	// sweeping. Never resurrect that state (or attach its history to a reuse).
	if e.flows[st.Key.Hash()] != st {
		return
	}
	r := e.transport
	if e.transportCoverage == nil {
		e.transportCoverage = make(map[*flow.State]*transportCoverage)
	}
	c := e.transportCoverage[st]
	if c == nil {
		c = &transportCoverage{}
	}
	connection := st.Connection.Load()
	if history != nil && (history.connection.Key == "" || history.connection.Key == connection.Key) {
		c = mergeTransportCoverage(c, history.coverage)
		history.coverage = c
	} else if history != nil {
		previous := history.coverage.root()
		if previous != nil && previous.conservative && previous.lost && !previous.stopped {
			// At notice capacity the token is the only owner of the loss.
			// A worker-discovered generation must not discard that stop
			// when it retires the token's admission-time predecessor.
			if !c.lost || previous.packet.Timestamp.Before(c.packet.Timestamp) {
				c.packet, c.at, c.reason = previous.packet, previous.at, previous.reason
			}
			c.lost, c.conservative = true, true
			r.lossFallback = true
		}
	}
	tuples := []flow.Key{st.Key, connection.Peer(st.Key)}
	for _, key := range tuples {
		if peer := e.tupleStateLocked(key.Tuple()); peer != nil {
			if pc := peer.Connection.Load(); pc != nil && pc.Key == connection.Key {
				c = mergeTransportCoverage(c, e.transportCoverage[peer])
			}
		}
		if entry := r.indexed[key.Tuple()]; entry != nil {
			loss := entry.coverage.root()
			if entry.connection.Key == connection.Key || loss != nil && loss.key == connection.Key {
				c = mergeTransportCoverage(c, entry.coverage)
				entry.coverage = c
			}
		}
	}
	e.transportCoverage[st] = c
	if c.unindexed && c.epoch != r.unindexedLoss && !c.lost {
		transport := "tcp"
		if st.Key.Proto == 17 {
			transport = "udp"
		}
		r.noteDecodeLossLocked(capture.Packet{Timestamp: st.LastSeen, SrcIP: st.Key.SrcIP,
			DstIP: st.Key.DstIP, SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort,
			Proto: st.Key.Proto, Transport: transport}, &transportAdmission{coverage: c})
		c.conservative, c.reason = true, "transport_loss_index_capacity"
	}
	entry := r.indexed[st.Key.Tuple()]
	c.unindexed = entry == nil || entry.connection.Key != connection.Key
	c.epoch = r.unindexedLoss
}

// A full notice channel cannot discard a stop marker. Scan only on that rare
// path and cap the pending window, collecting from already bounded owners.
func (r *transportResolver) decodeLossFallback(e *Engine, pending []transportPacket) []transportPacket {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	if !r.lossFallback {
		return nil
	}
	r.lossFallback = false
	var out []transportPacket
	add := func(c *transportCoverage) {
		c = c.root()
		if c == nil || !c.lost || c.stopped || c.scheduled {
			return
		}
		if len(pending)+len(out) >= 2*transportQueueLimit {
			r.lossFallback = true
			return
		}
		c.scheduled = true
		out = append(out, transportPacket{packet: c.packet, at: c.at, loss: c})
	}
	for _, h := range r.indexed {
		add(h.coverage)
	}
	for _, c := range e.transportCoverage {
		add(c)
	}
	for _, p := range pending {
		if p.history != nil {
			add(p.history.coverage)
		}
	}
	return out
}

// Stop at the worker's loss point. A late/earlier notice or equal timestamp
// stops conservatively at the next packet; already processed bytes cannot be
// retracted. This guard also covers a notice still waiting for a bounded slot.
func (e *Engine) applyDecodeCoverage(st *flow.State, pkt capture.Packet) bool {
	r := e.transport
	if r == nil || pkt.Token.Inline() {
		return false
	}
	e.flowMu.Lock()
	r.admissionMu.Lock()
	c := e.transportCoverage[st].root()
	stop := c != nil && (c.stopped || c.conservative && c.lost && !pkt.Timestamp.Before(c.packet.Timestamp))
	r.admissionMu.Unlock()
	e.flowMu.Unlock()
	if stop {
		e.stopDecodeCoverage(c, st.Connection.Load())
	}
	return stop
}

func (e *Engine) consumeDecodeLoss(p transportPacket, connection *flow.Connection) {
	// Resolve and retire at the same worker boundary as an ordinary packet.
	// An admission token can still describe the previous generation when
	// a SYN or CT transition overtook the loss in capture-time order.
	e.retireTransportIncarnation(p.packet, connection)
	r := e.transport
	e.flowMu.Lock()
	r.admissionMu.Lock()
	source := p.loss.root()
	tuples := []flow.Key{packetKey(p.packet), packetKey(p.packet).Reversed()}
	if connection.Evidence != nil {
		tuples = append(tuples, flow.TupleKey(connection.Evidence.Original, flow.DirForward),
			flow.TupleKey(connection.Evidence.Reply, flow.DirReverse))
	}
	var target *transportCoverage
	for _, key := range tuples {
		if st := e.tupleStateLocked(key.Tuple()); st != nil && e.flows[st.Key.Hash()] == st {
			current := st.Connection.Load()
			if current != nil && (current.Key == connection.Key || !connection.Verified() ||
				sameGeneration(current.Evidence, connection.Evidence)) {
				connection = current
				target = e.transportCoverage[st].root()
				if target == nil {
					target = &transportCoverage{}
					if e.transportCoverage == nil {
						e.transportCoverage = make(map[*flow.State]*transportCoverage)
					}
					e.transportCoverage[st] = target
				}
				break
			}
		}
	}
	if target == nil {
		for _, key := range tuples {
			if entry := r.indexed[key.Tuple()]; entry != nil {
				candidate := entry.coverage.root()
				if candidate != nil && candidate.key == connection.Key {
					target = candidate
					break
				}
			}
		}
	}
	if target == nil {
		entry := r.admissionHistoryLocked(packetKey(p.packet).Tuple())
		if entry != nil {
			candidate := entry.coverage.root()
			if candidate != nil && (candidate.key == "" || candidate.key == connection.Key) {
				target = candidate
			}
			if target == nil {
				target = &transportCoverage{}
			}
			entry.coverage = target
		} else {
			target = &transportCoverage{}
		}
	}
	if !target.lost || p.packet.Timestamp.Before(target.packet.Timestamp) {
		target.packet, target.at, target.reason = p.packet, p.at, source.reason
	}
	target.lost, target.key = true, connection.Key
	if source != target && !source.stopped {
		source.lost, source.scheduled = false, false
	}
	r.admissionMu.Unlock()
	e.flowMu.Unlock()
	e.stopDecodeCoverage(target, connection)
}

// Only the resolver worker calls this. It never invokes HandlePacket with the
// dropped packet, fails a stream, evaluates policy or changes a cached verdict.
func (e *Engine) stopDecodeCoverage(marker *transportCoverage, connection *flow.Connection) {
	r := e.transport
	e.flowMu.Lock()
	r.admissionMu.Lock()
	c := marker.root()
	clean := !c.stopped || c.dirty
	if !clean && c.reported {
		r.admissionMu.Unlock()
		e.flowMu.Unlock()
		return
	}
	c.stopped = true
	c.dirty = false
	var states []*flow.State
	// Only the two connection tuples can own these streams. Do not scan
	// every live flow under flowMu during a burst of overflow notices.
	key := packetKey(c.packet)
	if connection == nil {
		if st := e.tupleStateLocked(key.Tuple()); st != nil {
			connection = st.Connection.Load()
		}
	}
	for _, key := range []flow.Key{key, connection.Peer(key)} {
		if st := e.tupleStateLocked(key.Tuple()); st != nil && e.transportCoverage[st].root() == c {
			states = append(states, st)
		}
	}
	report := !c.reported
	c.reported = true
	pkt, reason := c.packet, c.reason
	r.admissionMu.Unlock()
	if live := e.observation; clean && live != nil && connection != nil {
		live.observer.Stop(identify.Key(connection.Key))
		live.syncMetrics()
	}
	e.flowMu.Unlock()
	if clean {
		for _, st := range states {
			e.dpiMgr.DiscardFlow(st)
		}
	}
	if t := e.iec; clean && t != nil && len(states) != 0 && isIECPort(pkt) {
		t.mu.Lock()
		src, srcOK := addrPort(pkt.SrcIP, pkt.SrcPort)
		dst, dstOK := addrPort(pkt.DstIP, pkt.DstPort)
		if srcOK && dstOK {
			if s, _ := t.lookupLocked(src, dst); s != nil {
				t.stopParseLocked(s)
			}
		}
		t.mu.Unlock()
	}
	if report {
		key, proto := transportOverflowIdentity(pkt, connection)
		e.eventStore.Append(events.Event{Kind: eventfields.KindCoverageLoss, Timestamp: pkt.Timestamp,
			FlowID: key.Hash(), Proto: proto, Transport: pkt.Transport, TransportConnectionID: connection.PublicID(),
			SrcIP: pkt.SrcIP.String(), DstIP: pkt.DstIP.String(), SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
			Attributes: map[string]any{eventfields.KeyCoverageIncomplete: true, eventfields.KeyReason: reason}})
		metrics.DPICoverageLosses.Inc()
	}
}

func (e *Engine) decodingStopped(st *flow.State) bool {
	if e.transport == nil {
		return false
	}
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	e.transport.admissionMu.Lock()
	defer e.transport.admissionMu.Unlock()
	c := e.transportCoverage[st].root()
	return c != nil && c.stopped
}

// The IEC table retains legacy states across passive incarnation retirement.
// Reset only passive coverage at that existing boundary, never table lifecycle.
// Caller holds flowMu.
func (e *Engine) retireDecodeCoverageLocked(st *flow.State, incoming *flow.Connection) {
	if e.transport == nil {
		return
	}
	c := st.Connection.Load()
	if c == nil {
		return
	}
	r := e.transport
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	generation := c.Evidence
	if previous := e.transportCoverage[st].root(); previous != nil && previous.generation != nil {
		generation = previous.generation
	}
	if incoming != nil && incoming.Evidence != nil {
		generation = incoming.Evidence
	}
	marker := &transportCoverage{generation: generation}
	if e.transportCoverage == nil {
		e.transportCoverage = make(map[*flow.State]*transportCoverage)
	}
	for _, key := range []flow.Key{st.Key, c.Peer(st.Key)} {
		if peer := e.tupleStateLocked(key.Tuple()); peer != nil {
			e.transportCoverage[peer] = marker
		}
		if entry := r.indexed[key.Tuple()]; entry != nil && entry.connection.Key == c.Key {
			entry.coverage = nil
		}
	}
}
