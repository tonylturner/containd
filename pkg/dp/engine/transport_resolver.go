// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	transportQueueLimit = 512
	transportByteLimit  = 4 << 20
	transportAliasLimit = 16384
	transportOrderDelay = 25 * time.Millisecond
	transportMaxWait    = 500 * time.Millisecond
)

type transportPacket struct {
	packet  capture.Packet
	at      time.Time
	history *transportAdmission
	loss    *transportCoverage
}

// An admission slot outlives its placeholder-to-root handoff. Queued packets
// retain this token even if a newer SYN replaces the tuple's current slot.
type transportAdmission struct {
	connection *flow.Connection
	synSeq     uint32
	hasSYN     bool
	settled    bool // terminal discovery with no port-selected decoder
	queued     int  // includes the in-flight worker packet; under admissionMu
	coverage   *transportCoverage
}

type transportAlias struct {
	connection *flow.Connection
	expires    time.Time
	version    uint64
	synSeq     uint32
	hasSYN     bool
}

type transportResolver struct {
	admissionMu   sync.Mutex
	closed        bool
	indexed       map[conntrack.Tuple]*transportAdmission // under admissionMu, independent of lookup TTL
	overflowNext  time.Time
	authority     *transportAuthority
	reader        conntrack.IdentityReader
	queue         chan transportPacket
	count         atomic.Int64
	bytes         atomic.Int64
	aliases       map[conntrack.Tuple]*transportAlias // worker-owned, O/R only
	expiry        transportExpiry
	epoch         string
	serial        uint64
	losses        chan transportPacket
	lossFallback  atomic.Bool // unscheduled notices retained in bounded histories
	unindexedLoss uint64      // conservative barrier for already-started unindexed streams
}

func (e *Engine) initTransport(cfg Config) error {
	if cfg.NFQueueGroup != 0 || strings.EqualFold(cfg.Capture.Mode, "nfqueue") || len(cfg.Capture.Interfaces) == 0 {
		return nil
	}
	var reader zoneSetterReader
	if e.applier == nil {
		reader = enforce.NewNftApplier()
	} else {
		reader, _ = e.applier.(zoneSetterReader)
	}
	r, err := newTransportResolver(reader, conntrack.NewIdentityReader())
	if err != nil {
		return err
	}
	e.transport = r
	if e.applier != nil {
		e.applier = &transportApplier{Applier: e.applier, authority: r.authority}
	}
	return nil
}

func newTransportResolver(zones zoneSetterReader, reader conntrack.IdentityReader) (*transportResolver, error) {
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, fmt.Errorf("transport identity epoch: %w", err)
	}
	return &transportResolver{authority: newTransportAuthority(zones), reader: reader,
		queue: make(chan transportPacket, transportQueueLimit), indexed: make(map[conntrack.Tuple]*transportAdmission), aliases: make(map[conntrack.Tuple]*transportAlias),
		losses: make(chan transportPacket, transportQueueLimit),
		epoch:  hex.EncodeToString(epoch[:])}, nil
}

func (r *transportResolver) nextKey() string {
	r.serial++
	return fmt.Sprintf("%s/%d", r.epoch, r.serial)
}

// Admission is nonblocking and never does network I/O. AF_PACKET has no inline
// verdict: pressure loses an observation, not a forwarding decision.
func (r *transportResolver) admit(e *Engine, pkt capture.Packet) capture.Decision {
	if !e.transportEligible(pkt) {
		return e.HandlePacket(pkt)
	}
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	if r.closed {
		r.authority.count("canceled")
		return acceptDecision
	}
	n := int64(len(pkt.Payload))
	if pkt.Timestamp.IsZero() {
		pkt.Timestamp = time.Now().UTC()
	}
	history := r.admitHistoryLocked(pkt)
	if r.count.Add(1) > transportQueueLimit {
		r.count.Add(-1)
		r.noteDecodeLossLocked(pkt, history)
		r.unavailable(e, pkt, "queue_overflow")
		return acceptDecision
	}
	if r.bytes.Add(n) > transportByteLimit {
		r.bytes.Add(-n)
		r.count.Add(-1)
		r.noteDecodeLossLocked(pkt, history)
		r.unavailable(e, pkt, "queue_overflow")
		return acceptDecision
	}
	// Capture decodes payload and IPs into owned allocations before invoking
	// admission. The queue retains those allocations, never the receive buffer.
	select {
	case r.queue <- transportPacket{packet: pkt, at: time.Now(), history: history}:
		if history != nil {
			history.queued++
		} else if e.observation != nil {
			// The worker still observes this packet. Missing loss-index
			// coverage is not an observer admission refusal.
			metrics.IdentificationTransportLosses.WithLabelValues("index_capacity").Inc()
		}
	default:
		r.bytes.Add(-n)
		r.count.Add(-1)
		r.noteDecodeLossLocked(pkt, history)
		r.unavailable(e, pkt, "queue_overflow")
	}
	return acceptDecision
}

func (r *transportResolver) unavailable(e *Engine, pkt capture.Packet, status string) {
	r.authority.count(status)
	if e.observation != nil {
		// Packet loss is intentionally per arrival: the incarnation may
		// already be admitted, or be admitted by a later packet. Only
		// Observer.Open can refuse an entire identification incarnation.
		metrics.IdentificationTransportLosses.WithLabelValues("queue_capacity").Inc()
	}
	now := time.Now()
	if entry := r.indexed[packetKey(pkt).Tuple()]; entry != nil {
		entry.connection.LoseCorrelation(now, anomaly.ModbusPairingTimeout)
	}
	if now.Before(r.overflowNext) {
		return
	}
	r.overflowNext = now.Add(time.Second)
	var c *flow.Connection
	if entry := r.indexed[packetKey(pkt).Tuple()]; entry != nil {
		c = entry.connection
	}
	key, proto := transportOverflowIdentity(pkt, c)
	e.eventStore.Append(events.Event{Kind: "dpi.correlation.unavailable", Timestamp: now.UTC(),
		FlowID: key.Hash(), Proto: proto, Transport: pkt.Transport, TransportConnectionID: c.PublicID(),
		CorrelationStatus: status,
		SrcIP:             pkt.SrcIP.String(), DstIP: pkt.DstIP.String(), SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
		Attributes: map[string]any{"correlation_status": status}})
}

// One worker owns lookup, alias admission and packet processing. A bounded
// timestamp reorder window lets an earlier request from another interface
// overtake its reply, including requests queued during a blocking GET.
func (r *transportResolver) run(ctx context.Context, e *Engine) {
	defer r.reader.Close()
	authorityCtx, stopAuthority := context.WithCancel(ctx)
	authorityDone := make(chan struct{})
	go func() { defer close(authorityDone); r.authority.run(authorityCtx) }()
	defer func() { stopAuthority(); <-authorityDone }()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	var pending []transportPacket
	sorted := true
	drain := func() {
		for len(pending) < transportQueueLimit {
			select {
			case p := <-r.queue:
				pending = append(pending, p)
				sorted = false
			default:
				goto losses
			}
		}
	losses:
		for len(pending) < 2*transportQueueLimit {
			select {
			case p := <-r.losses:
				pending = append(pending, p)
				sorted = false
			default:
				return
			}
		}
	}
	sortPending := func() {
		r.admissionMu.Lock()
		for i := range pending {
			if pending[i].loss != nil {
				c := pending[i].loss.root()
				if !pending[i].packet.Timestamp.Equal(c.packet.Timestamp) {
					pending[i].packet, pending[i].at = c.packet, c.at
					sorted = false
				}
			}
		}
		r.admissionMu.Unlock()
		if !sorted {
			sort.SliceStable(pending, func(i, j int) bool {
				if pending[i].packet.Timestamp.Equal(pending[j].packet.Timestamp) {
					return pending[i].loss != nil && pending[j].loss == nil
				}
				return pending[i].packet.Timestamp.Before(pending[j].packet.Timestamp)
			})
			sorted = true
		}
	}
	defer func() {
		r.admissionMu.Lock()
		defer r.admissionMu.Unlock()
		r.closed = true
		for {
			select {
			case p := <-r.queue:
				r.releaseAdmissionLocked(p)
				r.authority.count("canceled")
			default:
				goto released
			}
		}
	released:
		for _, p := range pending {
			if p.loss == nil {
				r.releaseAdmissionLocked(p)
			}
			r.authority.count("canceled")
		}
		r.aliases = make(map[conntrack.Tuple]*transportAlias)
		r.expiry = transportExpiry{}
		clear(r.indexed)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-r.queue:
			pending = append(pending, p)
			sorted = false
		case <-tick.C:
		}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			drain()
			fallback := r.decodeLossFallback(e, pending)
			if len(fallback) != 0 {
				pending = append(pending, fallback...)
				sorted = false
			}
			sortPending()
			if len(pending) == 0 || time.Since(pending[0].at) < transportOrderDelay {
				break
			}
			// Resolve before the last drain: a request observed while GET was in
			// progress must be processed before the already-pending response.
			p := pending[0]
			c := r.resolve(ctx, p.packet, time.Since(p.at) > transportMaxWait)
			drain()
			sortPending()
			if pending[0].at != p.at {
				continue
			}
			pending[0] = transportPacket{}
			pending = pending[1:]
			if ctx.Err() == nil {
				if p.loss != nil {
					e.consumeDecodeLoss(p, c)
				} else {
					e.handleTransportPacket(p.packet, c, p.history)
				}
			}
			if p.loss == nil {
				r.releaseAdmission(p)
			}
		}
	}
}

func (r *transportResolver) unresolved(status string) *flow.Connection {
	r.authority.count(status)
	return &flow.Connection{Key: r.nextKey(), Status: status}
}

func (r *transportResolver) unresolvedAlias(old *transportAlias, status string) *flow.Connection {
	c := r.unresolved(status)
	if old != nil && !old.connection.Closed().Load() {
		return adoptTransport(old.connection, c)
	}
	return c
}

func (r *transportResolver) resolve(ctx context.Context, pkt capture.Packet, overdue bool) *flow.Connection {
	version := r.authority.version.Load()
	tuple := packetKey(pkt).Tuple()
	if err := tuple.Validate(); err != nil {
		return r.unresolved("unsupported_tuple")
	}
	now := time.Now()
	old := r.aliases[tuple]
	syn := pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0
	newSYN := syn && old != nil && (!old.hasSYN || old.synSeq != pkt.TCP.Seq)
	history := old
	if newSYN {
		history = nil
	}
	if overdue {
		return r.unresolvedAlias(history, "admission_timeout")
	}
	if version%2 != 0 {
		return r.unresolvedAlias(history, "zone_unverified")
	}
	if !newSYN && old != nil && old.version == version && now.Before(old.expires) && !old.connection.Closed().Load() {
		r.authority.count("cache_hits")
		return old.connection
	}
	r.pruneAliases(now)
	if len(r.aliases)+2 > transportAliasLimit {
		return r.unresolvedAlias(history, "cache_capacity")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	r.authority.count("lookups")
	evidence, err := r.reader.Lookup(lookupCtx, tuple)
	if version != r.authority.version.Load() {
		return r.unresolvedAlias(history, "zone_unverified")
	}
	if err == nil {
		err = evidence.Validate(tuple)
	}
	if err != nil {
		status := "lookup_error"
		switch {
		case errors.Is(err, conntrack.ErrUnsupportedZone):
			status = "unsupported_zone"
		case errors.Is(err, conntrack.ErrNotFound):
			status = "not_found"
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			status = "lookup_timeout"
		}
		c := r.unresolvedAlias(history, status)
		r.storeAlias(tuple, &transportAlias{connection: c, expires: now.Add(100 * time.Millisecond), version: version})
		return c
	}
	// A live alias cannot be silently reassigned to another kernel entry.
	for _, t := range []conntrack.Tuple{evidence.Original, evidence.Reply} {
		if a := r.aliases[t]; a != nil && a != old && now.Before(a.expires) && a.connection.Evidence != nil &&
			!a.connection.Closed().Load() && !sameGeneration(a.connection.Evidence, &evidence) {
			return r.unresolvedAlias(history, "ambiguous")
		}
	}
	var c *flow.Connection
	if !newSYN {
		for _, t := range []conntrack.Tuple{evidence.Original, evidence.Reply} {
			if a := r.aliases[t]; a != nil && !a.connection.Closed().Load() && sameGeneration(a.connection.Evidence, &evidence) {
				c = a.connection
				break
			}
		}
	}
	if c == nil || !c.Verified() {
		key := r.nextKey()
		c = &flow.Connection{ID: flow.TransportConnectionID(key), Key: key, Status: "resolved",
			Evidence: &evidence}
	}
	ttl := time.Second
	if timeout := time.Duration(evidence.TimeoutSeconds) * time.Second; timeout < ttl {
		ttl = timeout
	}
	a := &transportAlias{connection: c, expires: now.Add(ttl), version: version, hasSYN: syn, synSeq: pkt.TCP.Seq}
	if old != nil && !newSYN && old.hasSYN {
		a.hasSYN, a.synSeq = true, old.synSeq
	}
	r.storeAlias(evidence.Original, a)
	r.storeAlias(evidence.Reply, a)
	r.authority.count("resolved")
	return c
}

func packetKey(pkt capture.Packet) flow.Key {
	return flow.Key{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Proto: pkt.Proto}
}

func sameGeneration(a, b *conntrack.Evidence) bool {
	return a != nil && b != nil && a.Original == b.Original && a.Reply == b.Reply &&
		a.ID == b.ID && a.Start == b.Start && a.Zone == b.Zone &&
		a.OriginalZone == b.OriginalZone && a.ReplyZone == b.ReplyZone
}
