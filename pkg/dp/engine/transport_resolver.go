// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
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
}

// An admission slot outlives its placeholder-to-root handoff. Queued packets
// retain this token even if a newer SYN replaces the tuple's current slot.
type transportAdmission struct {
	connection *flow.Connection
	synSeq     uint32
	hasSYN     bool
}

type transportAlias struct {
	connection *flow.Connection
	expires    time.Time
	version    uint64
	synSeq     uint32
	hasSYN     bool
}

type transportResolver struct {
	admissionMu  sync.Mutex
	closed       bool
	indexed      map[conntrack.Tuple]*transportAdmission // under admissionMu, independent of lookup TTL
	overflowNext time.Time
	authority    *transportAuthority
	reader       conntrack.IdentityReader
	queue        chan transportPacket
	count        atomic.Int64
	bytes        atomic.Int64
	aliases      map[conntrack.Tuple]*transportAlias // worker-owned, O/R only
	epoch        string
	serial       uint64
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
		epoch: hex.EncodeToString(epoch[:])}, nil
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
		r.unavailable(e, pkt, "queue_overflow")
		return acceptDecision
	}
	if r.bytes.Add(n) > transportByteLimit {
		r.bytes.Add(-n)
		r.count.Add(-1)
		r.unavailable(e, pkt, "queue_overflow")
		return acceptDecision
	}
	pkt.Payload, pkt.SrcIP, pkt.DstIP = bytes.Clone(pkt.Payload), bytes.Clone(pkt.SrcIP), bytes.Clone(pkt.DstIP)
	select {
	case r.queue <- transportPacket{packet: pkt, at: time.Now(), history: history}:
	default:
		r.bytes.Add(-n)
		r.count.Add(-1)
		r.unavailable(e, pkt, "queue_overflow")
	}
	return acceptDecision
}

func (r *transportResolver) unavailable(e *Engine, pkt capture.Packet, status string) {
	r.authority.count(status)
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
				return
			}
		}
	}
	sortPending := func() {
		if !sorted {
			sort.SliceStable(pending, func(i, j int) bool {
				return pending[i].packet.Timestamp.Before(pending[j].packet.Timestamp)
			})
			sorted = true
		}
	}
	defer func() {
		r.admissionMu.Lock()
		defer r.admissionMu.Unlock()
		r.closed = true
		drain()
		for _, p := range pending {
			r.bytes.Add(-int64(len(p.packet.Payload)))
			r.count.Add(-1)
			r.authority.count("canceled")
		}
		r.aliases = make(map[conntrack.Tuple]*transportAlias)
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
				e.handleTransportPacket(p.packet, c, p.history)
			}
			r.bytes.Add(-int64(len(p.packet.Payload)))
			r.count.Add(-1)
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
	for t, alias := range r.aliases {
		if now.Sub(alias.expires) > 30*time.Second || !alias.connection.Verified() && !now.Before(alias.expires) {
			delete(r.aliases, t)
		}
	}
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
		r.aliases[tuple] = &transportAlias{connection: c, expires: now.Add(100 * time.Millisecond), version: version}
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
	r.aliases[evidence.Original], r.aliases[evidence.Reply] = a, a
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
