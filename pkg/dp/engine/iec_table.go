// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// IEC104 session bounds.
const (
	iec104Port              = 2404
	iecMaxHeldPerSession    = 32
	iecMaxHeldBytes         = 64 << 10
	iecMaxHeldGlobal        = 256
	iecPendingTimeout       = time.Second
	iecStreamMaxBytes       = 64 << 10
	iecStreamMaxSegments    = 32
	iecMaxSessions          = 4096
	iecMaxTombstones        = 4096
	iecTombstoneTTL         = 10 * time.Minute
	iecClosedTTL            = time.Minute
	iecIdleTTL              = 10 * time.Minute
	iecResetRetries         = 3
	iecResetWindow          = time.Second
	iecReconnectWindow      = 10 * time.Minute
	iecExpireInterval       = 100 * time.Millisecond
	iecProtocol             = "iec104"
	iecDirClient, iecDirSrv = 0, 1
)

// iecPolicy is the IEC104 part of the rule evaluator.
// *rules.Evaluator implements it.
type iecPolicy interface {
	IEC104Envelope(ctx rules.EvalContext, globalMode string) (bool, string)
	EvaluateIEC104(ctx rules.EvalContext) (rules.Action, *rules.Entry)
}

func newRulesPolicy(snap *rules.Snapshot) iecPolicy { return rules.NewEvaluator(snap) }

type iecKey struct{ client, server netip.AddrPort }

type iecState uint8

const (
	iecSynSent iecState = iota
	iecEstablished
	iecClosed
	iecAborted
)

// iecSession is one IEC104 session incarnation, from its SYN.
type iecSession struct {
	id         string
	client     netip.AddrPort
	server     netip.AddrPort
	ctx        rules.EvalContext // opener-oriented session tuple
	mode       string            // envelope mode, fixed at the SYN
	state      iecState
	lastSeen   time.Time
	endedAt    time.Time // closed or aborted
	dirs       [2]*iecDir
	held       []*heldPacket
	heldBytes  int
	stopParse  bool // learn envelope: parsing stopped after a stream error
	reconnects bool // first STARTDT con counts as a reconnect
	reset      *iecReset
	next       *iecSession         // new incarnation whose handshake is pending
	apci       *anomaly.IEC104APCI // observational state, owned by this incarnation
	inventory  *iecInventoryLedger
}

// iecDir is one direction of a session (client→server or server→client).
type iecDir struct {
	hasISN    bool
	isn       uint32
	seq       flow.SeqSpace
	bytes     *flow.ByteStream
	frames    []iecFrame // decided frames still retained, in order
	framedEnd int64      // end of the last framed APDU
	forwarded int64      // end of the bytes forwarded to the peer
	finFwd    bool       // a FIN was forwarded
	fin       bool
}

type iecFrame struct{ start, end int64 }

type heldPacket struct {
	tok   capture.Token
	dir   int
	off   int64
	end   int64
	fin   bool // the packet carries a FIN
	since time.Time
}

func newIECDir(isn uint32) *iecDir {
	return &iecDir{
		hasISN: true,
		isn:    isn,
		seq:    flow.NewSeqSpace(isn),
		bytes:  flow.NewByteStream(iecStreamMaxBytes, iecStreamMaxSegments),
	}
}

// iecTable holds the IEC104 sessions of one engine configuration. mu is the
// session lock: it is never held across verdict submission or I/O.
type iecTable struct {
	mu         sync.Mutex
	now        func() time.Time
	dpi        *dpi.Manager
	injector   session.Injector
	health     *iecHealth
	settler    func() capture.Settler
	jobs       *worker
	emit       func([]events.Event)
	markAbort  func(sessionID string)
	onError    func(error)
	newPolicy  func(*rules.Snapshot) iecPolicy
	safeRead   func(map[string]any) bool
	newID      func() string
	ctDelete   func(context.Context, conntrack.DeleteRequest) error // after the resets
	globalMode string

	inventory       iecInventoryInput
	inventoryTokens map[capture.Token]*iecSession

	// pressureOffline affects diagnostics only; retained tuples remain unchanged.
	pressureOffline bool

	policy     iecPolicy
	snap       *rules.Snapshot
	hasIEC     bool
	sessions   map[iecKey]*iecSession
	tombstones int
	heldTotal  int
	held       map[capture.Token]*iecSession
	aborts     map[capture.Token]*abortTxn
	reconnect  map[string]time.Time // client IP + server → aborted at
}

func newIECTable(globalMode string) *iecTable {
	return &iecTable{
		now:        time.Now,
		newPolicy:  newRulesPolicy,
		safeRead:   iec104.SafeRead,
		newID:      nextLiveSessionID,
		ctDelete:   conntrack.Delete,
		globalMode: globalMode,
		sessions:   make(map[iecKey]*iecSession),
		held:       make(map[capture.Token]*iecSession),
		aborts:     make(map[capture.Token]*abortTxn),
		reconnect:  make(map[string]time.Time),

		inventoryTokens: make(map[capture.Token]*iecSession),
	}
}

func addrPort(ip net.IP, port uint16) (netip.AddrPort, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return netip.AddrPort{}, false
	}
	a, _ := netip.AddrFromSlice(v4)
	return netip.AddrPortFrom(a, port), true
}

func pairKey(client, server netip.AddrPort) string {
	return client.Addr().String() + ">" + server.String()
}

// sessionCtx is the opener-oriented evaluation context of a session.
func (t *iecTable) sessionCtx(client, server netip.AddrPort) rules.EvalContext {
	return iecSessionContext(t.snap, client, server, resolveZonesForFlow)
}

func iecSessionContext(snap *rules.Snapshot, client, server netip.AddrPort, resolve zoneResolver) rules.EvalContext {
	ctx := rules.EvalContext{
		SrcIP: net.IP(client.Addr().AsSlice()),
		DstIP: net.IP(server.Addr().AsSlice()),
		Proto: "tcp",
		Port:  strconv.Itoa(int(server.Port())),
	}
	ctx.SrcZone, ctx.DstZone = resolve(snap, ctx.SrcIP, ctx.DstIP)
	ctx.Identities = snap.IdentitiesOf(ctx.SrcIP)
	return ctx
}

// envelopeLocked evaluates the envelope of a session tuple.
func (t *iecTable) envelopeLocked(ctx rules.EvalContext) (bool, string) {
	if t.policy == nil || !t.hasIEC {
		return false, ""
	}
	return t.policy.IEC104Envelope(ctx, t.globalMode)
}

// lookupLocked finds the session of a packet and the packet's direction.
func (t *iecTable) lookupLocked(src, dst netip.AddrPort) (*iecSession, int) {
	if s := t.sessions[iecKey{client: src, server: dst}]; s != nil {
		return s, iecDirClient
	}
	if s := t.sessions[iecKey{client: dst, server: src}]; s != nil {
		return s, iecDirSrv
	}
	return nil, 0
}

// hasEnforceIEC reports whether a snapshot loads an enforce envelope.
func hasEnforceIEC(snap *rules.Snapshot, globalMode string) (hasIEC, enforce bool) {
	if snap == nil {
		return false, false
	}
	for _, entry := range snap.Firewall {
		if !strings.EqualFold(entry.ICS.Protocol, iecProtocol) {
			continue
		}
		hasIEC = true
		if rules.EffectiveMode(entry.ICS.Mode, globalMode) == "enforce" {
			enforce = true
		}
	}
	return hasIEC, enforce
}

// setPolicy installs the snapshot's IEC104 policy. Live sessions whose
// envelope or mode changed are aborted; sessions of an
// unchanged envelope continue.
func (t *iecTable) setPolicy(snap *rules.Snapshot) {
	hasIEC, active := hasEnforceIEC(snap, t.globalMode)
	var acts iecActions
	t.mu.Lock()
	t.snap, t.hasIEC = snap, hasIEC
	t.policy = t.newPolicy(snap)
	now := t.now()
	for key, s := range t.sessions {
		if s.state != iecSynSent && s.state != iecEstablished {
			continue
		}
		ctx := t.sessionCtx(s.client, s.server)
		matched, mode := t.envelopeLocked(ctx)
		switch {
		case matched && mode == s.mode:
			s.ctx = ctx
		case s.mode == "enforce" || mode == "enforce":
			acts.merge(t.abortLocked(s, abortPolicy, "", nil, now))
		default:
			// A learn session left every envelope: stop tracking it.
			t.dpi.EndStream(s.id)
			acts.merge(t.deleteLocked(key, s))
		}
	}
	t.mu.Unlock()
	if t.health != nil {
		t.health.clear(faultEnvelope)
		t.health.setActive(active)
	}
	t.apply(acts)
}

// expire runs the timers: pending holds, tombstones, closed and idle
// sessions. It runs without new packets.
func (t *iecTable) expire() {
	var acts iecActions
	t.mu.Lock()
	now := t.now()
	for key, s := range t.sessions {
		switch s.state {
		case iecAborted:
			if now.Sub(s.endedAt) > iecTombstoneTTL {
				acts.merge(t.deleteLocked(key, s))
			}
		case iecClosed:
			if now.Sub(s.endedAt) > iecClosedTTL {
				acts.merge(t.deleteLocked(key, s))
			}
		default:
			s.expireAPCILocked(&acts, now)
			t.expireInventoryLocked(s, &acts, now)
			if len(s.held) > 0 && now.Sub(s.held[0].since) > iecPendingTimeout {
				acts.merge(t.abortLocked(s, abortTimeout, "", nil, now))
			} else if now.Sub(s.lastSeen) > iecIdleTTL {
				t.dpi.EndStream(s.id)
				acts.merge(t.deleteLocked(key, s))
			}
		}
	}
	for k, at := range t.reconnect {
		if now.Sub(at) > iecReconnectWindow {
			delete(t.reconnect, k)
		}
	}
	t.mu.Unlock()
	t.apply(acts)
}

func (t *iecTable) deleteLocked(key iecKey, s *iecSession) iecActions {
	acts := t.endInventoryLocked(s)
	s.apci = nil
	if s.state == iecAborted {
		t.tombstones--
	}
	delete(t.sessions, key)
	return acts
}

// evictTombstoneLocked removes the oldest tombstone when the bound is hit.
// A packet of the evicted session is then "not observed from SYN".
func (t *iecTable) evictTombstoneLocked() {
	if t.tombstones <= iecMaxTombstones {
		return
	}
	var oldKey iecKey
	var old *iecSession
	for k, s := range t.sessions {
		if s.state == iecAborted && (old == nil || s.endedAt.Before(old.endedAt)) {
			oldKey, old = k, s
		}
	}
	if old != nil {
		t.deleteLocked(oldKey, old)
	}
}

// run drives the timers until stop is closed.
func (t *iecTable) run(stop <-chan struct{}) {
	defer func() {
		t.stopInventory()
		t.mu.Lock()
		t.pressureOffline = true
		t.mu.Unlock()
	}()
	ticker := time.NewTicker(iecExpireInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.expire()
		}
	}
}
