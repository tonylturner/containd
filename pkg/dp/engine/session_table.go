// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// Session transport bounds; diagnostic labels and values remain unchanged.
const (
	sessionMaxHeldPerSession        = 32
	sessionMaxHeldBytes             = 64 << 10
	sessionMaxHeldGlobal            = 256
	sessionPendingTimeout           = time.Second
	sessionStreamMaxBytes           = 64 << 10
	sessionStreamMaxSegments        = 32
	sessionMaxSessions              = 4096
	sessionMaxTombstones            = 4096
	sessionTombstoneTTL             = 10 * time.Minute
	sessionClosedTTL                = time.Minute
	sessionIdleTTL                  = 10 * time.Minute
	sessionResetRetries             = 3
	sessionResetWindow              = time.Second
	sessionMaxReconnectHistory      = 4096
	sessionReconnectWindow          = 10 * time.Minute
	sessionExpireInterval           = 100 * time.Millisecond
	sessionDirClient, sessionDirSrv = 0, 1
)

type sessionKey struct{ client, server netip.AddrPort }

type sessionState uint8

const (
	sessionSynSent sessionState = iota
	sessionEstablished
	sessionClosed
	sessionAborted
)

// trackedSession owns one TCP session incarnation, from its SYN.
type trackedSession struct {
	iecSession     // protocol state; transport identity, ranges and credits live here
	pairing        sessionPairing
	memory         *flow.InspectionMemory
	inspectionLost bool
	id             string
	flow           *flow.State // immutable service key captured at creation; client/server stay in packet space
	client         netip.AddrPort
	server         netip.AddrPort
	state          sessionState
	lastSeen       time.Time
	endedAt        time.Time // closed or aborted
	dirs           [2]*sessionDir
	held           []*heldPacket
	heldBytes      int
	stopParse      bool // monitor envelope: parsing stopped after a stream error
	reset          *connReset
	next           *trackedSession // new incarnation whose handshake is pending
}

// sessionDir is one direction of a session (client→server or server→client).
type sessionDir struct {
	frameLease *limits.Lease
	hasISN     bool
	isn        uint32
	seq        flow.SeqSpace
	bytes      *flow.ByteStream
	frames     []sessionFrame // decided frames still retained, in order
	framedEnd  int64          // end of the last framed unit
	forwarded  int64          // end of the bytes forwarded to the peer
	finFwd     bool           // a FIN was forwarded
	fin        bool
}

type sessionFrame struct {
	start, end int64
	covered    bool
	nonAdmit   bool
}

type heldPacket struct {
	tok   capture.Token
	mark  uint32
	dir   int
	off   int64
	end   int64
	fin   bool // the packet carries a FIN
	since time.Time
}

// sessionTable owns the tracked TCP sessions of one engine configuration. mu is the
// session lock: it is never held across verdict submission or I/O.
type sessionTable struct {
	iecAdapter  // the only protocol binding; no separate tracker or lock
	ledger      *limits.Ledger
	resources   limits.Resources
	settlements map[capture.Token]*heldCredit
	detached    bool
	mu          sync.Mutex
	zones       *zoneCache // the engine's
	now         func() time.Time
	dpi         *dpi.Manager
	injector    session.Injector
	health      *iecHealth
	settler     func() capture.Settler
	jobs        *worker
	emit        func([]iecTelemetry)
	markAbort   func(sessionID string)
	onError     func(error)
	newID       func() string
	ctDelete    func(context.Context, conntrack.DeleteRequest) error // after the resets

	// pickups are generic inline flow resets (closeDeniedTCP),
	// which share this table's injector, worker and health.
	pickups *pickupResets

	// pressureOffline affects diagnostics only; retained tuples remain unchanged.
	pressureOffline bool

	snap         *rules.Snapshot
	sessions     map[sessionKey]*trackedSession
	tombstones   int
	heldTotal    int
	pairingTotal int
	held         map[capture.Token]*trackedSession
	aborts       map[capture.Token]*abortTxn
	reconnect    map[string]time.Time // client IP + server → aborted at
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

// rememberReconnectLocked retains observational abort history. Refreshing a
// pair does not consume another slot; new pairs displace the oldest abort.
func (t *sessionTable) rememberReconnectLocked(client, server netip.AddrPort, now time.Time) {
	key := pairKey(client, server)
	if _, exists := t.reconnect[key]; !exists && len(t.reconnect) >= sessionMaxReconnectHistory {
		var oldest string
		var at time.Time
		for k, aborted := range t.reconnect {
			if oldest == "" || aborted.Before(at) || aborted.Equal(at) && k < oldest {
				oldest, at = k, aborted
			}
		}
		delete(t.reconnect, oldest)
		t.ledger.Record(limits.TableIECReconnect, limits.ReasonEvicted, limits.ModeObserve)
	}
	t.reconnect[key] = now
}

// sessionCtx is the opener-oriented evaluation context of a session.
func (t *sessionTable) sessionCtx(client, server netip.AddrPort) rules.EvalContext {
	return iecSessionContext(t.snap, client, server, t.zones.resolve)
}

// stateContext uses the same service authority as generic ICS policy.
func (t *sessionTable) stateContext(state *flow.State) rules.EvalContext {
	return statePolicyContext(t.snap, state, t.zones)
}

func retainedSessionState(state *flow.State) *flow.State {
	retained := &flow.State{Key: state.ServiceKey()}
	retained.Connection.Store(state.Connection.Load())
	if evidence := state.InlinePolicy.Load(); evidence != nil {
		copy := *evidence
		retained.InlinePolicy.Store(&copy)
	}
	return retained
}

func (t *sessionTable) sessionContext(s *trackedSession) rules.EvalContext {
	if s.flow != nil {
		return t.stateContext(s.flow)
	}
	return t.sessionCtx(s.client, s.server)
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

// lookupLocked finds the session of a packet and the packet's direction.
func (t *sessionTable) lookupLocked(src, dst netip.AddrPort) (*trackedSession, int) {
	if s := t.sessions[sessionKey{client: src, server: dst}]; s != nil {
		return s, sessionDirClient
	}
	if s := t.sessions[sessionKey{client: dst, server: src}]; s != nil {
		return s, sessionDirSrv
	}
	return nil, 0
}

// setPolicy installs the snapshot's protocol policy. Live sessions whose
// envelope or mode changed are aborted; sessions of an
// unchanged envelope continue.
func (t *sessionTable) setPolicy(snap *rules.Snapshot) {
	t.apply(t.installPolicy(snap, false))
}

// installPolicy collects work without submitting verdicts. An nft replacement
// invalidates every held partial frame even when the effective policy is equal.
func (t *sessionTable) installPolicy(snap *rules.Snapshot, abortPartial bool) sessionActions {
	var acts sessionActions
	t.mu.Lock()
	t.snap = snap
	active, hasICS := t.iecAdapter.installLocked(snap)
	now := t.now()
	for key, s := range t.sessions {
		if s.state != sessionSynSent && s.state != sessionEstablished {
			continue
		}
		ctx := t.sessionContext(s)
		matched, mode := t.envelopeLocked(ctx)
		switch {
		case abortPartial && s.mode == "enforce" && s.partial():
			acts.merge(t.abortLocked(s, abortPolicy, "", nil, now))
		case matched && mode == s.mode:
			s.ctx = ctx
		case s.mode == "enforce" || mode == "enforce":
			acts.merge(t.abortLocked(s, abortPolicy, "", nil, now))
		default:
			// A monitor session left every envelope: stop tracking it.
			t.dpi.EndStream(s.id)
			acts.merge(t.deleteLocked(key, s))
		}
	}
	t.mu.Unlock()
	if t.health != nil {
		t.health.clear(faultEnvelope)
		t.health.setICS(hasICS)
		t.health.setActive(active)
	}
	return acts
}

func (s *trackedSession) partial() bool {
	if len(s.held) != 0 {
		return true
	}
	for _, dir := range s.dirs {
		if dir != nil && dir.bytes != nil && dir.bytes.Next() > dir.framedEnd {
			return true
		}
	}
	return false
}

// expire runs the timers: pending holds, tombstones, closed and idle
// sessions. It runs without new packets.
func (t *sessionTable) expire() {
	var acts sessionActions
	t.mu.Lock()
	now := t.now()
	for key, s := range t.sessions {
		switch s.state {
		case sessionAborted:
			if now.Sub(s.endedAt) > sessionTombstoneTTL {
				acts.merge(t.deleteLocked(key, s))
			}
		case sessionClosed:
			if now.Sub(s.endedAt) > sessionClosedTTL {
				acts.merge(t.deleteLocked(key, s))
			}
		default:
			if s.pairing != nil {
				s.pairing.expire(now)
			}
			t.iecAdapter.expireLocked(t, s, &acts, now)
			if len(s.held) > 0 && now.Sub(s.held[0].since) > sessionPendingTimeout {
				acts.merge(t.abortLocked(s, abortTimeout, "", nil, now))
			} else if now.Sub(s.lastSeen) > sessionIdleTTL {
				t.dpi.EndStream(s.id)
				acts.merge(t.deleteLocked(key, s))
			}
		}
	}
	for k, at := range t.reconnect {
		if now.Sub(at) > sessionReconnectWindow {
			delete(t.reconnect, k)
		}
	}
	t.mu.Unlock()
	t.apply(acts)
}

func (t *sessionTable) deleteLocked(key sessionKey, s *trackedSession) sessionActions {
	acts := t.iecAdapter.endLocked(t, s)
	acts.retired = true
	if s.state == sessionAborted {
		t.tombstones--
	}
	delete(t.sessions, key)
	s.releaseInspection()
	return acts
}

// evictTombstoneLocked removes the oldest tombstone when the bound is hit.
// A packet of the evicted session is then "not observed from SYN".
func (t *sessionTable) evictTombstoneLocked() {
	if t.tombstones <= sessionMaxTombstones {
		return
	}
	var oldKey sessionKey
	var old *trackedSession
	for k, s := range t.sessions {
		if s.state == sessionAborted && (old == nil || s.endedAt.Before(old.endedAt)) {
			oldKey, old = k, s
		}
	}
	if old != nil {
		t.deleteLocked(oldKey, old)
	}
}

// run drives the timers until stop is closed.
func (t *sessionTable) run(stop <-chan struct{}) {
	defer func() {
		t.iecAdapter.stopDelivery(t)
		t.mu.Lock()
		t.pressureOffline = true
		t.mu.Unlock()
	}()
	ticker := time.NewTicker(sessionExpireInterval)
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
