// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"net/netip"
	"testing"
	"time"
)

func TestSessionIndexesBoundedAndRetired(t *testing.T) {
	p := runtimePairCases()[0]
	e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce",
		Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
	inlineHandshake(t, e, 41000, p.port)
	table := e.sessions
	table.mu.Lock()
	defer table.mu.Unlock()
	s := runtimePairOwner(t, e, p)
	key := sessionKey{s.client, s.server}
	c := &flow.Connection{Key: "indexed-session"}
	s.flow.Connection.Store(c)
	table.publishSessionLocked(key, s)
	state := &flow.State{Key: s.flow.Key}
	state.Connection.Store(c)
	if got, _ := table.lookupPacketLocked(netip.AddrPortFrom(s.client.Addr(), 42000), s.server, state); got != s {
		t.Fatal("connection key failed to join a different wire tuple")
	}
	for i := uint32(1); i <= 3*pairSessionCap; i++ {
		table.rememberTokenLocked(s, capture.NewToken(999, i), capture.VerdictRepeat)
	}
	if len(table.tokenOwners) != pairSessionCap || len(table.byConnection) != 1 {
		t.Fatalf("index bounds: tokens=%d connections=%d", len(table.tokenOwners), len(table.byConnection))
	}
	if owner, _ := table.tokenOwnerLocked(capture.NewToken(999, 1)); owner != nil {
		t.Fatal("overwritten token retained its owner")
	}
	latest := capture.NewToken(999, 3*pairSessionCap)
	next := s.tokenNext
	table.rememberTokenLocked(s, latest, capture.VerdictDrop)
	if owner, verdict := table.tokenOwnerLocked(latest); owner != s || verdict != capture.VerdictDrop || s.tokenNext != next {
		t.Fatal("duplicate token did not update its expected verdict in place")
	}
	table.deleteLocked(key, &trackedSession{client: s.client, server: s.server})
	if table.sessions[key] != s {
		t.Fatal("stale incarnation deleted the current owner")
	}
	table.deleteLocked(key, s)
	if len(table.tokenOwners) != 0 || len(table.byConnection) != 0 {
		t.Fatal("retired owner retained lookup indexes")
	}
}

func TestTokenOwnerLookupCost(t *testing.T) {
	p := runtimePairCases()[0]
	e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
	const sessions = 4000
	for i := 0; i < sessions; i++ {
		inlineHandshake(t, e, uint16(20000+i), p.port)
	}
	e.sessions.mu.Lock()
	n := len(e.sessions.sessions)
	e.sessions.mu.Unlock()
	const calls = 2000
	start := time.Now()
	for i := 0; i < calls; i++ {
		e.hooks.onVerdict(capture.NewToken(1, uint32(0x7f000000+i)), capture.VerdictDrop, nil)
	}
	per := time.Since(start) / calls
	// Unknown-tuple lookup with a connection key walks the same table.
	t.Logf("sessions=%d: onVerdict of an unattributed token costs %v under the table lock", n, per)
	if per > 50*time.Microsecond {
		t.Errorf("per-completion scan %v with %d sessions", per, n)
	}
}
