// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func installRetentionClock(e *Engine, now time.Time) *atomic.Int64 {
	clock := new(atomic.Int64)
	clock.Store(now.UnixNano())
	get := func() time.Time { return time.Unix(0, clock.Load()) }
	e.deniedTCPNow = get
	e.sessions.mu.Lock()
	e.sessions.now = get
	e.sessions.mu.Unlock()
	return clock
}

func retentionPrefix(f *resetFlow, what string, payload []byte) {
	if f.port == 44818 {
		f.accept(what, payload)
	} else {
		f.hold(what, payload)
	}
}

func retainSessionTuple(t *sessionTable, port uint16, now time.Time) *trackedSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	client := netip.AddrPortFrom(netip.MustParseAddr(testClient), port)
	server := netip.MustParseAddrPort(testServer + ":502")
	key := sessionKey{client, server}
	if s := t.sessions[key]; s != nil {
		t.retainDenialLocked(s, now) // a duplicate must not refresh or reorder
		return s
	}
	s := &trackedSession{client: client, server: server}
	t.sessions[key] = s
	t.retainDenialLocked(s, now)
	return s
}

func forceSessionRetentionEviction(tb *testing.T, e *Engine) {
	tb.Helper()
	for port := 1; port <= deniedTCPCapacity; port++ {
		retainSessionTuple(e.sessions, uint16(port), e.sessions.now())
	}
}

func TestSessionDenialRetentionCapacity(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "FIFO", true: "concurrent"}[concurrent], func(t *testing.T) {
			table := newIECTable("enforce", &zoneCache{})
			now := time.Now()
			before := retentionEvictions(t)
			const extra = 512
			if concurrent {
				var wg sync.WaitGroup
				for worker := range 8 {
					wg.Go(func() {
						for i := range (deniedTCPCapacity + extra) / 8 {
							port := worker*((deniedTCPCapacity+extra)/8) + i + 1
							retainSessionTuple(table, uint16(port), now)
							table.mu.Lock()
							size, count := table.denials.Len(), table.tombstones
							table.mu.Unlock()
							if size > deniedTCPCapacity || count != size {
								t.Errorf("capacity violated: FIFO=%d count=%d", size, count)
							}
						}
					})
				}
				wg.Wait()
			} else {
				first := retainSessionTuple(table, 1, now)
				for i := 2; i <= deniedTCPCapacity+extra; i++ {
					retainSessionTuple(table, uint16(i), now)
					if i == deniedTCPCapacity {
						retainSessionTuple(table, 1, now.Add(9*time.Second))
						if first.endedAt != now || table.denials.Front().Value != first {
							t.Fatal("duplicate refreshed or reordered denial")
						}
					}
					if table.denials.Len() > deniedTCPCapacity || table.tombstones != table.denials.Len() {
						t.Fatalf("capacity violated at %d", i)
					}
				}
				for i := 1; i <= deniedTCPCapacity+extra; i++ {
					s, _ := table.lookupLocked(netip.AddrPortFrom(netip.MustParseAddr(testClient), uint16(i)), netip.MustParseAddrPort(testServer+":502"))
					if (s == nil) != (i <= extra) {
						t.Fatalf("oldest-first eviction wrong for tuple %d", i)
					}
				}
			}
			if table.denials.Len() != deniedTCPCapacity || len(table.sessions) != deniedTCPCapacity {
				t.Fatalf("final size FIFO=%d map=%d", table.denials.Len(), len(table.sessions))
			}
			if got := retentionEvictions(t) - before; got != extra {
				t.Fatalf("evictions=%v, want %d", got, extra)
			}
		})
	}
}
