// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

func TestServiceKeyNAT(t *testing.T) {
	evidence := conntrack.Evidence{
		Original: conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort("192.0.2.1:41000"), Destination: netip.MustParseAddrPort("203.0.113.1:1502")},
		Reply:    conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort("10.0.0.1:502"), Destination: netip.MustParseAddrPort("10.0.0.2:52000")},
	}
	for _, wire := range []Key{
		TupleKey(evidence.Original, DirForward),
		TupleKey(evidence.Reply, DirReverse).Reversed(),
		TupleKey(evidence.Reply, DirReverse),
		TupleKey(evidence.Original, DirForward).Reversed(),
	} {
		t.Run(wire.Hash(), func(t *testing.T) {
			state := NewState(wire, time.Now())
			id := state.ID()
			for _, status := range []string{"resolved", "wire", "not_found", "zone_unverified", "ambiguous", "lookup_timeout"} {
				state.Connection.Store(&Connection{Status: status, Evidence: &evidence})
				key := state.ServiceKey()
				if status != "resolved" {
					if key.MapKey() != wire.MapKey() {
						t.Fatalf("%s invented service coordinates: %+v", status, key)
					}
					continue
				}
				client, server := key.Tuple().Source, key.Tuple().Destination
				if key.Dir == DirReverse {
					client, server = server, client
				}
				if client != evidence.Original.Source || server != evidence.Reply.Source {
					t.Fatalf("service tuple = %+v", key.Tuple())
				}
				src, dst, verified := state.LogicalIPs()
				if !verified || src != key.SrcIP.String() || dst != key.DstIP.String() {
					t.Fatal("logical IP consumers disagree with service authority")
				}
			}
			if state.ID() != id || state.Key.MapKey() != wire.MapKey() {
				t.Fatal("service lookup changed wire identity")
			}
		})
	}
	// The exact kernel reply tuple overrides a contradictory wire direction.
	state := NewState(TupleKey(evidence.Reply, DirForward), time.Now())
	state.Connection.Store(&Connection{Status: "resolved", Evidence: &evidence})
	if state.ServiceKey().Dir != DirReverse {
		t.Fatal("ignored kernel reply direction")
	}
}

func TestServiceKeyNonNAT(t *testing.T) {
	key := Key{SrcPort: 41000, DstPort: 502, Proto: 6}
	key.SrcIP = netip.MustParseAddr("192.0.2.1").AsSlice()
	key.DstIP = netip.MustParseAddr("192.0.2.2").AsSlice()
	state := NewState(key, time.Now())
	if state.ServiceKey().MapKey() != key.MapKey() {
		t.Fatal("offline key changed")
	}
	state.Connection.Store(&Connection{Status: "resolved", Evidence: &conntrack.Evidence{Original: key.Tuple(), Reply: key.Reversed().Tuple()}})
	if state.ServiceKey().MapKey() != key.MapKey() {
		t.Fatal("non-NAT key changed")
	}
}

func TestServiceKeyCacheInvalidation(t *testing.T) {
	wire := Key{SrcIP: netip.MustParseAddr("192.0.2.1").AsSlice(), DstIP: netip.MustParseAddr("203.0.113.1").AsSlice(),
		SrcPort: 41000, DstPort: 1502, Proto: 6}
	evidence := conntrack.Evidence{Original: wire.Tuple(), Reply: wire.Reversed().Tuple()}
	evidence.Reply.Source = netip.MustParseAddrPort("10.0.0.1:502")
	first := &Connection{Status: "resolved", Evidence: &evidence}
	state := NewState(wire, time.Now())
	state.Connection.Store(first)
	state.ServiceKey()
	cached := state.Connection.pointer.service.Load()
	if allocs := testing.AllocsPerRun(100, func() { state.ServiceKey() }); allocs != 0 {
		t.Fatalf("cached service lookup allocated %g times", allocs)
	}
	if state.Connection.pointer.service.Load() != cached {
		t.Fatal("unchanged inputs replaced cache")
	}

	// State snapshots share atomic slots, not mutable cached keys. A changed
	// snapshot key (including in-place IP edits) must invalidate the lookup.
	snapshot := *state
	snapshot.Key = snapshot.Key.Reversed()
	if key := snapshot.ServiceKey(); key.Dir != DirReverse || key.SrcPort != 502 || key.DstPort != 41000 {
		t.Fatalf("snapshot reused forward cache: %+v", key)
	}
	if key := state.ServiceKey(); key.Dir != DirForward || key.DstPort != 502 {
		t.Fatal("snapshot polluted original lookup")
	}
	state.Key.SrcIP[3]++
	state.ServiceKey()
	if state.Connection.pointer.service.Load().wire != state.Key.MapKey() {
		t.Fatal("IP slice edit did not invalidate cache")
	}
	state.Key.Proto = 17
	state.Key.DstPort++
	if key := state.ServiceKey(); key.Proto != 17 {
		t.Fatal("key edit returned stale protocol")
	}

	secondEvidence := evidence
	secondEvidence.Reply.Source = netip.MustParseAddrPort("10.0.0.2:20000")
	state.Connection.Store(&Connection{Status: "resolved", Evidence: &secondEvidence})
	if key := state.ServiceKey(); key.DstIP.String() != "10.0.0.2" || key.DstPort != 20000 {
		t.Fatal("connection replacement reused old authority")
	}
	state.Connection.Store(&Connection{Status: "ambiguous", Evidence: &secondEvidence})
	if state.ServiceKey().MapKey() != state.Key.MapKey() {
		t.Fatal("unverified authority reused verified cache")
	}
	state.Connection.Store(nil)
	if state.ServiceKey().MapKey() != state.Key.MapKey() {
		t.Fatal("cleared authority reused cache")
	}
}

func TestServiceKeyConcurrentSnapshots(t *testing.T) {
	wire := Key{SrcIP: netip.MustParseAddr("192.0.2.1").AsSlice(), DstIP: netip.MustParseAddr("203.0.113.1").AsSlice(),
		SrcPort: 41000, DstPort: 1502, Proto: 6}
	evidence := conntrack.Evidence{Original: wire.Tuple(), Reply: wire.Reversed().Tuple()}
	evidence.Reply.Source = netip.MustParseAddrPort("10.0.0.1:502")
	first := &Connection{Status: "resolved", Evidence: &evidence}
	secondEvidence := evidence
	secondEvidence.Reply.Source = netip.MustParseAddrPort("10.0.0.2:20000")
	second := &Connection{Status: "resolved", Evidence: &secondEvidence}
	state := NewState(wire, time.Now())
	state.Connection.Store(first)
	snapshot := *state
	snapshot.Key = wire.Reversed()
	var wg sync.WaitGroup
	for _, reader := range []*State{state, &snapshot} {
		wg.Go(func() {
			for range 1000 {
				key := reader.ServiceKey()
				port := key.DstPort
				if key.Dir == DirReverse {
					port = key.SrcPort
				}
				if port != 502 && port != 20000 {
					t.Errorf("incoherent cache: %+v", key)
					return
				}
			}
		})
	}
	for range 1000 {
		state.Connection.Store(second)
		state.Connection.Store(first)
	}
	wg.Wait()
}
