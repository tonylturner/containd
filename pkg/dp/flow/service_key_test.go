// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net/netip"
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
