// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestIECShadowCountersFollowReconfiguredEngine(t *testing.T) {
	e, err := New(Config{DPIEnabled: true, DPIMode: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	snap := rules.Snapshot{Version: "before", Default: rules.ActionAllow, Firewall: []rules.Entry{
		{ID: "monitor", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}},
	}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	observe := func() {
		t.Helper()
		tab := e.iec
		client := netip.MustParseAddrPort("10.60.60.10:40000")
		server := netip.MustParseAddrPort("10.30.30.30:2404")
		s := &iecSession{id: "reconfigure", client: client, server: server, mode: "monitor", ctx: tab.sessionCtx(client, server)}
		ev := dpi.Event{Proto: "iec104", Kind: "request", Attributes: map[string]any{
			"apci_type": "I", "type_id": uint8(46), "ca": uint16(1), "apdu_id": "message", "direction": "request",
		}}
		tab.mu.Lock()
		j := tab.judgeLocked(s, []dpi.Event{ev, ev}, time.Now())
		tab.mu.Unlock()
		if j.denied {
			t.Fatal("monitor denied delivery")
		}
	}
	check := func(want uint64) {
		t.Helper()
		got := e.ShadowCounters()
		if len(got.Rules) != 1 || got.Rules[0].ShadowMatches != want || got.Rules[0].WouldDeny != want {
			t.Fatalf("shadow counts = %+v, want %d messages", got, want)
		}
	}
	observe()
	check(1)
	fresh, err := New(Config{DPIEnabled: true, DPIMode: "monitor", Events: e.Events()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	check(1) // Rebuilding capture is not a new policy installation.
	observe()
	check(2)
	snap.Version = "after"
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	check(0)
	observe()
	check(1)
	if fresh.ShadowCounters().Available {
		t.Fatal("observations charged the discarded constructor's engine")
	}
}
