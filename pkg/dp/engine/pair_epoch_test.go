// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestPairingEpochLifecycle(t *testing.T) {
	t.Run("publisher", func(t *testing.T) {
		var owner ruleSnapshots
		snap := &rules.Snapshot{Version: "unchanged"}
		owner.Store(snap)
		first := owner.current.Load().epoch
		owner.Install(snap, time.Unix(1, 0))
		shadow := owner.current.Load().shadow
		owner.Update(snap)
		if owner.current.Load().epoch != first+2 || owner.current.Load().shadow != shadow {
			t.Fatal("publication did not advance, or resolver update reset counters")
		}
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() { owner.Update(snap) })
		}
		wg.Wait()
		if owner.current.Load().epoch != first+34 {
			t.Fatal("concurrent publications lost an epoch")
		}
	})
	t.Run("retained-requests", func(t *testing.T) {
		h := newIECHarness(t, "enforce")
		h.handshake()
		table := h.e.sessions
		table.mu.Lock()
		client, _ := addrPort(h.client, h.cport)
		server, _ := addrPort(h.server, iec104Port)
		s, _ := table.lookupLocked(client, server)
		q := iec104.PairShape{Format: "I", TypeID: 46, Cause: 6, CA: 1, Objects: []iec104.Object{{IOA: 1, ValueBits: 1}}}
		ctx := s.ctx
		typ := uint8(46)
		ctx.ICS = &rules.ICSContext{Protocol: iecProtocol, MessageClass: rules.ClassRequest, Direction: "request", IEC104: &rules.IEC104Context{APCIType: "I", TypeID: &typ, CA: &q.CA, Class: "control"}}
		epoch := h.e.ruleSnap.current.Load().epoch
		if why := s.pairing.apply(pairIE(q), dpi.ClientToServer, requestPermit{Epoch: epoch, Contexts: []rules.EvalContext{ctx}}, h.clock); why != pairOK {
			t.Fatal(why)
		}
		book := s.pairing.(*pairLedger[iecPairKey, iec104.PairShape])
		expires := book.grants[0].Expires
		table.mu.Unlock()
		allow := rules.Entry{ID: "request", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: iecProtocol, Mode: "enforce"}}
		h.e.LoadRules(rules.Snapshot{Version: "unchanged", Firewall: []rules.Entry{allow}})
		table.mu.Lock()
		if len(book.grants) != 1 || book.grants[0].Permit.Epoch <= epoch || book.grants[0].Expires != expires {
			t.Fatal("compatible install revoked or extended a grant")
		}
		kept := book.grants[0].Permit.Epoch
		// Time/input changes alone do not invoke reauthorization on the reply path.
		s.ctx.Identities = []string{"changed-without-publication"}
		r := q
		r.Cause = 7
		if _, why := book.inspect(pairIE(r), dpi.ServerToClient, h.clock.Add(time.Second)); why != pairOK {
			t.Fatal(why)
		}
		if book.grants[0].Permit.Epoch != kept {
			t.Fatal("reply reauthorized policy")
		}
		table.mu.Unlock()
		allow.Action = rules.ActionDeny
		h.e.LoadRules(rules.Snapshot{Version: "unchanged", Firewall: []rules.Entry{allow}})
		table.mu.Lock()
		defer table.mu.Unlock()
		if len(book.grants) != 0 {
			t.Fatal("removed request permission retained a grant")
		}
		if _, why := book.inspect(pairIE(r), dpi.ServerToClient, h.clock); why != pairExpired {
			t.Fatal("retired reply", why)
		}
	})
	t.Run("live-install-and-addresses", func(t *testing.T) {
		e, nft := admissionEngine(t)
		metadata := protection.Metadata{BootID: "boot", ApplyID: "first", RunningRevision: "running", Mode: protection.ModeNormal}
		e.BindProtection(metadata)
		current := []netip.Addr{netip.MustParseAddr("203.0.113.1")}
		e.localIPv4 = func(*rules.Snapshot) (map[string][]netip.Addr, error) {
			return map[string][]netip.Addr{"wan0": current}, nil
		}
		snap := rules.Snapshot{Version: "unchanged", ZoneIfaces: map[string][]string{"wan": {"wan0"}}}
		if err := e.ApplyRules(context.Background(), snap); err != nil {
			t.Fatal(err)
		}
		installed := e.ruleSnap.current.Load().epoch
		metadata.ApplyID = "adopted"
		e.BindProtection(metadata)
		if err := e.ApplyRules(context.Background(), snap); err != nil {
			t.Fatal(err)
		}
		if e.ruleSnap.current.Load().epoch != installed {
			t.Fatal("adopted no-op advanced epoch")
		}
		current = []netip.Addr{netip.MustParseAddr("203.0.113.2")}
		if err := e.RefreshLocalAddresses(context.Background()); err != nil {
			t.Fatal(err)
		}
		refreshed := e.ruleSnap.current.Load().epoch
		if refreshed <= installed || e.sessions.ruleOwner != &e.ruleSnap || e.sessions.snap != e.CurrentRules() {
			t.Fatal("resolver publication bypassed session policy")
		}
		current = []netip.Addr{netip.MustParseAddr("203.0.113.3")}
		nft.err = errors.New("atomic update failed")
		if err := e.RefreshLocalAddresses(context.Background()); err == nil {
			t.Fatal("failure hidden")
		}
		if e.ruleSnap.current.Load().epoch != refreshed {
			t.Fatal("failed install advanced epoch")
		}
	})
}
