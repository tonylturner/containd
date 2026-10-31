// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func TestLocalAddressUpdatePublishesWithoutReloadOrSweep(t *testing.T) {
	e, nft := admissionEngine(t)
	current := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}
	discoveryErr := error(nil)
	e.localIPv4 = func(*rules.Snapshot) (map[string][]netip.Addr, error) {
		return map[string][]netip.Addr{"wan0": current}, discoveryErr
	}
	snap := rules.Snapshot{Version: "installed", ZoneIfaces: map[string][]string{"wan": {"wan0"}}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	installed, shadow := e.RulesetStatus(), e.ruleSnap.current.Load().shadow
	if !reflect.DeepEqual(e.CurrentRules().LocalIPv4ByDevice["wan0"], current) {
		t.Fatal("compile did not receive all local addresses")
	}
	e.clearMarks = func(context.Context, uint32, uint32, uint32) (int, error) {
		t.Error("address change swept conntrack")
		return 0, nil
	}
	e.verdictCache.Put("stale", verdict.Verdict{Action: verdict.DenyDrop})
	current = current[1:]
	if err := e.RefreshLocalAddresses(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.ruleset, "flush set") || strings.Contains(nft.ruleset, "delete table") ||
		!strings.Contains(nft.ruleset, "203.0.113.2") || strings.Contains(nft.ruleset, "203.0.113.1") {
		t.Fatalf("not an in-place set transaction: %s", nft.ruleset)
	}
	if e.CurrentRules().AdmissionParity != 0 || e.verdictCache.Len() != 0 ||
		e.ruleSnap.current.Load().shadow != shadow || e.RulesetStatus().AppliedAt != installed.AppliedAt ||
		!reflect.DeepEqual(e.CurrentRules().LocalIPv4ByDevice["wan0"], current) {
		t.Fatal("address update reinstalled policy or failed to publish resolver")
	}
	discoveryErr = errors.New("address dump failed")
	if err := e.RefreshLocalAddresses(context.Background()); err == nil || e.IEC104Enforcement().Healthy {
		t.Fatal("discovery failure hidden")
	}
	discoveryErr = nil
	if err := e.RefreshLocalAddresses(context.Background()); err != nil || !e.IEC104Enforcement().Healthy {
		t.Fatal("unchanged successful discovery did not recover health")
	}
	old := e.CurrentRules()
	current = nil
	nft.err = errors.New("atomic set update failed")
	if err := e.RefreshLocalAddresses(context.Background()); err == nil || e.CurrentRules() != old {
		t.Fatal("published addresses that nft did not install")
	}
	nft.err = nil
	if err := e.RefreshLocalAddresses(context.Background()); err != nil || len(e.CurrentRules().LocalIPv4ByDevice["wan0"]) != 0 {
		t.Fatal("could not remove the last local address")
	}
}

func TestAddressNotificationsCoalesce(t *testing.T) {
	zones := &zoneCache{changes: make(chan struct{}, 1)}
	zones.subscribed()
	for range 100 {
		zones.changed()
	}
	if len(zones.changes) != 1 {
		t.Fatal("address notifications did not coalesce")
	}
	<-zones.changes
	zones.unsubscribed()
	if len(zones.changes) != 1 {
		t.Fatal("loss of subscription did not invalidate address sets")
	}
}
