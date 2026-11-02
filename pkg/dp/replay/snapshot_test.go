// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDeriveDemoSnapshotMonitorOnly(t *testing.T) {
	running := rules.Snapshot{
		DPIMode: "enforce",
		Firewall: []rules.Entry{
			{ID: "plain", Action: rules.ActionDeny},
			{ID: "operator-deny", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}},
			{ID: "operator-reset", Action: rules.ActionReset, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
			{ID: "operator-inherit", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "cip"}},
		},
		IDS: rules.IDSConfig{Enabled: true, Rules: []rules.IDSRule{{ID: "ids"}}},
	}
	snap := DeriveDemoSnapshot(&running, []string{"dmz", "lan"})
	if snap.DPIMode != "monitor" || len(snap.Firewall) != 3 || !reflect.DeepEqual(snap.IDS, running.IDS) {
		t.Fatalf("%+v", snap)
	}
	for i, e := range snap.Firewall {
		original := running.Firewall[i+1]
		if !rules.MonitorICS(e, snap.DPIMode) || e.ID != original.ID || e.Action != original.Action {
			t.Fatalf("enforcing or lost identity: %+v", e)
		}
	}
	if running.Firewall[1].ICS.Mode != "enforce" || running.Firewall[3].ICS.Mode != "" {
		t.Fatal("mutated running snapshot")
	}
	if !reflect.DeepEqual(snap.ZoneIfaces, map[string][]string{"dmz": {"demo:dmz"}, "lan": {"demo:lan"}}) {
		t.Fatal(snap.ZoneIfaces)
	}
}

func TestDeriveDemoSnapshotDefaultEnvelope(t *testing.T) {
	for _, running := range []*rules.Snapshot{nil, {}, {Firewall: []rules.Entry{{ID: "demo-iec104-envelope"}}}} {
		snap := DeriveDemoSnapshot(running, nil)
		if len(snap.Firewall) != 1 {
			t.Fatal(snap.Firewall)
		}
		e := snap.Firewall[0]
		if e.ICS.Protocol != "iec104" || !rules.MonitorICS(e, snap.DPIMode) || len(e.Sources) != 0 || len(e.Destinations) != 0 || len(e.SourceZones) != 0 || len(e.DestZones) != 0 {
			t.Fatal(e)
		}
	}
}
