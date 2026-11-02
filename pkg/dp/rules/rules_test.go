// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSnapshotOrderedZonesJSON(t *testing.T) {
	want := []string{"mgmt", "outside", "plant", "unbound"}
	raw, err := json.Marshal(Snapshot{Zones: want})
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snap.Zones, want) {
		t.Fatalf("zone order lost over engine wire: %s", raw)
	}
}

func TestSnapshotDefaults(t *testing.T) {
	s := Snapshot{
		Version: "1",
		Default: ActionAllow,
		Firewall: []Entry{
			{ID: "1", Action: ActionDeny},
		},
	}
	if s.Default != ActionAllow {
		t.Fatalf("expected allow default")
	}
	if len(s.Firewall) != 1 || s.Firewall[0].ID != "1" {
		t.Fatalf("unexpected firewall entries %+v", s.Firewall)
	}
}
