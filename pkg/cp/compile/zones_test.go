// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestCompilePreservesAllZoneNamesInConfigOrder(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Zones = append([]config.Zone{{Name: "unbound"}}, cfg.Zones...)
	var want []string
	for _, zone := range cfg.Zones {
		want = append(want, zone.Name)
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var received rules.Snapshot
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(received.Zones, want) {
		t.Fatalf("received zones = %v, want %v", received.Zones, want)
	}
	cfg.Zones[0].Name = "edited-after-compile"
	if !reflect.DeepEqual(snap.Zones, want) {
		t.Fatal("snapshot aliases mutable config")
	}
}
