// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// TestIdentityBindingsAreDurableConfig stages bindings like rules: they are
// committed, survive a store reopen (an appliance restart), export with the
// config, roll back with it, and compile into a canonical snapshot.
func TestIdentityBindingsAreDurableConfig(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	base := config.DefaultConfig()
	if err := store.Save(ctx, base); err != nil {
		t.Fatal(err)
	}
	cand := config.DefaultConfig()
	cand.Firewall.IdentityBindings = []config.IdentityBinding{
		{IP: "2001:db8::7", Identities: []string{"vendor"}},
		{IP: "10.0.0.20", Identities: []string{"operator", "engineer"}},
		{IP: "::ffff:10.0.0.5", Identities: []string{"operator"}},
	}
	cand.Firewall.Rules = append(cand.Firewall.Rules, config.Rule{ID: "ops-ssh", Identities: []string{"operator"},
		Protocols: []config.Protocol{{Name: "tcp", Port: "22"}}, Action: config.ActionAllow})
	if err := testSaveCandidate(store, ctx, cand); err != nil {
		t.Fatal(err)
	}
	if running, err := store.Load(ctx); err != nil || len(running.Firewall.IdentityBindings) != 0 {
		t.Fatalf("staged bindings reached the running config: %v, %v", running, err)
	}
	if err := testCommit(store, ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	running, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(running.Firewall.IdentityBindings, cand.Firewall.IdentityBindings) {
		t.Fatalf("bindings after reopen = %+v, want %+v", running.Firewall.IdentityBindings, cand.Firewall.IdentityBindings)
	}
	exported, err := json.Marshal(running)
	if err != nil {
		t.Fatal(err)
	}
	var imported config.Config
	if err := json.Unmarshal(exported, &imported); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imported.Firewall.IdentityBindings, cand.Firewall.IdentityBindings) {
		t.Fatalf("exported bindings = %+v", imported.Firewall.IdentityBindings)
	}

	snap, err := CompileSnapshot(running)
	if err != nil {
		t.Fatal(err)
	}
	want := []dprules.IdentityBinding{
		{IP: "10.0.0.5", Identities: []string{"operator"}},
		{IP: "10.0.0.20", Identities: []string{"engineer", "operator"}},
		{IP: "2001:db8::7", Identities: []string{"vendor"}},
	}
	if !reflect.DeepEqual(snap.IdentityBindings, want) {
		t.Fatalf("snapshot bindings = %+v, want %+v", snap.IdentityBindings, want)
	}

	if err := testRollback(store, ctx); err != nil {
		t.Fatal(err)
	}
	if rolled, err := store.Load(ctx); err != nil || len(rolled.Firewall.IdentityBindings) != 0 {
		t.Fatalf("rollback kept the bindings: %+v, %v", rolled, err)
	}
}
