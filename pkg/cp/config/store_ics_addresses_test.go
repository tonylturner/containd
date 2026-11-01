// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStoredUnsupportedAddressesRemainRepairable(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip"} {
		t.Run(proto, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			store, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg := icsAddressConfig(proto, "10-20")
			// Model a running document accepted before capability validation.
			raw, err := marshalStoredConfig(configKeyRunning, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`INSERT INTO configs (key,data,updated_at) VALUES (?,?,0)`, configKeyRunning, string(raw)); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = NewSQLiteStore(path)
			if err != nil {
				t.Fatalf("opening incompatible config must not stop management: %v", err)
			}
			defer store.Close()
			loaded, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded.Firewall.Rules[0].ICS.Addresses, []string{"10-20"}) {
				t.Fatal("loading silently changed the unsupported filter")
			}
			// This is the validation used by bootConflict and replay preflight.
			conflict := ValidateForStore(store, loaded)
			if conflict == nil || !strings.Contains(conflict.Error(), "rule ics-1 ics addresses") {
				t.Fatalf("boot/replay cause: %v", conflict)
			}
			// Boot records the validation cause, rather than replaying this policy.
			if err := store.SetManagementBootFault(ctx, conflict.Error()); err != nil {
				t.Fatal(err)
			}
			if err := CheckManagementBootFault(ctx, store); !errors.Is(err, ErrManagementBootFault) || !strings.Contains(err.Error(), conflict.Error()) {
				t.Fatalf("replay gate lost the cause: %v", err)
			}
			candidate, err := store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := testSaveCandidate(store, ctx, candidate); err == nil {
				t.Fatal("unchanged invalid candidate was accepted")
			}
			candidate.Firewall.Rules[0].ICS.Addresses = nil
			if err := testSaveCandidate(store, ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err := CheckManagementBootFault(ctx, store); !errors.Is(err, ErrManagementBootFault) {
				t.Fatalf("staging cleared recovery: %v", err)
			}
			if err := testCommit(store, ctx); err != nil {
				t.Fatal(err)
			}
			if err := CheckManagementBootFault(ctx, store); err != nil {
				t.Fatalf("valid commit did not clear recovery: %v", err)
			}
		})
	}
}
