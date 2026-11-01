// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"testing"
)

func TestProtocolScopeUpgradeEntrypoints(t *testing.T) {
	for _, path := range []string{"save", "candidate", "rollback", "promote"} {
		t.Run(path, func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			old := DefaultConfig()
			old.SchemaVersion = "0.1.7"
			old.IDS.Rules = append(old.IDS.Rules, retiredBuiltinDefinitions()...)
			switch path {
			case "save":
				if err := s.Save(ctx, old); err != nil {
					t.Fatal(err)
				}
			case "candidate":
				// Validate before saving is the import/restore path; evidence must survive.
				if err := old.Validate(); err != nil {
					t.Fatal(err)
				}
				if err := testSaveCandidate(s, ctx, old); err != nil {
					t.Fatal(err)
				}
				if err := testCommit(s, ctx); err != nil {
					t.Fatal(err)
				}
			default:
				key := configKeyPrevious
				if path == "promote" {
					key = configKeyCandidate
				}
				tx, err := s.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeConfigTx(ctx, tx, key, old); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if path == "promote" {
					err = testCommit(s, ctx)
				} else {
					err = testRollback(s, ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.Load(ctx)
			if err != nil || got.SchemaVersion != SchemaVersionCurrent {
				t.Fatalf("running: %+v %v", got, err)
			}
			if len(got.IDS.Rules) != len(DefaultIDSConfig().Rules) {
				t.Fatalf("obsolete bank restored: %+v", got.IDS.Rules)
			}
			if path == "rollback" {
				if err := testRollback(s, ctx); err != nil {
					t.Fatal(err)
				}
			}
			records, err := s.IndustrialScopeMigrations(ctx)
			if err != nil || len(records) != 1 || len(records[0].Removed) != 5 {
				t.Fatalf("outbox: %+v %v", records, err)
			}
		})
	}
}
