// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRevisionRecoveryBanksAcrossHandles(t *testing.T) {
	for _, mode := range []string{"rejected CAS", "open handle"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			first, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			original := DefaultConfig()
			original.Description = "original"
			if err := first.Save(ctx, original); err != nil {
				t.Fatal(err)
			}
			replaceGCTestBank(t, first, "candidate-bank")
			before := revisionSnapshot(t, first)
			recoveryBank, err := bankReference(ctx, first.db, configKeyCandidate)
			if err != nil || recoveryBank == 0 {
				t.Fatalf("candidate bank: %d, %v", recoveryBank, err)
			}
			var second *SQLiteStore
			if mode == "rejected CAS" {
				second, err = NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
			}
			_, err = first.ApplyReset(ctx, before.Revision, DefaultConfig(), func(_ context.Context, _, next *Config) error {
				if next.Description == "original" {
					return nil
				}
				if mode == "open handle" {
					var count int
					if err := first.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ids_banks WHERE id = ?`, recoveryBank).Scan(&count); err != nil {
						t.Fatal(err)
					}
					if count != 1 {
						t.Fatal("recovery bank was not held before opening the second handle")
					}
					opened, err := NewSQLiteStore(path)
					if err != nil {
						t.Fatal(err)
					}
					defer opened.Close()
					second = opened
					if err := second.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ids_banks WHERE id = ?`, recoveryBank).Scan(&count); err != nil {
						t.Fatal(err)
					}
					if count != 0 {
						t.Fatal("opening the second handle did not sweep the recovery bank")
					}
				} else {
					_, rejection := second.ApplyChange(ctx, before.Revision, ChangeCommit, 0, func(context.Context, *Config, *Config) error {
						t.Fatal("stale apply ran")
						return nil
					})
					var mismatch *ErrRevisionMismatch
					if !errors.As(rejection, &mismatch) {
						t.Fatalf("want mismatch: %v", rejection)
					}
				}
				// Rejection/open must not consume a revision of its own.
				during := revisionSnapshot(t, second)
				if during.Revision == before.Revision {
					t.Fatal("reset did not allocate")
				}
				return errors.New("runtime apply failure")
			})
			var failure *ApplyError
			if !errors.As(err, &failure) || failure.RestoreError != nil || failure.ReapplyError != nil {
				t.Fatalf("recovery failed: %v", err)
			}
			after := revisionSnapshot(t, first)
			if !reflect.DeepEqual(before.Running, after.Running) || !reflect.DeepEqual(before.Candidate, after.Candidate) || before.Revision == after.Revision {
				t.Fatal("recovery lost documents, banks or fresh revision")
			}
			assertBankCollection(t, first, 3)
		})
	}
}
