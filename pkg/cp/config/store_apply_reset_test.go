// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func resetTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := DefaultConfig()
	cfg.System.Hostname = "previous"
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.System.Hostname = "running"
	cfg.IDS.Rules = DefaultIDSConfig().Rules[:1]
	if err := testSaveCandidate(store, ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	cfg.System.Hostname = "candidate"
	cfg.IDS.Rules = []IDSRule{}
	if err := testSaveCandidate(store, ctx, cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func resetConfigRows(t *testing.T, store *SQLiteStore) []savedConfigRow {
	t.Helper()
	rows, err := store.db.Query(`SELECT key, data, updated_at FROM configs WHERE key != ? ORDER BY key`, runtimeApplyFaultKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var saved []savedConfigRow
	for rows.Next() {
		var row savedConfigRow
		if err := rows.Scan(&row.key, &row.data, &row.updatedAt); err != nil {
			t.Fatal(err)
		}
		saved = append(saved, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestApplyResetRestoresStateAndCanceledCaller(t *testing.T) {
	for _, failReapply := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered", true: "reapply_failed"}[failReapply], func(t *testing.T) {
			store := resetTestStore(t)
			before := resetConfigRows(t, store)
			bank, err := store.LoadIDSRules(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			err = testApplyReset(store, ctx, DefaultConfig(), func(ctx context.Context, previous, next *Config) error {
				calls++
				if calls == 1 {
					if previous.System.Hostname != "running" || next.System.Hostname != DefaultConfig().System.Hostname {
						t.Fatalf("unexpected reset snapshots: %s -> %s", previous.System.Hostname, next.System.Hostname)
					}
					cancel()
					return errors.New("nft apply failed")
				}
				if ctx.Err() != nil || next.System.Hostname != "running" || !reflect.DeepEqual(next.IDS.Rules, bank) {
					t.Fatalf("incorrect recovery snapshot/context: %+v %v", next, ctx.Err())
				}
				if failReapply {
					return errors.New("nft recovery failed")
				}
				return nil
			})
			var failure *ApplyError
			if !errors.As(err, &failure) || failure.RestoreError != nil || (failure.ReapplyError != nil) != failReapply || calls != 2 {
				t.Fatalf("recovery result: %v calls=%d", err, calls)
			}
			if after := resetConfigRows(t, store); !reflect.DeepEqual(before, after) || store.pendingTimer == nil {
				t.Fatalf("configuration rows/timer not restored: before=%+v after=%+v", before, after)
			}
			gotBank, err := store.LoadIDSRules(context.Background())
			if err != nil || !reflect.DeepEqual(bank, gotBank) {
				t.Fatalf("IDS bank changed: %v %+v", err, gotBank)
			}
			fault, err := store.RuntimeApplyFault(context.Background())
			if err != nil || (fault != "") != failReapply {
				t.Fatalf("runtime fault: %q %v", fault, err)
			}
			if err := testRollback(store, context.Background()); err != nil {
				t.Fatal(err)
			}
			running, err := store.Load(context.Background())
			if err != nil || running.System.Hostname != "previous" {
				t.Fatalf("previous lost: %+v %v", running, err)
			}
		})
	}
}

func TestApplyResetClearsHistoryAndBank(t *testing.T) {
	ctx := context.Background()
	store := resetTestStore(t)
	if err := store.SetManagementBootFault(ctx, "old fault"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRuntimeApplyFault(ctx, "old fault"); err != nil {
		t.Fatal(err)
	}
	defaults := DefaultConfig()
	defaults.IDS.Rules = []IDSRule{}
	calls := 0
	if err := testApplyReset(store, ctx, defaults, func(_ context.Context, _, next *Config) error {
		calls++
		if len(next.IDS.Rules) != 0 {
			t.Fatalf("reset retained IDS bank: %+v", next.IDS.Rules)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows := resetConfigRows(t, store)
	if calls != 1 || len(rows) != 1 || rows[0].key != configKeyRunning || store.pendingTimer != nil {
		t.Fatalf("reset retained state: %+v timer=%v calls=%d", rows, store.pendingTimer, calls)
	}
	bank, err := store.LoadIDSRules(ctx)
	if err != nil || len(bank) != 0 {
		t.Fatalf("IDS bank not cleared: %+v %v", bank, err)
	}
	fault, err := store.RuntimeApplyFault(ctx)
	if err != nil || fault != "" {
		t.Fatalf("runtime fault retained: %q %v", fault, err)
	}
}

func TestApplyResetRejectsInvalidDefaults(t *testing.T) {
	store := resetTestStore(t)
	before := resetConfigRows(t, store)
	invalid := DefaultConfig()
	invalid.System.Hostname = strings.Repeat("x", 256)
	for _, cfg := range []*Config{nil, invalid} {
		err := testApplyReset(store, context.Background(), cfg, func(context.Context, *Config, *Config) error {
			t.Fatal("invalid defaults reached runtime apply")
			return nil
		})
		if err == nil || !reflect.DeepEqual(before, resetConfigRows(t, store)) || store.pendingTimer == nil {
			t.Fatalf("invalid defaults changed state: %v", err)
		}
	}
}

func TestConfigWipeTransactionFailurePreservesStateAndTimer(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "wipe", true: "reset"}[reset], func(t *testing.T) {
			store := resetTestStore(t)
			before := resetConfigRows(t, store)
			timer := store.pendingTimer
			bank, err := store.LoadIDSRules(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`CREATE TRIGGER deny_wipe BEFORE DELETE ON ids_rules BEGIN SELECT RAISE(ABORT, 'wipe denied'); END`); err != nil {
				t.Fatal(err)
			}
			if reset {
				err = testApplyReset(store, context.Background(), DefaultConfig(), func(context.Context, *Config, *Config) error {
					t.Fatal("failed reset transaction reached runtime apply")
					return nil
				})
			} else {
				err = store.WipeAll(context.Background())
			}
			if err == nil || !reflect.DeepEqual(before, resetConfigRows(t, store)) || store.pendingTimer != timer {
				t.Fatalf("transaction failure changed state/timer: %v", err)
			}
			gotBank, err := store.LoadIDSRules(context.Background())
			if err != nil || !reflect.DeepEqual(bank, gotBank) {
				t.Fatalf("transaction failure changed IDS bank: %+v %v", gotBank, err)
			}
		})
	}
}
