// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireReservationError(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "reserved management path") {
		t.Fatalf("want reservation conflict, got %v", err)
	}
}

func TestStoreReservationPersistenceBoundaries(t *testing.T) {
	ctx := context.Background()
	valid, r := reservationFixture()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"), WithManagementReservation(r))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(ctx, valid); err != nil {
		t.Fatal(err)
	}
	invalid, _ := reservationFixture()
	invalid.Interfaces[0].Addresses = []string{"192.0.2.1/24"}
	requireReservationError(t, store.Save(ctx, invalid))
	requireReservationError(t, testSaveCandidate(store, ctx, invalid))
	requireReservationError(t, testMutateCandidate(store, ctx, func(c *Config) error {
		c.DataPlane.Enforcement = false
		return nil
	}))
	// Simulate snapshots written before enabling the reservation.
	putSnapshot := func(key string, cfg *Config) {
		t.Helper()
		blob, err := marshalStoredConfig(key, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, key, string(blob)); err != nil {
			t.Fatal(err)
		}
	}
	putSnapshot(configKeyCandidate, invalid)
	requireReservationError(t, testCommit(store, ctx))
	requireReservationError(t, testCommitConfirmed(store, ctx, time.Hour))
	if _, err := Repair(ctx, store, func(c *Config) error { c.System.Hostname = "repaired"; return nil }); err != nil {
		t.Fatalf("boot normalization blocked by residual candidate conflict: %v", err)
	}
	requireReservationError(t, testCommit(store, ctx))
	putSnapshot(configKeyCandidate, valid)
	putSnapshot(configKeyPrevious, invalid)
	requireReservationError(t, testRollback(store, ctx))
	fault, err := store.ManagementRollbackFault(ctx)
	if err != nil || !strings.Contains(fault, "rollback refused") {
		t.Fatalf("missing visible refusal: %q %v", fault, err)
	}
	base := testBaseRevision(store, ctx)
	_, applyErr := store.ApplyChange(ctx, base, ChangeRollback, 0, func(context.Context, *Config, *Config) error {
		t.Fatal("refused rollback reached runtime apply")
		return nil
	})
	requireReservationError(t, applyErr)
	if testBaseRevision(store, ctx) != base {
		t.Fatal("rollback refusal allocated a revision")
	}
	// Confirmation only validates when it actually removes pending state.
	if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	putSnapshot(configKeyRunning, invalid)
	requireReservationError(t, testConfirmCommit(store, ctx))
	putSnapshot(configKeyRunning, valid)
	f := false
	for i := range valid.Interfaces {
		valid.Interfaces[i].Access = InterfaceAccess{Mgmt: &f, HTTP: &f, HTTPS: &f, SSH: &f}
	}
	if err := testSaveCandidate(store, ctx, valid); err != nil {
		t.Fatal(err)
	}
	if err := testCommit(store, ctx); err != nil {
		t.Fatalf("disabling ordinary access must succeed: %v", err)
	}
	// Mutation of caller-owned authority or its read-only view cannot weaken it.
	r.Device = "other"
	view := store.ManagementReservation()
	view.Sources[0] = view.Local.Addr()
	if store.ManagementReservation().Sources[0] == view.Local.Addr() {
		t.Fatal("authority escaped")
	}
	requireReservationError(t, store.Save(ctx, invalid))
}

func TestStoreReservationRefusesTimedRollback(t *testing.T) {
	for _, atOpen := range []bool{false, true} {
		t.Run(map[bool]string{false: "timer", true: "expired at open"}[atOpen], func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			valid, r := reservationFixture()
			store, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			unsafe, _ := reservationFixture()
			unsafe.DataPlane.Enforcement = false
			if err := store.Save(ctx, unsafe); err != nil {
				t.Fatal(err)
			}
			if err := testSaveCandidate(store, ctx, valid); err != nil {
				t.Fatal(err)
			}
			if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
				t.Fatal(err)
			}
			beforeExpiry := testBaseRevision(store, ctx)
			deadline := time.Now().Add(150 * time.Millisecond)
			if atOpen {
				deadline = time.Now().Add(-time.Second)
			}
			raw, err := json.Marshal(pendingCommit{DeadlineUnix: deadline.UnixNano()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`UPDATE configs SET data=? WHERE key=?`, string(raw), configKeyPending); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = NewSQLiteStore(path, WithManagementReservation(r))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			notify := make(chan struct{}, 1)
			store.SetAutoRollbackNotify(notify)
			until := time.Now().Add(3 * time.Second)
			for {
				fault, err := store.ManagementRollbackFault(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if fault != "" {
					break
				}
				if time.Now().After(until) {
					t.Fatal("timed rollback refusal not visible")
				}
				time.Sleep(10 * time.Millisecond)
			}
			store.mu.Lock()
			_, pendingErr := store.loadPending(ctx)
			store.mu.Unlock()
			if revision := testBaseRevision(store, ctx); revision == beforeExpiry {
				t.Fatal("refused timed rollback did not allocate")
			}
			if !errors.Is(pendingErr, ErrNotFound) {
				t.Fatalf("pending retained: %v", pendingErr)
			}
			select {
			case <-notify:
				t.Fatal("refused rollback triggered runtime replay")
			default:
			}
			running, err := store.Load(ctx)
			if err != nil || !running.DataPlane.Enforcement {
				t.Fatalf("unsafe rollback applied: %+v %v", running, err)
			}
		})
	}
}

func TestStoreReservationOpensConflictingStoredRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.db")
	invalid, r := reservationFixture()
	invalid.DataPlane.Enforcement = false
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), invalid); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(path, WithManagementReservation(r))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	running, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireReservationError(t, store.ValidateConfig(running))
}

func TestManagementBootFaultRecovery(t *testing.T) {
	for _, recovery := range []string{"commit", "rollback", "reset"} {
		t.Run(recovery, func(t *testing.T) {
			ctx := context.Background()
			valid, r := reservationFixture()
			path := filepath.Join(t.TempDir(), "config.db")
			store, err := NewSQLiteStore(path, WithManagementReservation(r))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(ctx, valid); err != nil {
				t.Fatal(err)
			}
			if err := testSaveCandidate(store, ctx, valid); err != nil {
				t.Fatal(err)
			}
			if err := testCommit(store, ctx); err != nil {
				t.Fatal(err)
			}
			if err := store.SetManagementBootFault(ctx, "stored conflict"); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = NewSQLiteStore(path, WithManagementReservation(r))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := CheckManagementBootFault(ctx, store); !errors.Is(err, ErrManagementBootFault) {
				t.Fatalf("fault lost on reopen: %v", err)
			}
			switch recovery {
			case "commit":
				err = testCommit(store, ctx)
			case "rollback":
				err = testRollback(store, ctx)
			case "reset":
				err = store.WipeAll(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckManagementBootFault(ctx, store); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagementBootFaultGatesWithoutReservation(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	// Boot records this for a stored config that fails validation.
	if err := store.SetManagementBootFault(ctx, "stored config invalid"); err != nil {
		t.Fatal(err)
	}
	if err := CheckManagementBootFault(ctx, store); !errors.Is(err, ErrManagementBootFault) {
		t.Fatalf("fault without reservation did not gate replay: %v", err)
	}
	if err := testSaveCandidate(store, ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := testCommit(store, ctx); err != nil {
		t.Fatal(err)
	}
	if err := CheckManagementBootFault(ctx, store); err != nil {
		t.Fatalf("valid commit did not clear the fault: %v", err)
	}
}
