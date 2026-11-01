// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func controlledWatch(t *testing.T) (*evidenceWatch, *sql.DB, *atomic.Int64) {
	t.Helper()
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence.db")
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixNano())
	s, err := sqlite.Open(path, sqlite.Options{
		CompatibleProof: learn.CompatibleVersions,
		Now:             func() time.Time { return time.Unix(0, clock.Load()) },
		WatchMetadata:   func() (evidence.Dataset, error) { return evidenceMetadata(e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	// Fault injection uses a second connection alongside the real flush worker.
	// Let DDL wait for its short transactions instead of racing SQLite's lock.
	execWatchSQL(t, db, `PRAGMA busy_timeout=5000`)
	w := &evidenceWatch{queue: make(chan evidenceBatch, 64), done: make(chan struct{}), store: s, engine: e}
	ctx, cancel := context.WithCancel(context.Background())
	go w.run(ctx)
	t.Cleanup(func() {
		e.SetLearnLossHook(nil)
		e.SetLearnWatchHook(nil)
		cancel()
		<-w.done
		_ = db.Close()
		_ = s.Close()
	})
	return w, db, clock
}

func execWatchSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticStopRetriesDetachedLease(t *testing.T) {
	for _, reason := range []string{"deadline", "policy_changed"} {
		t.Run(reason, func(t *testing.T) {
			w, db, clock := controlledWatch(t)
			ctx := context.Background()
			watch, err := w.start(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			lease := w.active.Load()
			lease.lossMu.Lock()
			lease.addLossLocked(evidence.CollectionLoss{Code: "capture_loss", ConnectionID: "affected"})
			lease.lossMu.Unlock()
			execWatchSQL(t, db, `CREATE TRIGGER deny_loss BEFORE UPDATE OF data ON datasets WHEN json_array_length(json_extract(NEW.data, '$.losses')) > 0 BEGIN SELECT RAISE(FAIL,'injected loss write failure'); END`)
			if reason == "deadline" {
				clock.Store(watch.Deadline.Add(time.Second).UnixNano())
			} else {
				w.engine.SetICSParsing(map[string]string{"modbus": "strict"})
			}
			w.maintainWatch(ctx)
			if w.stopping != lease || w.active.Load() != nil || w.err() == nil {
				t.Fatal("failed automatic stop did not retain detached authority")
			}
			execWatchSQL(t, db, `DROP TRIGGER deny_loss`)
			w.maintainWatch(ctx)
			got, err := w.store.GetWatch(ctx, watch.ID)
			if err != nil || got.StoppedAt == nil || got.StopReason != reason || w.stopping != nil || w.err() != nil {
				t.Fatalf("automatic retry: %+v %v", got, err)
			}
			ds, err := w.store.GetDataset(ctx, watch.DatasetID)
			if err != nil || !ds.LossTouches("affected", evidence.Tuple{}) {
				t.Fatalf("retry lost exclusion: %+v %v", ds, err)
			}
		})
	}
}

func TestStartFailureRetainsCleanupAuthority(t *testing.T) {
	w, db, _ := controlledWatch(t)
	// StartWatch commits successfully, then GetDataset cannot decode its row.
	// Save the row so recovery exercises the real retry path, not a fake store.
	execWatchSQL(t, db, `CREATE TABLE saved_dataset(id TEXT, data BLOB);
CREATE TRIGGER corrupt_start AFTER INSERT ON watches BEGIN
INSERT INTO saved_dataset SELECT id,data FROM datasets WHERE id=NEW.dataset;
UPDATE datasets SET data='invalid-json' WHERE id=NEW.dataset;
END`)
	ctx := context.Background()
	watch, err := w.start(ctx, evidence.StartWatchRequest{})
	if err == nil || w.stopping == nil || w.active.Load() != nil {
		t.Fatal("fault did not interrupt post-StartWatch initialization")
	}
	execWatchSQL(t, db, `DROP TRIGGER corrupt_start;
UPDATE datasets SET data=(SELECT data FROM saved_dataset WHERE saved_dataset.id=datasets.id)`)
	w.maintainWatch(ctx)
	ds, err := w.store.GetDataset(ctx, watch.DatasetID)
	if err != nil || ds.State != evidence.DatasetSealed || w.stopping != nil {
		t.Fatalf("start cleanup did not seal: %+v %v", ds, err)
	}
	if len(ds.Losses) != 1 || ds.Losses[0].Code != "watch_storage_loss" {
		t.Fatalf("collector-less seal omitted uncertainty: %+v", ds)
	}
}
