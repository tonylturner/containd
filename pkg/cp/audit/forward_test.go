// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T, path string) *SQLiteStore {
	t.Helper()
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	return store
}

func addRecords(t *testing.T, store *SQLiteStore, actions ...string) {
	t.Helper()
	for _, a := range actions {
		if err := store.Add(context.Background(), Record{Actor: "admin", Source: "api", Action: a, Target: "running", Result: "success"}); err != nil {
			t.Fatalf("add %s: %v", a, err)
		}
	}
}

func cursorOf(t *testing.T, store *SQLiteStore, consumer string) (int64, bool) {
	t.Helper()
	id, ok, err := store.ForwardCursor(context.Background(), consumer)
	if err != nil {
		t.Fatalf("ForwardCursor(%s): %v", consumer, err)
	}
	return id, ok
}

func TestListAfterIsOldestFirstAndBounded(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	addRecords(t, store, "a", "b", "c", "d")

	recs, err := store.ListAfter(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListAfter: %v", err)
	}
	if len(recs) != 2 || recs[0].ID != 2 || recs[1].ID != 3 || recs[0].Action != "b" {
		t.Fatalf("ListAfter(1, 2) = %+v", recs)
	}
	if n, err := store.CountAfter(ctx, 1); err != nil || n != 3 {
		t.Fatalf("CountAfter(1) = %d, %v", n, err)
	}
	if _, err := store.ListAfter(ctx, 0, 0); err == nil {
		t.Fatal("ListAfter accepted a zero limit")
	}
}

func TestForwardCursorLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	addRecords(t, store, "a", "b")

	if _, ok := cursorOf(t, store, "syslog:udp://x:514"); ok {
		t.Fatal("cursor exists before start")
	}
	if err := store.AdvanceForwardCursor(ctx, "syslog:udp://x:514", 2); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if _, ok := cursorOf(t, store, "syslog:udp://x:514"); ok {
		t.Fatal("Advance created a cursor")
	}
	if err := store.StartForwardCursor(ctx, "syslog:udp://x:514"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if id, ok := cursorOf(t, store, "syslog:udp://x:514"); !ok || id != 2 {
		t.Fatalf("new cursor = %d, %v; want the newest record 2", id, ok)
	}
	addRecords(t, store, "c", "d")
	if err := store.StartForwardCursor(ctx, "syslog:udp://x:514"); err != nil {
		t.Fatalf("Start again: %v", err)
	}
	if id, _ := cursorOf(t, store, "syslog:udp://x:514"); id != 2 {
		t.Fatalf("restart moved the cursor to %d", id)
	}
	if err := store.AdvanceForwardCursor(ctx, "syslog:udp://x:514", 4); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if err := store.AdvanceForwardCursor(ctx, "syslog:udp://x:514", 3); err != nil {
		t.Fatalf("Advance backwards: %v", err)
	}
	if id, _ := cursorOf(t, store, "syslog:udp://x:514"); id != 4 {
		t.Fatalf("cursor = %d after a backwards advance; want 4", id)
	}

	// The cursor survives reopening the database.
	store.Close()
	store = openTestStore(t, path)
	defer store.Close()
	if id, ok := cursorOf(t, store, "syslog:udp://x:514"); !ok || id != 4 {
		t.Fatalf("reopened cursor = %d, %v; want 4", id, ok)
	}
}

func TestRetainForwardCursorsDropsOnlyUnlistedPrefixMatches(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	for _, c := range []string{"syslog:udp://a:514", "syslog:tcp://b:514", "other:consumer"} {
		if err := store.StartForwardCursor(ctx, c); err != nil {
			t.Fatalf("Start %s: %v", c, err)
		}
	}
	if err := store.RetainForwardCursors(ctx, "syslog:", []string{"syslog:tcp://b:514"}); err != nil {
		t.Fatalf("Retain: %v", err)
	}
	if _, ok := cursorOf(t, store, "syslog:udp://a:514"); ok {
		t.Fatal("unlisted cursor kept")
	}
	if _, ok := cursorOf(t, store, "syslog:tcp://b:514"); !ok {
		t.Fatal("listed cursor dropped")
	}
	if _, ok := cursorOf(t, store, "other:consumer"); !ok {
		t.Fatal("cursor outside the prefix dropped")
	}
}

func TestWipeAllRewindsCursorsAndKeepsIDsIncreasing(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	addRecords(t, store, "a", "b", "c")
	if err := store.StartForwardCursor(ctx, "syslog:udp://x:514"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := store.WipeAll(ctx); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}
	if id, ok := cursorOf(t, store, "syslog:udp://x:514"); !ok || id != 0 {
		t.Fatalf("cursor after wipe = %d, %v; want 0", id, ok)
	}
	addRecords(t, store, "factory_reset.completed")
	recs, err := store.ListAfter(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListAfter: %v", err)
	}
	if len(recs) != 1 || recs[0].ID <= 3 {
		t.Fatalf("records after wipe = %+v; want one record with an ID above 3", recs)
	}
}
