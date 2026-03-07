// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAuditStoreAddList(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	defer store.Close()

	rec := Record{
		Actor:  "user1",
		Source: "api",
		Action: "commit",
		Target: "config",
		Result: "success",
		Detail: "test detail",
	}
	if err := store.Add(context.Background(), rec); err != nil {
		t.Fatalf("add: %v", err)
	}
	list, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 record, got %d", len(list))
	}
	if list[0].Actor != "user1" || list[0].Action != "commit" {
		t.Fatalf("unexpected record %+v", list[0])
	}
}
