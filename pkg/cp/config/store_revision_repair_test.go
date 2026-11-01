// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"testing"
)

func TestRevisionRepairPersistsReadUpgrades(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	if err := testSaveCandidate(s, ctx, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	// Model persisted bytes requiring only a read-time upgrade, with no edit
	// supplied by boot repair. Keeping the handle open bypasses boot migration.
	if _, err := s.db.Exec(`UPDATE configs SET data = json_set(data, '$.schema_version', '0.1.8', '$.dataplane.dpiMode', 'learn') WHERE key IN (?, ?)`, configKeyRunning, configKeyCandidate); err != nil {
		t.Fatal(err)
	}
	base := revisionSnapshot(t, s).Revision
	if _, err := Repair(ctx, s, func(*Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after := revisionSnapshot(t, s).Revision
	if after == base {
		t.Fatal("read-time upgrade was not persisted")
	}
	for _, key := range []string{configKeyRunning, configKeyCandidate} {
		cfg, err := readKindUnupgradedFrom(ctx, s.db, key, true)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SchemaVersion != SchemaVersionCurrent || cfg.DataPlane.DPIMode != "monitor" {
			t.Fatal("upgrade left stale bytes")
		}
	}
	records, err := s.RuleModeMigrations(ctx)
	if err != nil || len(records) != 2 {
		t.Fatalf("missing migration outbox: %v %v", records, err)
	}
	if _, err := Repair(ctx, s, func(*Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if revisionSnapshot(t, s).Revision != after {
		t.Fatal("no-op repair allocated again")
	}
}
