// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func legacyModes(version string) *Config {
	c := DefaultConfig()
	c.SchemaVersion = version
	c.DataPlane.DPIMode = "learn"
	c.Firewall.Rules = []Rule{
		{ID: "trial", Action: ActionDeny, ICS: ICSPredicate{Protocol: "modbus", Mode: "learn"}},
		{ID: "l4", Action: ActionAllow, ICS: ICSPredicate{Mode: "enforce"}},
	}
	return c
}

func TestRuleModesUpgradeAndValidation(t *testing.T) {
	for _, version := range []string{"", "0.1.7", "0.1.8"} {
		t.Run(version, func(t *testing.T) {
			c := legacyModes(version)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if c.SchemaVersion != SchemaVersionCurrent || c.DataPlane.DPIMode != "monitor" || c.Firewall.Rules[1].ICS.Mode != "monitor" || c.Firewall.Rules[0].ICS.Mode != "" {
				t.Fatalf("migration: %+v", c)
			}
			if c.modeMigration == nil || len(c.modeMigration.Changes) != 3 || c.modeMigration.Changes[2].Action != "clear" {
				t.Fatalf("evidence: %+v", c.modeMigration)
			}
			if c.modeMigration.SchemaBefore != version {
				t.Fatalf("original schema %q lost: %+v", version, c.modeMigration)
			}
			rec := c.modeMigration
			if err := c.Validate(); err != nil || c.modeMigration != rec {
				t.Fatal("validation lost pending evidence", err)
			}
		})
	}
	for _, global := range []bool{false, true} {
		c := legacyModes(SchemaVersionCurrent)
		c.Firewall.Rules = c.Firewall.Rules[:1]
		if global {
			c.Firewall.Rules[0].ICS.Mode = "monitor"
		} else {
			c.DataPlane.DPIMode = "monitor"
		}
		err := c.Validate()
		field := "ics.mode"
		if global {
			field = "dataplane.dpiMode"
		}
		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "use monitor") {
			t.Fatalf("rejected learn: %v", err)
		}
	}
	if err := ValidateICSPredicate(ICSPredicate{Mode: "monitor"}, "new"); err == nil || !strings.Contains(err.Error(), "requires ics.protocol") {
		t.Fatal(err)
	}
}

func TestRuleModesOrderedThreeBankBoot(t *testing.T) {
	for _, version := range []string{"", "0.1.7", "0.1.8"} {
		t.Run(version, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			c := legacyModes(version)
			c.IDS.Rules = append(historicalCIPBuiltinDefinitions(), retiredBuiltinDefinitions()...)
			// Install actual legacy rows without invoking public validation/upgrades.
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				if err := writeConfigTx(ctx, tx, bank, c); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			for boot := 0; boot < 2; boot++ {
				s, err = NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				modes, err := s.RuleModeMigrations(ctx)
				if err != nil || len(modes) != 3 {
					t.Fatalf("mode outbox: %+v %v", modes, err)
				}
				for _, rec := range modes {
					if len(rec.Changes) != 3 || rec.SchemaBefore != version || rec.SchemaAfter != "0.1.9" {
						t.Fatalf("record: %+v", rec)
					}
				}
				scope, err := s.IndustrialScopeMigrations(ctx)
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if version == "" || version == "0.1.8" {
					want = 0
				}
				if len(scope) != want {
					t.Fatalf("scope outbox: %+v", scope)
				}
				for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
					got, err := readKindUnupgradedFrom(ctx, s.db, bank, true)
					if err != nil {
						t.Fatal(err)
					}
					if got.SchemaVersion != SchemaVersionCurrent || got.Firewall.Rules[1].ICS.Mode != "monitor" || got.Firewall.Rules[0].ICS.Mode != "" {
						t.Fatalf("bank %s: %+v", bank, got)
					}
					if want == 1 && (len(got.IDS.Rules) != 2 || got.IDS.Rules[0].Proto != "cip") {
						t.Fatalf("scope ordering: %+v", got.IDS.Rules)
					}
					if want == 0 && !reflect.DeepEqual(got.IDS.Rules, c.IDS.Rules) {
						t.Fatalf("ineligible scope migration changed IDS bank %s: %+v", bank, got.IDS.Rules)
					}
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestVersionlessRuleModeImportPreservesIDSBuiltins(t *testing.T) {
	c := legacyModes("")
	c.IDS.Rules = append(historicalCIPBuiltinDefinitions(), retiredBuiltinDefinitions()...)
	want, err := json.Marshal(c.IDS.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := UpgradeInPlace(c); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(c.IDS.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) || c.scopeMigration != nil {
		t.Fatalf("versionless import unexpectedly rewrote IDS builtins: %s; scope audit %+v", got, c.scopeMigration)
	}
	if c.modeMigration == nil || c.modeMigration.SchemaBefore != "" || c.DataPlane.DPIMode != "monitor" {
		t.Fatalf("versionless mode migration missing: %+v", c.modeMigration)
	}
	// An unstamped body does not assert an old IDS schema. As before, POST
	// validation must reject unsupported legacy predicates, not rewrite them.
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), `proto "enip"`) {
		t.Fatalf("unsupported unstamped IDS predicate was accepted: %v", err)
	}
}

func TestRuleModesImportRollbackAndTransactionFailure(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	original := DefaultConfig()
	original.SchemaVersion = SchemaVersionCurrent
	if err := s.Save(ctx, original); err != nil {
		t.Fatal(err)
	}
	c := legacyModes("")
	// Validate-before-save matches import. The outbox appears only on persistence.
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if recs, err := s.RuleModeMigrations(ctx); err != nil || len(recs) != 0 {
		t.Fatal(recs, err)
	}
	if err := s.SaveCandidate(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitConfirmed(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || len(got.Firewall.Rules) != len(original.Firewall.Rules) {
		t.Fatalf("rollback: %+v %v", got, err)
	}
	before, err := s.RuleModeMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bad := legacyModes("")
	bad.Firewall.Rules[0].ICS.Protocol = "invalid"
	if err := s.SaveCandidate(ctx, bad); err == nil {
		t.Fatal("invalid import saved")
	}
	after, err := s.RuleModeMigrations(ctx)
	if err != nil || len(after) != len(before) {
		t.Fatal("rejected import audited", after, err)
	}
	// Force the outbox write itself to fail after the bank write started.
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_modes BEFORE INSERT ON configs WHEN NEW.key = 'rule_mode_migration_019' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCandidate(ctx, legacyModes("0.1.8")); err == nil {
		t.Fatal("transaction failure ignored")
	}
	after, err = s.RuleModeMigrations(ctx)
	if err != nil || len(after) != len(before) {
		t.Fatal("failed transaction audited", after, err)
	}
}

func TestRuleModesBootStampsUnchangedBanks(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	c := DefaultConfig()
	c.SchemaVersion = "0.1.8"
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`REPLACE INTO configs(key,data,updated_at) VALUES(?,?,0)`, configKeyRunning, string(blob)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MigrateIndustrialScope(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := readKindUnupgradedFrom(ctx, s.db, configKeyRunning, false)
	if err != nil || got.SchemaVersion != SchemaVersionCurrent {
		t.Fatal(got, err)
	}
	recs, err := s.RuleModeMigrations(ctx)
	if err != nil || len(recs) != 0 {
		t.Fatal(recs, err)
	}
}

func TestRuleModesUpgradeBeforeExpiredRollback(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		cfg := legacyModes("0.1.7")
		cfg.System.Hostname = bank
		if err = writeConfigTx(ctx, tx, bank, cfg); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,0)`, configKeyPending, string(pending)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := s.Load(ctx)
	if err != nil || cfg.System.Hostname != configKeyPrevious || cfg.SchemaVersion != SchemaVersionCurrent || cfg.Firewall.Rules[1].ICS.Mode != "monitor" {
		t.Fatalf("rollback=%+v err=%v", cfg, err)
	}
	recs, err := s.RuleModeMigrations(ctx)
	if err != nil || len(recs) != 3 {
		t.Fatalf("banks not migrated before rollback: %+v %v", recs, err)
	}
}
