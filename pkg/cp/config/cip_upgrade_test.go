// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"testing"
)

func TestProtocolScopeCIPUpgrade(t *testing.T) {
	for _, version := range []string{"0.1.7", SchemaVersionCurrent} {
		for _, edited := range []bool{false, true} {
			for _, enabled := range []*bool{nil, boolRef(true), boolRef(false)} {
				cfg := DefaultConfig()
				cfg.SchemaVersion = version
				cfg.IDS.Rules = historicalCIPBuiltinDefinitions()
				cfg.IDS.Rules[0].Enabled = enabled
				if edited {
					cfg.IDS.Rules[0].Description += " operator edit"
				}
				if err := UpgradeInPlace(cfg); err != nil {
					t.Fatal(err)
				}
				err := cfg.Validate()
				invalid := edited || version == SchemaVersionCurrent
				if invalid != (err != nil) {
					t.Fatalf("edited=%t schema=%s validation=%v", edited, version, err)
				}
				for i, rule := range cfg.IDS.Rules {
					want := "enip"
					if version == "0.1.7" && (i != 0 || !edited) {
						want = "cip"
					}
					if rule.Proto != want {
						t.Fatalf("schema=%s edited=%t rule=%+v", version, edited, rule)
					}
				}
				if cfg.IDS.Rules[0].Enabled != enabled {
					t.Fatal("enabled changed")
				}
				if version == SchemaVersionCurrent && cfg.scopeMigration != nil {
					t.Fatal("current schema migrated")
				}
			}
		}
	}
	// Combined evidence is persisted once; custom enip references are refused.
	s := candidateStore(t)
	cfg := DefaultConfig()
	cfg.SchemaVersion = "0.1.7"
	cfg.IDS.Rules = historicalCIPBuiltinDefinitions()
	cfg.IDS.Rules = append(cfg.IDS.Rules, retiredBuiltinDefinitions()...)
	if err := s.SaveCandidate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	records, err := s.IndustrialScopeMigrations(context.Background())
	if err != nil || len(records) != 1 || len(records[0].Removed) != 5 || len(records[0].Updated) != 2 {
		t.Fatalf("combined migration: %+v %v", records, err)
	}
	got, err := s.LoadCandidate(context.Background())
	if err != nil || len(got.IDS.Rules) != 2 || got.IDS.Rules[0].Proto != "cip" {
		t.Fatalf("staged: %+v %v", got, err)
	}
	custom := DefaultConfig()
	custom.SchemaVersion = "0.1.7"
	custom.IDS.Rules = []IDSRule{{ID: "custom", Proto: "enip"}}
	if err := s.SaveCandidate(context.Background(), custom); err == nil || err.Error() != `ids rule custom proto "enip": EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command` {
		t.Fatalf("custom accepted: %v", err)
	}
	if custom.IDS.Rules[0].Proto != "enip" {
		t.Fatal("custom silently rewritten")
	}
}

func TestProtocolScopeCIPStoreOpen(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(map[bool]string{false: "stock", true: "edited"}[edited], func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			cfg := DefaultConfig()
			cfg.SchemaVersion = "0.1.7"
			cfg.IDS.Rules = historicalCIPBuiltinDefinitions()
			if edited {
				cfg.IDS.Rules[0].Title += " edited"
			}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := replaceIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				if err := writeConfigTx(ctx, tx, key, cfg); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var path string
			if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			records, err := s.IndustrialScopeMigrations(ctx)
			want := 2
			if edited {
				want--
			}
			if err != nil || len(records) != 1 || len(records[0].Removed) != 0 || len(records[0].Updated) != want {
				t.Fatalf("updated-only outbox: %+v %v", records, err)
			}
			for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
				got, err := s.loadKind(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				if err := got.Validate(); edited != (err != nil) {
					t.Fatalf("edited=%t validation=%v", edited, err)
				}
			}
			if again, err := s.MigrateIndustrialScope(ctx); err != nil || again != nil {
				t.Fatalf("repeated migration: %+v %v", again, err)
			}
		})
	}
}
