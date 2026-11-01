// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func installOrderedLegacyBanks(t *testing.T, s *SQLiteStore, empty []string) map[string]int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	ids := map[string]int64{}
	for _, bank := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		c := placementConfig("partial")
		c.SchemaVersion = "0.1.9"
		c.System.Hostname = bank
		c.Firewall.NAT.PortForwards[0].AllowedSources = empty
		c.Firewall.Rules = append([]Rule{{ID: "z-deny", Action: ActionDeny}}, c.Firewall.Rules...)
		c.IDS.Rules = []IDSRule{{ID: "custom-" + bank, Action: "alert", Proto: "tcp"}}
		if err := writeConfigTx(ctx, tx, bank, c); err != nil {
			t.Fatal(err)
		}
		ids[bank], err = bankReference(ctx, tx, bank)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestOrderedStoreOpenNormalizesLegacySourcesAndKeepsBanks(t *testing.T) {
	for _, sources := range [][]string{{"", " \t"}, {"", "198.51.100.0/24", " "}} {
		t.Run(fmt.Sprint(sources), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			ids := installOrderedLegacyBanks(t, s, sources)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			for boot := range 2 {
				s, err = NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				for bank, id := range ids {
					c, err := readKindUnupgradedFrom(ctx, s.db, bank, true)
					if err != nil {
						t.Fatal(err)
					}
					if c.SchemaVersion != "0.1.10" || !reflect.DeepEqual(policyRuleIDs(c), []string{"reads", "z-deny"}) {
						t.Fatalf("bank %s not durably migrated: %+v", bank, c)
					}
					wantSources := slices.DeleteFunc(slices.Clone(sources), func(s string) bool { return s == "" || s == " \t" || s == " " })
					if !reflect.DeepEqual(c.Firewall.NAT.PortForwards[0].AllowedSources, wantSources) &&
						!(len(wantSources) == 0 && len(c.Firewall.NAT.PortForwards[0].AllowedSources) == 0) {
						t.Fatal("normalization changed restrictions", c.Firewall.NAT.PortForwards)
					}
					if err := c.Validate(); err != nil {
						t.Fatal("stored 0.1.9 no longer opens/validates", err)
					}
					gotID, err := bankReference(ctx, s.db, bank)
					if err != nil || gotID != id || c.IDS.Rules[0].ID != "custom-"+bank {
						t.Fatalf("IDS bank identity changed: %d -> %d, %v", id, gotID, err)
					}
				}
				recs, err := s.OrderedPolicyMigrations(ctx)
				if err != nil || len(recs) != 3 {
					t.Fatalf("boot %d records: %+v %v", boot, recs, err)
				}
				for _, rec := range recs {
					if rec.SchemaBefore != "0.1.9" || rec.SchemaAfter != "0.1.10" ||
						!reflect.DeepEqual(rec.Before, []string{"z-deny", "reads"}) ||
						len(rec.Forwards) != 1 || rec.Forwards[0].Overlap != "partial" || len(rec.Warnings) != 1 {
						t.Fatalf("incomplete durable evidence: %+v", rec)
					}
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOrderedStoreBootTransactionIsAtomic(t *testing.T) {
	for _, target := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious, orderedPolicyMigrationKey} {
		t.Run(target, func(t *testing.T) {
			ctx := context.Background()
			s := candidateStore(t)
			ids := installOrderedLegacyBanks(t, s, nil)
			trigger := fmt.Sprintf("CREATE TRIGGER refuse_ordered_bank BEFORE INSERT ON configs WHEN NEW.key = '%s' BEGIN SELECT RAISE(ABORT, 'test failure'); END", target)
			if _, err := s.db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			if _, err := s.MigrateIndustrialScope(ctx); err == nil {
				t.Fatal("failed migration transaction succeeded")
			}
			for bank, id := range ids {
				c, err := readKindUnupgradedFrom(ctx, s.db, bank, false)
				if err != nil || c.SchemaVersion != "0.1.9" || c.Firewall.Rules[0].ID != "z-deny" {
					t.Fatal("partial bank migration persisted", bank, c, err)
				}
				got, err := bankReference(ctx, s.db, bank)
				if err != nil || got != id {
					t.Fatal("bank reference changed", bank, got, err)
				}
			}
			recs, err := s.OrderedPolicyMigrations(ctx)
			if err != nil || len(recs) != 0 {
				t.Fatal("audit survived failed transaction", recs, err)
			}
		})
	}
}

func TestOrderedStoreRepeatedImportsAndCurrentOrder(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	for _, stamp := range []string{"", "0.1.0", "0.1.9"} {
		for range 2 {
			c := placementConfig("no-overlap")
			c.SchemaVersion = stamp
			c.Firewall.Rules = append([]Rule{{ID: "z-deny", Action: ActionDeny}}, c.Firewall.Rules...)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := testSaveCandidate(s, ctx, c); err != nil {
				t.Fatal(err)
			}
			gotSnapshot1, err := s.ReadSnapshot(ctx, SnapshotCandidate, true)
			got := gotSnapshot1.Candidate
			if err != nil || !reflect.DeepEqual(policyRuleIDs(got), []string{"pf-process", "reads", "z-deny"}) {
				t.Fatal("legacy POST/import order lost", got, err)
			}
		}
	}
	c := placementConfig("no-overlap")
	c.Firewall.Rules = append([]Rule{{ID: "operator-deny", Action: ActionDeny}}, c.Firewall.Rules...)
	if err := testSaveCandidate(s, ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := testCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || !reflect.DeepEqual(policyRuleIDs(got), []string{"operator-deny", "reads"}) {
		t.Fatal("current-schema order/deleted grant not preserved", got, err)
	}
}

func TestOrderedStorePlacementAtUpgradeAndPublish(t *testing.T) {
	for _, path := range []string{"upgrade", "publish"} {
		for _, kind := range []string{"inside", "partial", "no-overlap"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				s := candidateStore(t)
				ctx := context.Background()
				c := placementConfig(kind)
				if path == "upgrade" {
					c.SchemaVersion = "0.1.9"
				} else {
					p := ForwardAllowPlacement(c, c.Firewall.NAT.PortForwards[0])
					if p.Rule != nil {
						c.Firewall.Rules = slices.Insert(c.Firewall.Rules, p.Index, *p.Rule)
					}
				}
				for range 2 {
					if err := testSaveCandidate(s, ctx, c); err != nil {
						t.Fatal(err)
					}
				}
				recs, err := s.OrderedPolicyMigrations(ctx)
				wantRecords := 0
				if path == "upgrade" || kind == "partial" {
					wantRecords = 1
				}
				if err != nil || len(recs) != wantRecords {
					t.Fatal("outbox missing or duplicated", recs, err)
				}
				if kind == "partial" && (len(recs[0].Warnings) != 1 || recs[0].Warnings[0].RuleIDs[0] != "reads") {
					t.Fatal("partial overlap not durably warned", recs)
				}
				gotSnapshot2, err := s.ReadSnapshot(ctx, SnapshotCandidate, true)
				got := gotSnapshot2.Candidate
				wantRules := 1
				if kind == "no-overlap" {
					wantRules = 2
				}
				if err != nil || len(got.Firewall.Rules) != wantRules {
					t.Fatal(got, err)
				}
			})
		}
	}
}

func TestOrderedStoreConfirmedRollbackAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			c := placementConfig("no-overlap")
			c.SchemaVersion = "0.1.9"
			if err := s.Save(ctx, c); err != nil {
				t.Fatal(err)
			}
			candidate := placementConfig("partial")
			if err := testSaveCandidate(s, ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
				t.Fatal(err)
			}
			if expiry {
				pending, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`REPLACE INTO configs(key,data,updated_at) VALUES(?,?,0)`, configKeyPending, string(pending)); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
			} else if err := testRollback(s, ctx); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.Load(ctx)
			if err != nil || got.SchemaVersion != "0.1.10" || got.Firewall.Rules[0].ID != "pf-process" {
				t.Fatal("upgraded rollback snapshot lost", got, err)
			}
		})
	}
}

func TestOrderedStorePromotesAndRollsBackDetachedLegacyBanks(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	installOrderedLegacyBanks(t, s, nil)
	// These raw rows appeared after open, so promotion itself must durably pin
	// the detached upgrade, not just upgrade the config returned to a caller.
	if err := testCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	for _, bank := range []string{configKeyRunning, configKeyPrevious} {
		got, err := readKindUnupgradedFrom(ctx, s.db, bank, false)
		if err != nil || got.SchemaVersion != "0.1.10" || got.Firewall.Rules[0].ID != "reads" {
			t.Fatal("promotion did not pin upgrade", bank, got, err)
		}
	}
	recs, err := s.OrderedPolicyMigrations(ctx)
	if err != nil || len(recs) != 3 {
		t.Fatal("promotion lost candidate/running/previous evidence", recs, err)
	}
	previous := placementConfig("no-overlap")
	previous.SchemaVersion = "0.1.9"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := writeConfigTx(ctx, tx, configKeyPrevious, previous); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := testRollback(s, ctx); err != nil {
		t.Fatal(err)
	}
	for _, bank := range []string{configKeyRunning, configKeyPrevious} {
		got, err := readKindUnupgradedFrom(ctx, s.db, bank, false)
		if err != nil || got.SchemaVersion != "0.1.10" || got.Firewall.Rules[0].ID != "pf-process" {
			t.Fatal("rollback did not pin upgrade", bank, got, err)
		}
	}
}

func TestOrderedStorePublishWarningFailureIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := candidateStore(t)
	if err := testSaveCandidate(s, ctx, placementConfig("inside")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_ordered_warning BEFORE INSERT ON configs WHEN NEW.key = 'ordered_policy_migration_0110' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := testSaveCandidate(s, ctx, placementConfig("partial")); err == nil {
		t.Fatal("warning failure was ignored")
	}
	gotSnapshot3, err := s.ReadSnapshot(ctx, SnapshotCandidate, true)
	got := gotSnapshot3.Candidate
	if err != nil || len(ForwardWarnings(got)) != 0 {
		t.Fatal("config published without durable warning", got, err)
	}
}
