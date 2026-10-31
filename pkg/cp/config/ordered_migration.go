// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

const orderedPolicyMigrationKey = "ordered_policy_migration_0110"

// OrderedPolicyMigration is the transactional outbox for order upgrades and
// partial-overlap publication warnings. Kind is "upgrade" or "publish".
type OrderedPolicyMigration struct {
	ID           uint64                `json:"id"`
	Timestamp    time.Time             `json:"timestamp"`
	Bank         string                `json:"bank"`
	Kind         string                `json:"kind"`
	SchemaBefore string                `json:"schemaBefore"`
	SchemaAfter  string                `json:"schemaAfter"`
	Before       []string              `json:"before"`
	After        []string              `json:"after"`
	Forwards     []ForwardPlacement    `json:"forwards,omitempty"`
	Warnings     []ForwardGrantWarning `json:"warnings,omitempty"`
}

func beforeOrderedPolicy(schema string) bool {
	v, err := parseSemver(schema)
	return schema == "" || err == nil && compareSemver(v, semver{minor: 1, patch: 10}) < 0
}

func policyRuleIDs(cfg *Config) []string {
	out := make([]string, 0, len(cfg.Firewall.Rules))
	for _, r := range cfg.Firewall.Rules {
		out = append(out, r.ID)
	}
	return out
}

func newOrderedRecord(kind, schema string) *OrderedPolicyMigration {
	now := time.Now().UTC()
	return &OrderedPolicyMigration{ID: uint64(now.UnixNano()), Timestamp: now, Kind: kind,
		SchemaBefore: schema, SchemaAfter: SchemaVersionCurrent}
}

func upgradeOrderedPolicy010(cfg *Config, originalSchema string) {
	rec := newOrderedRecord("upgrade", originalSchema)
	rec.Before = policyRuleIDs(cfg)
	entries := make([]rules.Entry, len(cfg.Firewall.Rules))
	for i, r := range cfg.Firewall.Rules {
		entries[i] = rules.Entry{ID: r.ID, Action: rules.Action(r.Action)}
	}
	order := rules.DecisionOrder(entries)
	old := slices.Clone(cfg.Firewall.Rules)
	next := 0
	for i, r := range old {
		if rules.Action(r.Action).Decides() {
			cfg.Firewall.Rules[i] = old[order[next]]
			next++
		}
	}
	// Legacy validation ignored empty elements, including an all-empty list
	// meaning unrestricted. Remove only those elements before strict 0.1.10
	// validation; current-schema empty strings must still fail.
	for i := range cfg.Firewall.NAT.PortForwards {
		f := &cfg.Firewall.NAT.PortForwards[i]
		f.AllowedSources = slices.DeleteFunc(slices.Clone(f.AllowedSources), func(s string) bool {
			return strings.TrimSpace(s) == ""
		})
	}
	for _, f := range sortedForwards(cfg) {
		p := ForwardAllowPlacement(cfg, f)
		rec.Forwards = append(rec.Forwards, p)
		if p.Rule != nil {
			cfg.Firewall.Rules = slices.Insert(cfg.Firewall.Rules, p.Index, *p.Rule)
		}
	}
	rec.After = policyRuleIDs(cfg)
	rec.Warnings = ForwardWarnings(cfg)
	cfg.orderMigration = rec
}

func readOrderedPolicyMigrations(ctx context.Context, db configReader) ([]OrderedPolicyMigration, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, orderedPolicyMigrationKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []OrderedPolicyMigration
	err = json.Unmarshal([]byte(raw), &records)
	return records, err
}

func (s *SQLiteStore) OrderedPolicyMigrations(ctx context.Context) ([]OrderedPolicyMigration, error) {
	return readOrderedPolicyMigrations(ctx, s.db)
}

func persistOrderedPolicyTx(ctx context.Context, tx *sql.Tx, bank string, cfg *Config) error {
	rec := cfg.orderMigration
	if rec == nil {
		if cfg.SchemaVersion != SchemaVersionCurrent {
			return nil
		}
		warnings := ForwardWarnings(cfg)
		if len(warnings) == 0 {
			return nil
		}
		previous, err := readKindUnupgradedFrom(ctx, tx, bank, false)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if previous != nil {
			before, err := json.Marshal(ForwardWarnings(previous))
			if err != nil {
				return err
			}
			after, err := json.Marshal(warnings)
			if err != nil {
				return err
			}
			if string(before) == string(after) {
				return nil
			}
		}
		rec = newOrderedRecord("publish", cfg.SchemaVersion)
		rec.Warnings = warnings
		rec.After = policyRuleIDs(cfg)
		if previous != nil {
			rec.Before = policyRuleIDs(previous)
		}
	}
	records, err := readOrderedPolicyMigrations(ctx, tx)
	if err != nil {
		return err
	}
	for _, old := range records {
		if old.ID == rec.ID && old.Bank == bank {
			return nil
		}
	}
	detached := *rec
	detached.Bank = bank
	records = append(records, detached)
	blob, err := json.Marshal(records)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`,
		orderedPolicyMigrationKey, string(blob), rec.Timestamp.Unix())
	return err
}
