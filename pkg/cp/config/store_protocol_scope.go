// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// IndustrialScopeMigration is the durable audit/event outbox written in the
// same transaction as the migrated banks. Reads and subsequent boots never
// create another record for already migrated snapshots.
type IndustrialScopeMigration struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Removed   []string  `json:"removed"`
}

const industrialScopeMigrationKey = "industrial_scope_migration_018"

// MigrateIndustrialScope runs at store open, before boot repair or rollback.
// It deliberately does not validate: incompatible configs remain exportable
// and management decides recovery using the ordinary validation path.
func (s *SQLiteStore) MigrateIndustrialScope(ctx context.Context) (*IndustrialScopeMigration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	removed := map[string]bool{}
	for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		cfg, err := readKindUnupgradedFrom(ctx, tx, key, false)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !beforeIndustrialScope(cfg.SchemaVersion) {
			continue
		}
		// The config row omits the separately referenced bank. Inspect that
		// actual bank only for snapshots eligible for this migration.
		cfg, err = readKindUnupgradedFrom(ctx, tx, key, true)
		if err != nil {
			return nil, err
		}
		ids := removeRetiredBuiltins(cfg)
		if len(ids) == 0 {
			continue
		}
		for _, id := range ids {
			removed[id] = true
		}
		if err := UpgradeInPlace(cfg); err != nil {
			return nil, err
		}
		if key == configKeyRunning {
			if err := replaceIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
				return nil, err
			}
		}
		if err := writeConfigTx(ctx, tx, key, cfg); err != nil {
			return nil, err
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	record := IndustrialScopeMigration{ID: uint64(now.UnixNano()), Timestamp: now}
	for id := range removed {
		record.Removed = append(record.Removed, id)
	}
	sort.Strings(record.Removed)
	// The outbox is append-only: restoring another old bank must not erase a
	// previous migration's audit evidence.
	var records []IndustrialScopeMigration
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, industrialScopeMigrationKey).Scan(&raw)
	if err == nil {
		if err := json.Unmarshal([]byte(raw), &records); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	records = append(records, record)
	blob, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, industrialScopeMigrationKey, string(blob), now.Unix()); err != nil {
		return nil, err
	}
	if err := s.commitStateTx(ctx, tx); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *SQLiteStore) IndustrialScopeMigrations(ctx context.Context) ([]IndustrialScopeMigration, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, industrialScopeMigrationKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []IndustrialScopeMigration
	err = json.Unmarshal([]byte(raw), &records)
	return records, err
}

func removeRetiredBuiltins(cfg *Config) []string {
	if !beforeIndustrialScope(cfg.SchemaVersion) {
		return nil
	}
	var ids []string
	kept := make([]IDSRule, 0, len(cfg.IDS.Rules))
	for _, rule := range cfg.IDS.Rules {
		matched := false
		for _, stock := range retiredBuiltinDefinitions() {
			if rule.ID == stock.ID && sameBuiltin(rule, stock) {
				matched = true
				break
			}
		}
		if matched {
			ids = append(ids, rule.ID)
		} else {
			kept = append(kept, rule)
		}
	}
	if len(ids) > 0 {
		cfg.IDS.Rules = kept
	}
	return ids
}

func beforeIndustrialScope(schema string) bool {
	version, err := parseSemver(schema)
	return err == nil && compareSemver(version, semver{patch: 8, minor: 1}) < 0
}

func sameBuiltin(a, b IDSRule) bool {
	a.Enabled, b.Enabled = nil, nil
	// Compare the complete persisted content, including metadata. JSON also
	// normalizes numeric values loaded through interface fields from SQLite.
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}
