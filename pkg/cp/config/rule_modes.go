// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const ruleModeMigrationKey = "rule_mode_migration_019"

type RuleModeChange struct {
	Path   string `json:"path"`
	RuleID string `json:"ruleId,omitempty"`
	Action string `json:"action"`
	Old    string `json:"old"`
	New    string `json:"new"`
}

type RuleModeMigration struct {
	ID           uint64           `json:"id"`
	Timestamp    time.Time        `json:"timestamp"`
	Bank         string           `json:"bank"`
	SchemaBefore string           `json:"schemaBefore"`
	SchemaAfter  string           `json:"schemaAfter"`
	Changes      []RuleModeChange `json:"changes"`
}

func beforeRuleModes(schema string) bool {
	v, err := parseSemver(schema)
	return schema == "" || err == nil && compareSemver(v, semver{minor: 1, patch: 9}) < 0
}

func upgradeRuleModes019(cfg *Config, originalSchema string) {
	rec := &RuleModeMigration{Timestamp: time.Now().UTC(), SchemaBefore: originalSchema, SchemaAfter: "0.1.9"}
	rec.ID = uint64(rec.Timestamp.UnixNano())
	if cfg.DataPlane.DPIMode == "learn" {
		rec.Changes = append(rec.Changes, RuleModeChange{Path: "dataplane.dpiMode", Action: "rewrite", Old: "learn", New: "monitor"})
		cfg.DataPlane.DPIMode = "monitor"
	}
	for i := range cfg.Firewall.Rules {
		r := &cfg.Firewall.Rules[i]
		old := r.ICS.Mode
		action := "rewrite"
		if old == "" {
			continue
		}
		if r.ICS.Protocol == "" {
			r.ICS.Mode = ""
			action = "clear"
		} else if old == "learn" {
			r.ICS.Mode = "monitor"
		} else {
			continue
		}
		rec.Changes = append(rec.Changes, RuleModeChange{Path: fmt.Sprintf("firewall.rules[%s].ics.mode", r.ID), RuleID: r.ID, Action: action, Old: old, New: r.ICS.Mode})
	}
	if len(rec.Changes) > 0 {
		cfg.modeMigration = rec
	}
}

func persistRuleModeMigrationTx(ctx context.Context, tx *sql.Tx, bank string, rec *RuleModeMigration) error {
	if rec == nil {
		return nil
	}
	records, err := readRuleModeMigrations(ctx, tx)
	if err != nil {
		return err
	}
	for _, old := range records {
		if old.ID == rec.ID && old.Bank == bank {
			return nil
		}
	}
	copy := *rec
	copy.Bank = bank
	records = append(records, copy)
	blob, err := json.Marshal(records)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, ruleModeMigrationKey, string(blob), rec.Timestamp.Unix())
	return err
}

func readRuleModeMigrations(ctx context.Context, db configReader) ([]RuleModeMigration, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, ruleModeMigrationKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []RuleModeMigration
	err = json.Unmarshal([]byte(raw), &records)
	return records, err
}

func (s *SQLiteStore) RuleModeMigrations(ctx context.Context) ([]RuleModeMigration, error) {
	return readRuleModeMigrations(ctx, s.db)
}
