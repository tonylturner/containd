// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

const (
	// Legacy snapshots did not own the separately deployed bank.
	snapshotFormatBankUnchanged  = 1
	snapshotFormatEmbeddedBank   = 2
	snapshotFormatReferencedBank = 3
)

// Storage metadata is not part of Config or its public wire representation.
type storedConfig struct {
	Config
	SnapshotFormat int   `json:"snapshot_format,omitempty"`
	BankID         int64 `json:"ids_bank,omitempty"`
}

// upgradeSnapshots classifies legacy snapshots before bank extraction and
// pending-deadline handling. The marker distinguishes inherited banks from
// authoritative empty embedded banks; slice nilness cannot make that decision.
func (s *SQLiteStore) upgradeSnapshots(ctx context.Context) error {
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	changed := false
	for _, key := range []string{configKeyCandidate, configKeyPrevious} {
		var raw string
		err := tx.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, key).Scan(&raw)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		// Preserve all existing fields during the storage-only migration.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			return fmt.Errorf("decode %s snapshot: %w", key, err)
		}
		if fields == nil {
			return fmt.Errorf("decode %s snapshot: expected an object", key)
		}
		var format int
		if value, ok := fields["snapshot_format"]; ok {
			if err := json.Unmarshal(value, &format); err != nil {
				return err
			}
		}
		switch format {
		case 0:
			format = snapshotFormatBankUnchanged
			// Preserve banks already embedded by pre-marker development builds.
			// Old releases omitted rules (or wrote null); a serialized rules
			// array is an embedded bank, including an explicit [].
			var ids map[string]json.RawMessage
			if rawIDS, ok := fields["ids"]; ok {
				if err := json.Unmarshal(rawIDS, &ids); err != nil {
					return err
				}
			}
			if rules, present := ids["rules"]; present && string(rules) != "null" {
				format = snapshotFormatEmbeddedBank
			}
			fields["snapshot_format"] = json.RawMessage(fmt.Sprint(format))
			blob, err := json.Marshal(fields)
			if err != nil {
				return err
			}
			changed = true
			if _, err := tx.ExecContext(ctx, `UPDATE configs SET data = ? WHERE key = ?`, string(blob), key); err != nil {
				return err
			}
		case snapshotFormatBankUnchanged, snapshotFormatEmbeddedBank, snapshotFormatReferencedBank:
		default:
			return fmt.Errorf("unsupported %s snapshot format %d", key, format)
		}
	}
	if changed {
		_, err = s.commitRevisionTx(ctx, tx)
		return err
	}
	return s.commitStateTx(ctx, tx)
}
