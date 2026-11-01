// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Generations are immutable. Config rows own references; state transactions
// reclaim unreferenced generations unless an apply is holding recovery rows.
func createBankTx(ctx context.Context, tx *sql.Tx, rules []IDSRule) (int64, error) {
	if rules == nil {
		rules = []IDSRule{}
	}
	blob, err := json.Marshal(rules)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO ids_banks (data) VALUES (?)`, string(blob))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func bankReference(ctx context.Context, db configReader, key string) (int64, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var metadata struct {
		BankID int64 `json:"ids_bank"`
	}
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return 0, err
	}
	return metadata.BankID, nil
}

func loadBankFrom(ctx context.Context, db configReader, id int64) ([]IDSRule, error) {
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT data FROM ids_banks WHERE id = ?`, id).Scan(&raw); err != nil {
		return nil, fmt.Errorf("load IDS bank %d: %w", id, err)
	}
	var rules []IDSRule
	err := json.Unmarshal([]byte(raw), &rules)
	return rules, err
}

// Extraction is one transaction across running, candidate and previous. Keep
// unknown document fields intact and preserve authoritative empty banks.
func (s *SQLiteStore) extractBanks(ctx context.Context) error {
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	changed := false
	runningID, err := bankReference(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	for _, key := range []string{configKeyRunning, configKeyCandidate, configKeyPrevious} {
		var raw string
		err := tx.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		var stored storedConfig
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return err
		}
		if stored.BankID != 0 {
			continue
		}
		if stored.SnapshotFormat == snapshotFormatReferencedBank {
			return fmt.Errorf("%s snapshot has no IDS bank reference", key)
		}
		id := runningID
		rules := stored.IDS.Rules
		if key == configKeyRunning {
			bank, err := loadIDSRulesFrom(ctx, tx)
			if err != nil {
				return err
			}
			if len(bank) > 0 || rules == nil {
				rules = bank
			} else if err := replaceIDSRulesTx(ctx, tx, rules); err != nil {
				return err
			}
		}
		if key == configKeyRunning || stored.SnapshotFormat == snapshotFormatEmbeddedBank || id == 0 {
			id, err = createBankTx(ctx, tx, rules)
			if err != nil {
				return err
			}
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			return err
		}
		if fields == nil {
			return fmt.Errorf("decode %s snapshot: expected an object", key)
		}
		var ids map[string]json.RawMessage
		if value := fields["ids"]; len(value) > 0 && string(value) != "null" {
			if err := json.Unmarshal(value, &ids); err != nil {
				return err
			}
		}
		if ids == nil {
			ids = map[string]json.RawMessage{}
		}
		delete(ids, "rules")
		fields["ids"], err = json.Marshal(ids)
		if err != nil {
			return err
		}
		fields["ids_bank"] = json.RawMessage(fmt.Sprint(id))
		fields["snapshot_format"] = json.RawMessage(fmt.Sprint(snapshotFormatReferencedBank))
		blob, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		changed = true
		if _, err := tx.ExecContext(ctx, `UPDATE configs SET data = ? WHERE key = ?`, string(blob), key); err != nil {
			return err
		}
		if key == configKeyRunning {
			runningID = id
		}
	}
	if changed {
		_, err = s.commitRevisionTx(ctx, tx)
		return err
	}
	return s.commitStateTx(ctx, tx)
}
