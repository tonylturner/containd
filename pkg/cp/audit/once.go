// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"context"
	"time"
)

// AddOnce delivers a durable outbox record idempotently, including when a
// process exits between the audit write and the next boot.
func (s *SQLiteStore) AddOnce(ctx context.Context, key string, r Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS delivered_records (key TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO delivered_records (key) VALUES (?)`, key)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 0 {
		if r.Timestamp.IsZero() {
			r.Timestamp = time.Now().UTC()
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO audit_records (ts,actor,source,action,target,result,detail) VALUES (?,?,?,?,?,?,?)`,
			r.Timestamp.Unix(), r.Actor, r.Source, r.Action, r.Target, r.Result, r.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}
