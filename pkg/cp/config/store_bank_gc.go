// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"fmt"
)

// commitStateTx collects in the transaction that changes the references. Only
// metadata in configs is inspected, never the bank contents. Fault rows can
// contain non-JSON text; they do not reference banks. Missing references become
// zero rather than NULL, so NOT IN cannot accidentally retain every generation.
// Callers hold mu (or are booting before the store is made available).
func (s *SQLiteStore) commitStateTx(ctx context.Context, tx *sql.Tx) error {
	if !s.recoveryHoldsBanks {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ids_banks WHERE id NOT IN (
   SELECT COALESCE(CASE WHEN json_valid(data) THEN json_extract(data, '$.ids_bank') END, 0)
   FROM configs
  )`); err != nil {
			return fmt.Errorf("reclaim IDS banks: %w", err)
		}
	}
	return tx.Commit()
}

// finishBankRecoveryLocked releases the saved-row hold only after apply or
// restoration/reapply has finished. mu still excludes writers and expiry. A
// failed sweep rolls back atomically, leaving all saved generations available
// if the caller needs to compensate. Freed SQLite pages are reused by imports.
func (s *SQLiteStore) finishBankRecoveryLocked(ctx context.Context) error {
	s.recoveryHoldsBanks = false
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	return s.commitStateTx(ctx, tx)
}
