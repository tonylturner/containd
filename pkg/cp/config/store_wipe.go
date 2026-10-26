// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"fmt"
)

func wipeAllTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs`); err != nil {
		return fmt.Errorf("wipe configs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ids_rules`); err != nil {
		return fmt.Errorf("wipe ids_rules: %w", err)
	}
	return nil
}

// resetLocked atomically clears history and replaces running and its IDS bank.
// A failed transaction leaves the pending timer intact.
func (s *SQLiteStore) resetLocked(ctx context.Context, defaults *Config) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := wipeAllTx(ctx, tx); err != nil {
		return err
	}
	if err := writeRunningTx(ctx, tx, defaults); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.stopPendingTimerLocked()
	return nil
}
