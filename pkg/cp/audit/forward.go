// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ForwardLog reads audit records in ID order for off-box forwarders and keeps
// each forwarder's delivery cursor in the audit database. A cursor holds the
// highest record ID its consumer has delivered.
type ForwardLog interface {
	// ListAfter returns at most limit records with an ID above afterID,
	// oldest first.
	ListAfter(ctx context.Context, afterID int64, limit int) ([]Record, error)
	// CountAfter returns the number of records with an ID above afterID.
	CountAfter(ctx context.Context, afterID int64) (int, error)
	// ForwardCursor returns the consumer's cursor; ok is false when none exists.
	ForwardCursor(ctx context.Context, consumer string) (id int64, ok bool, err error)
	// StartForwardCursor creates the consumer's cursor at the newest record,
	// so a new consumer skips history. An existing cursor is kept.
	StartForwardCursor(ctx context.Context, consumer string) error
	// AdvanceForwardCursor moves an existing cursor forward to id. It never
	// moves a cursor backwards and never creates one.
	AdvanceForwardCursor(ctx context.Context, consumer string, id int64) error
	// RetainForwardCursors deletes the cursors whose consumer starts with
	// prefix and is not listed in keep.
	RetainForwardCursors(ctx context.Context, prefix string, keep []string) error
}

var _ ForwardLog = (*SQLiteStore)(nil)

func (s *SQLiteStore) ListAfter(ctx context.Context, afterID int64, limit int) ([]Record, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("list audit records after %d: limit must be positive", afterID)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordColumns+` FROM audit_records WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit records after %d: %w", afterID, err)
	}
	return scanRecords(rows)
}

func (s *SQLiteStore) CountAfter(ctx context.Context, afterID int64) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_records WHERE id > ?`, afterID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count audit records after %d: %w", afterID, err)
	}
	return n, nil
}

func (s *SQLiteStore) ForwardCursor(ctx context.Context, consumer string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT last_id FROM forward_cursors WHERE consumer = ?`, consumer).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read audit forward cursor %q: %w", consumer, err)
	}
	return id, true, nil
}

func (s *SQLiteStore) StartForwardCursor(ctx context.Context, consumer string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO forward_cursors (consumer, last_id) SELECT ?, COALESCE(MAX(id), 0) FROM audit_records`, consumer)
	if err != nil {
		return fmt.Errorf("start audit forward cursor %q: %w", consumer, err)
	}
	return nil
}

func (s *SQLiteStore) AdvanceForwardCursor(ctx context.Context, consumer string, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE forward_cursors SET last_id = ? WHERE consumer = ? AND last_id < ?`, id, consumer, id)
	if err != nil {
		return fmt.Errorf("advance audit forward cursor %q: %w", consumer, err)
	}
	return nil
}

func (s *SQLiteStore) RetainForwardCursors(ctx context.Context, prefix string, keep []string) error {
	consumers, err := s.forwardConsumers(ctx, prefix)
	if err != nil {
		return err
	}
	kept := make(map[string]bool, len(keep))
	for _, k := range keep {
		kept[k] = true
	}
	for _, consumer := range consumers {
		if kept[consumer] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM forward_cursors WHERE consumer = ?`, consumer); err != nil {
			return fmt.Errorf("drop audit forward cursor %q: %w", consumer, err)
		}
	}
	return nil
}

// forwardConsumers lists the cursor consumers that start with prefix. The
// rows are closed before returning: the store uses a single connection.
func (s *SQLiteStore) forwardConsumers(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT consumer FROM forward_cursors WHERE substr(consumer, 1, length(?)) = ?`, prefix, prefix)
	if err != nil {
		return nil, fmt.Errorf("list audit forward cursors: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var consumer string
		if err := rows.Scan(&consumer); err != nil {
			return nil, fmt.Errorf("scan audit forward cursor: %w", err)
		}
		out = append(out, consumer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit forward cursors: %w", err)
	}
	return out, nil
}
