// SPDX-License-Identifier: Apache-2.0
package users

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// lockUser obtains SQLite's writer reservation before reading an invariant.
// This also serializes mutations made through independent store connections.
func lockUser(ctx context.Context, tx *sql.Tx, id string) error {
	res, err := tx.ExecContext(ctx, `UPDATE users SET id=id WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("lock user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func preserveAdmin(ctx context.Context, tx *sql.Tx, u *StoredUser) error {
	if u.Role != "admin" {
		return nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&count); err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

func (s *SQLiteStore) Update(ctx context.Context, id string, patch Patch) (*User, error) {
	if patch.Role != "" && patch.Role != "admin" && patch.Role != "view" {
		return nil, fmt.Errorf("invalid role %q", patch.Role)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockUser(ctx, tx, id); err != nil {
		return nil, err
	}
	existing, err := getByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	role := existing.Role
	if patch.Role != "" && patch.Role != role {
		if err := preserveAdmin(ctx, tx, existing); err != nil {
			return nil, err
		}
		role = patch.Role
		if err := invalidateChallenges(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET first_name=COALESCE(?,first_name), last_name=COALESCE(?,last_name), email=COALESCE(?,email), role=?, updated_at=? WHERE id=?`, patch.FirstName, patch.LastName, patch.Email, role, time.Now().Unix(), id)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	updated, err := getByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &updated.User, nil
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockUser(ctx, tx, id); err != nil {
		return err
	}
	existing, err := getByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := preserveAdmin(ctx, tx, existing); err != nil {
		return err
	}
	removed, err := activeSessionIDs(ctx, tx, id, "")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.revocations.publish(removed)
	return nil
}
