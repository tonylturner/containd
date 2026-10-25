// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const bootFaultKey = "management_reservation_boot_fault"

// ErrManagementBootFault gates runtime replay until a validated promotion,
// rollback or factory reset replaces the conflicting running configuration.
var ErrManagementBootFault = errors.New("reserved management path boot fault")

func (s *SQLiteStore) ManagementBootFault(ctx context.Context) (string, error) {
	var fault string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, bootFaultKey).Scan(&fault)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return fault, err
}

// SetManagementBootFault records the post-normalization boot decision. Normal
// recovery clears it transactionally with promotion/rollback, not with staging.
func (s *SQLiteStore) SetManagementBootFault(ctx context.Context, fault string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fault == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, bootFaultKey)
		return err
	}
	_, err := s.db.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, bootFaultKey, fault, time.Now().Unix())
	return err
}

func ManagementBootFaultForStore(ctx context.Context, store Store) (string, error) {
	if faults, ok := store.(interface {
		ManagementBootFault(context.Context) (string, error)
	}); ok {
		return faults.ManagementBootFault(ctx)
	}
	return "", nil
}

func CheckManagementBootFault(ctx context.Context, store Store) error {
	fault, err := ManagementBootFaultForStore(ctx, store)
	if err != nil {
		return err
	}
	if fault != "" {
		return fmt.Errorf("%w: %s", ErrManagementBootFault, fault)
	}
	return nil
}
