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

// The key predates boot recovery without a reservation; it holds every boot
// fault so an upgrade needs no migration.
const bootFaultKey = "management_reservation_boot_fault"

// ErrManagementBootFault gates runtime replay until a validated promotion,
// rollback or factory reset replaces the refused running configuration.
var ErrManagementBootFault = errors.New("management recovery: stored running configuration refused at boot")

func (s *SQLiteStore) ManagementBootFault(ctx context.Context) (string, error) {
	var fault string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, bootFaultKey).Scan(&fault)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return fault, err
}

// SetManagementBootFault records the post-normalization boot decision. Every
// boot records it, so a fault never outlives the condition that caused it,
// such as a removed reservation. Normal recovery clears it transactionally
// with promotion/rollback, not with staging.
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

// SetServiceBootFaults records service quarantine separately from the boot gate.
// Faults never make management recovery active.
func (s *SQLiteStore) SetServiceBootFaults(ctx context.Context, faults []ServiceFault) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(faults)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, "service_boot_faults", string(data), time.Now().Unix())
	return err
}

// ServiceBootFaultsForStore returns the most recent boot's quarantine record.
func ServiceBootFaultsForStore(ctx context.Context, store Store) ([]ServiceFault, error) {
	out := []ServiceFault{}
	s, ok := store.(*SQLiteStore)
	if !ok {
		return out, nil
	}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, "service_boot_faults").Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []ServiceFault{}
	}
	return out, nil
}
