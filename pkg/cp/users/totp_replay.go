// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/common/labmode"
)

var (
	// ErrInvalidTOTP refuses a code that no time step in the accepted window
	// produces, or an account without TOTP.
	ErrInvalidTOTP = errors.New("invalid authentication code")
	// ErrTOTPReused refuses a valid code whose time step is not later than the
	// last accepted one, so a code works once.
	ErrTOTPReused = errors.New("authentication code already used; wait for the next code")
)

// AcceptTOTP verifies code against the account's TOTP secret and records its
// time step. Each sign-in and MFA change that checks a stored secret goes
// through it, so a code observed in use cannot be replayed on web or SSH, and
// wrong codes count against the account's TOTP limit (factor_limit.go). It
// returns a *FactorLockedError while that limit locks the code check. Lab mode
// verifies the code without a limit, and without recording or refusing reuse.
func (s *SQLiteStore) AcceptTOTP(ctx context.Context, id string, code string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin accept totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result := acceptTOTP(ctx, tx, id, code, now)
	if result != nil {
		if _, _, refused := Refusal(result); !refused {
			return result
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit accept totp: %w", err)
	}
	return result
}

// acceptTOTP leaves commit ownership with the caller, including failure counters.
func acceptTOTP(ctx context.Context, tx *sql.Tx, id, code string, now time.Time) error {
	var secret string
	var enabled bool
	var lastStep int64
	err := tx.QueryRowContext(ctx, `SELECT mfa_totp_secret, mfa_totp_enabled, mfa_totp_last_step FROM users WHERE id = ?`, id).Scan(&secret, &enabled, &lastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read totp state: %w", err)
	}
	if !enabled {
		return ErrInvalidTOTP
	}
	if labmode.Enabled() {
		if _, ok := matchTOTPStep(secret, code, now); !ok {
			return ErrInvalidTOTP
		}
		return nil
	}
	st, err := loadFactor(ctx, tx, id, FactorTOTP)
	if err != nil {
		return err
	}
	if locked := st.refuse(now); locked != nil {
		if err := st.save(ctx, tx); err != nil {
			return err
		}
		return locked
	}
	step, ok := matchTOTPStep(secret, code, now)
	if !ok {
		st.fail(now)
		if err := st.save(ctx, tx); err != nil {
			return err
		}
		return ErrInvalidTOTP
	}
	if step <= lastStep {
		return ErrTOTPReused
	}
	// The condition keeps the update atomic even if another writer accepted
	// a step since the read.
	res, err := tx.ExecContext(ctx, `UPDATE users SET mfa_totp_last_step=? WHERE id=? AND mfa_totp_last_step<?`, step, id, step)
	if err != nil {
		return fmt.Errorf("record totp step: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTOTPReused
	}
	if err := clearFactor(ctx, tx, id, FactorTOTP); err != nil {
		return err
	}
	return nil
}
