// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/common/labmode"
)

// Outside lab mode, the store limits guesses at an account's TOTP code and at
// its current password (the confirmation asked before a password or MFA
// change) per account, whichever client address they come from. After
// MaxFailures failed checks without a success, that check alone is locked for
// LockFor: it is refused before the guess is checked, so the refusal does not
// reveal whether the guess was right. Password login is never locked here and
// keeps only its per-address limit, so an attacker who lacks the password
// cannot lock an account out; reaching the TOTP check takes the right
// password. A success, a lapse of LockFor since the last failure, or a new
// credential resets the count.

// Factor names an account check that the store limits per account.
type Factor string

const (
	// FactorTOTP is the account's TOTP code, at login and at MFA self-disable.
	FactorTOTP Factor = "totp"
	// FactorCurrentPassword is the current password confirmed before a
	// password or MFA change of a signed-in account.
	FactorCurrentPassword Factor = "current_password"
)

// FactorLimit is the number of failed checks that locks a factor and how long
// the lock lasts.
type FactorLimit struct {
	MaxFailures int
	LockFor     time.Duration
}

// factorLimits holds each factor's limit. A TOTP guess is right about once in
// 333,000 (three codes in the accepted window out of 10^6), so five failures
// per 15 minutes bound one account to about 480 guesses a day. Signed-in
// users mistype their current password more often and its space is larger.
var factorLimits = map[Factor]FactorLimit{
	FactorTOTP:            {MaxFailures: 5, LockFor: 15 * time.Minute},
	FactorCurrentPassword: {MaxFailures: 10, LockFor: 15 * time.Minute},
}

// LimitFor returns factor's limit.
func LimitFor(factor Factor) FactorLimit { return factorLimits[factor] }

// ErrCurrentPasswordInvalid refuses a wrong current password.
var ErrCurrentPasswordInvalid = errors.New("current password invalid")

// ErrFactorLocked matches every *FactorLockedError with errors.Is.
var ErrFactorLocked = errors.New("factor locked")

// FactorLockedError refuses a check while the account's factor is locked.
type FactorLockedError struct {
	Factor Factor
	Until  time.Time
	// First is set on the first refusal of this lock; callers record that
	// refusal only, so a lock writes one audit record however often it is
	// tried.
	First bool
	now   time.Time
}

// RetryAfter returns the time left on the lock, rounded up to a second.
func (e *FactorLockedError) RetryAfter() time.Duration {
	left := e.Until.Sub(e.now)
	if left < time.Second {
		return time.Second
	}
	return left.Round(time.Second)
}

func (e *FactorLockedError) Error() string {
	minutes := int((e.RetryAfter() + time.Minute - 1) / time.Minute)
	what := "authentication codes"
	if e.Factor == FactorCurrentPassword {
		what = "current password attempts"
	}
	return fmt.Sprintf("too many failed %s for this account; try again in %d minutes", what, minutes)
}

func (e *FactorLockedError) Is(target error) bool { return target == ErrFactorLocked }

// Refusal returns the audit detail for a refused AcceptTOTP or
// CheckCurrentPassword call and whether to record it. ok is false for any
// other error, such as a store failure.
func Refusal(err error) (detail string, record bool, ok bool) {
	var locked *FactorLockedError
	switch {
	case errors.As(err, &locked):
		if locked.Factor == FactorCurrentPassword {
			return "current password locked after repeated failures", locked.First, true
		}
		return "totp locked after repeated failures", locked.First, true
	case errors.Is(err, ErrTOTPReused):
		return "totp code reused", true, true
	case errors.Is(err, ErrInvalidTOTP):
		return "invalid totp code", true, true
	case errors.Is(err, ErrCurrentPasswordInvalid):
		return "current password invalid", true, true
	}
	return "", false, false
}

// CheckCurrentPassword confirms a signed-in account's current password. It
// returns ErrCurrentPasswordInvalid for a wrong one and a *FactorLockedError
// while the check is locked. The attempt is counted before the slow hash
// comparison and cleared on success, so concurrent guesses cannot pass the
// limit. Lab mode compares without a limit.
func (s *SQLiteStore) CheckCurrentPassword(ctx context.Context, id string, password string, now time.Time) error {
	if labmode.Enabled() {
		u, err := s.GetByID(ctx, id)
		if err != nil {
			return err
		}
		return comparePassword(u.PasswordHash, password)
	}
	hash, err := s.reservePasswordCheck(ctx, id, now)
	if err != nil {
		return err
	}
	if err := comparePassword(hash, password); err != nil {
		return err
	}
	return clearFactor(ctx, s.db, id, FactorCurrentPassword)
}

func comparePassword(hash, password string) error {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return ErrCurrentPasswordInvalid
	}
	return nil
}

// reservePasswordCheck refuses a locked check, otherwise counts the attempt
// as a failure and returns the password hash to compare.
func (s *SQLiteStore) reservePasswordCheck(ctx context.Context, id string, now time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin password check: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var hash string
	err = tx.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	st, err := loadFactor(ctx, tx, id, FactorCurrentPassword)
	if err != nil {
		return "", err
	}
	if locked := st.refuse(now); locked != nil {
		return "", commitFactor(ctx, tx, st, locked)
	}
	st.fail(now)
	if err := commitFactor(ctx, tx, st, nil); err != nil {
		return "", err
	}
	return hash, nil
}

// factorState is one account's failure count for one factor. Times are Unix
// seconds; zero means unset.
type factorState struct {
	userID       string
	factor       Factor
	failures     int
	lastFailure  int64
	lockedUntil  int64
	lockReported bool
}

func loadFactor(ctx context.Context, tx *sql.Tx, id string, factor Factor) (*factorState, error) {
	st := &factorState{userID: id, factor: factor}
	err := tx.QueryRowContext(ctx, `SELECT failures, last_failure, locked_until, lock_reported FROM factor_failures WHERE user_id = ? AND factor = ?`, id, string(factor)).
		Scan(&st.failures, &st.lastFailure, &st.lockedUntil, &st.lockReported)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read %s failures: %w", factor, err)
	}
	return st, nil
}

// refuse returns the lock error while the factor is locked, marking the first
// refusal. It forgets failures once the lock or the last failure is older
// than LockFor.
func (st *factorState) refuse(now time.Time) *FactorLockedError {
	limit := factorLimits[st.factor]
	at := now.Unix()
	if st.lockedUntil > at {
		first := !st.lockReported
		st.lockReported = true
		return &FactorLockedError{Factor: st.factor, Until: time.Unix(st.lockedUntil, 0), First: first, now: now}
	}
	if st.lockedUntil != 0 || at-st.lastFailure >= int64(limit.LockFor/time.Second) {
		st.failures, st.lastFailure, st.lockedUntil, st.lockReported = 0, 0, 0, false
	}
	return nil
}

// fail counts a failed check and locks the factor at its limit.
func (st *factorState) fail(now time.Time) {
	limit := factorLimits[st.factor]
	st.failures++
	st.lastFailure = now.Unix()
	if st.failures >= limit.MaxFailures {
		st.lockedUntil = now.Add(limit.LockFor).Unix()
		st.lockReported = false
	}
}

func (st *factorState) save(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO factor_failures (user_id, factor, failures, last_failure, locked_until, lock_reported) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(user_id, factor) DO UPDATE SET failures=excluded.failures, last_failure=excluded.last_failure, locked_until=excluded.locked_until, lock_reported=excluded.lock_reported`,
		st.userID, string(st.factor), st.failures, st.lastFailure, st.lockedUntil, st.lockReported)
	if err != nil {
		return fmt.Errorf("record %s failures: %w", st.factor, err)
	}
	return nil
}

// commitFactor saves st, commits tx and returns result.
func commitFactor(ctx context.Context, tx *sql.Tx, st *factorState, result error) error {
	if err := st.save(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s failures: %w", st.factor, err)
	}
	return result
}

func clearFactor(ctx context.Context, db userDB, id string, factor Factor) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM factor_failures WHERE user_id = ? AND factor = ?`, id, string(factor)); err != nil {
		return fmt.Errorf("clear %s failures: %w", factor, err)
	}
	return nil
}
