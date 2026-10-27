// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// midStep returns a time in the middle of a TOTP step, so the window holds
// the previous, current and next step.
func midStep(at time.Time) time.Time {
	return time.Unix((at.Unix()/TOTPPeriod)*TOTPPeriod+TOTPPeriod/2, 0)
}

// lowerPasswordLimit shortens the current-password limit for one test: each
// check is a bcrypt comparison, which is slow under the race detector. The web
// and SSH tests use the shipped limit.
func lowerPasswordLimit(t *testing.T) {
	t.Helper()
	shipped := factorLimits[FactorCurrentPassword]
	factorLimits[FactorCurrentPassword] = FactorLimit{MaxFailures: 3, LockFor: shipped.LockFor}
	t.Cleanup(func() { factorLimits[FactorCurrentPassword] = shipped })
}

func requireLocked(t *testing.T, err error, factor Factor, first bool) {
	t.Helper()
	var locked *FactorLockedError
	if !errors.As(err, &locked) || !errors.Is(err, ErrFactorLocked) {
		t.Fatalf("err = %v, want a %s lock", err, factor)
	}
	if locked.Factor != factor || locked.First != first {
		t.Fatalf("lock = %+v, want factor %s first=%v", locked, factor, first)
	}
	if locked.RetryAfter() <= 0 || locked.RetryAfter() > LimitFor(factor).LockFor {
		t.Fatalf("retry after = %v", locked.RetryAfter())
	}
	detail, record, ok := Refusal(err)
	if !ok || record != first || detail == "" {
		t.Fatalf("Refusal = %q %v %v", detail, record, ok)
	}
}

func TestAcceptTOTPLocksTheCodeCheckPerAccount(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	path := filepath.Join(t.TempDir(), "users.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, secret := totpUser(t, s)
	now := midStep(time.Now())
	limit := LimitFor(FactorTOTP)
	step := time.Duration(TOTPPeriod) * time.Second

	// A success clears earlier failures, and a reused code is not a guess.
	for i := 0; i < limit.MaxFailures-1; i++ {
		if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatalf("wrong code %d = %v", i, err)
		}
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); err != nil {
		t.Fatalf("right code under the limit = %v", err)
	}
	for i := 0; i < limit.MaxFailures; i++ {
		if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); !errors.Is(err, ErrTOTPReused) {
			t.Fatalf("reused code %d = %v", i, err)
		}
	}
	for i := 0; i < limit.MaxFailures; i++ {
		if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatalf("wrong code %d = %v", i, err)
		}
	}

	// Locked: even the right code is refused before it is checked, and only
	// the first refusal asks to be recorded.
	right := codeAt(t, secret, now.Add(step))
	requireLocked(t, s.AcceptTOTP(ctx, id, right, now), FactorTOTP, true)
	requireLocked(t, s.AcceptTOTP(ctx, id, right, now), FactorTOTP, false)
	requireLocked(t, s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now.Add(limit.LockFor-time.Second)), FactorTOTP, false)

	// The current password is a different check and stays open.
	if err := s.CheckCurrentPassword(ctx, id, storeCredential("otp"), now); err != nil {
		t.Fatalf("current password while TOTP is locked = %v", err)
	}

	// The lock survives a restart, and lifts after its period.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	requireLocked(t, s.AcceptTOTP(ctx, id, right, now), FactorTOTP, false)
	later := now.Add(limit.LockFor)
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, later), later); err != nil {
		t.Fatalf("right code after the lock = %v", err)
	}
}

func TestFactorFailuresLapse(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	id, secret := totpUser(t, s)
	now := midStep(time.Now())
	limit := LimitFor(FactorTOTP)
	for i := 0; i < limit.MaxFailures-1; i++ {
		if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatalf("wrong code %d = %v", i, err)
		}
	}
	// Failures older than the lock period are forgotten.
	later := midStep(now.Add(limit.LockFor))
	if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, later), later); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong code after the lapse = %v", err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, later), later); err != nil {
		t.Fatalf("right code after the lapse = %v", err)
	}
}

func TestCheckCurrentPasswordLocksPerAccount(t *testing.T) {
	lowerPasswordLimit(t)
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	id, secret := totpUser(t, s)
	password := storeCredential("otp")
	now := midStep(time.Now())
	limit := LimitFor(FactorCurrentPassword)

	for i := 0; i < limit.MaxFailures-1; i++ {
		if err := s.CheckCurrentPassword(ctx, id, "wrong", now); !errors.Is(err, ErrCurrentPasswordInvalid) {
			t.Fatalf("wrong password %d = %v", i, err)
		}
	}
	if err := s.CheckCurrentPassword(ctx, id, password, now); err != nil {
		t.Fatalf("right password under the limit = %v", err)
	}
	for i := 0; i < limit.MaxFailures; i++ {
		if err := s.CheckCurrentPassword(ctx, id, "wrong", now); !errors.Is(err, ErrCurrentPasswordInvalid) {
			t.Fatalf("wrong password %d = %v", i, err)
		}
	}
	requireLocked(t, s.CheckCurrentPassword(ctx, id, password, now), FactorCurrentPassword, true)
	requireLocked(t, s.CheckCurrentPassword(ctx, id, password, now), FactorCurrentPassword, false)

	// The TOTP code is a different check and stays open.
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); err != nil {
		t.Fatalf("TOTP while the current password is locked = %v", err)
	}
	if err := s.CheckCurrentPassword(ctx, "missing", password, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user = %v", err)
	}
}

// Concurrent guesses are counted before the slow hash comparison, so they
// cannot pass the limit together.
func TestCheckCurrentPasswordCountsConcurrentGuesses(t *testing.T) {
	lowerPasswordLimit(t)
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	id, _ := totpUser(t, s)
	now := time.Now()
	limit := LimitFor(FactorCurrentPassword)
	callers := 2 * limit.MaxFailures
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.CheckCurrentPassword(context.Background(), id, "wrong", now)
		}()
	}
	wg.Wait()
	close(errs)
	checked, locked := 0, 0
	for err := range errs {
		switch {
		case errors.Is(err, ErrCurrentPasswordInvalid):
			checked++
		case errors.Is(err, ErrFactorLocked):
			locked++
		default:
			t.Fatalf("concurrent check = %v", err)
		}
	}
	if checked != limit.MaxFailures || locked != callers-limit.MaxFailures {
		t.Fatalf("checked %d, locked %d of %d", checked, locked, callers)
	}
}

// A new credential starts a new count, so an admin can lift a lock by
// resetting the password or MFA, and a deleted account leaves no state.
func TestCredentialChangesClearFactorLocks(t *testing.T) {
	lowerPasswordLimit(t)
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	id, secret := totpUser(t, s)
	now := midStep(time.Now())
	lock := func() {
		t.Helper()
		for i := 0; i < LimitFor(FactorTOTP).MaxFailures; i++ {
			_ = s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now)
		}
		for i := 0; i < LimitFor(FactorCurrentPassword).MaxFailures; i++ {
			_ = s.CheckCurrentPassword(ctx, id, "wrong", now)
		}
	}

	lock()
	fresh := storeCredential("fresh")
	if err := s.SetPassword(ctx, id, fresh); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCurrentPassword(ctx, id, fresh, now); err != nil {
		t.Fatalf("current password after a reset = %v", err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); err != nil {
		t.Fatalf("TOTP after a password reset = %v", err)
	}

	lock()
	if err := s.DisableTOTP(ctx, id); err != nil {
		t.Fatal(err)
	}
	enrollment, err := GenerateTOTPEnrollment(DefaultTOTPIssuer, "otp")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTP(ctx, id, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, enrollment.Secret, now), now); err != nil {
		t.Fatalf("TOTP after re-enrollment = %v", err)
	}
	requireLocked(t, s.CheckCurrentPassword(ctx, id, fresh, now), FactorCurrentPassword, true)

	other, err := s.Create(ctx, User{Username: "other", Role: "admin"}, storeCredential("other"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete an account with failure state = %v", err)
	}
	for i := 0; i < LimitFor(FactorCurrentPassword).MaxFailures; i++ {
		_ = s.CheckCurrentPassword(ctx, other.ID, "wrong", now)
	}
	if err := s.ResetToDefaultAdmin(ctx); err != nil {
		t.Fatalf("reset with failure state = %v", err)
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM factor_failures`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("failure rows after delete and reset = %d, %v", rows, err)
	}
}

func TestFactorLimitsLabModeUnchanged(t *testing.T) {
	lowerPasswordLimit(t)
	t.Setenv("CONTAIND_LAB_MODE", "1")
	s := newTestStore(t)
	ctx := context.Background()
	id, secret := totpUser(t, s)
	now := midStep(time.Now())
	for i := 0; i <= LimitFor(FactorCurrentPassword).MaxFailures; i++ {
		if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatalf("lab wrong code %d = %v", i, err)
		}
		if err := s.CheckCurrentPassword(ctx, id, "wrong", now); !errors.Is(err, ErrCurrentPasswordInvalid) {
			t.Fatalf("lab wrong password %d = %v", i, err)
		}
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); err != nil {
		t.Fatalf("lab right code = %v", err)
	}
	if err := s.CheckCurrentPassword(ctx, id, storeCredential("otp"), now); err != nil {
		t.Fatalf("lab right password = %v", err)
	}
}

func TestRefusalDetails(t *testing.T) {
	for _, tc := range []struct {
		err    error
		detail string
		record bool
		ok     bool
	}{
		{ErrInvalidTOTP, "invalid totp code", true, true},
		{ErrTOTPReused, "totp code reused", true, true},
		{ErrCurrentPasswordInvalid, "current password invalid", true, true},
		{&FactorLockedError{Factor: FactorTOTP, First: true}, "totp locked after repeated failures", true, true},
		{&FactorLockedError{Factor: FactorCurrentPassword}, "current password locked after repeated failures", false, true},
		{ErrNotFound, "", false, false},
	} {
		detail, record, ok := Refusal(tc.err)
		if detail != tc.detail || record != tc.record || ok != tc.ok {
			t.Fatalf("Refusal(%v) = %q %v %v", tc.err, detail, record, ok)
		}
	}
}
