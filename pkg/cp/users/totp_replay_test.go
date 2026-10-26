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

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: TOTPPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// wrongCode returns a code that no step in the window around at accepts.
func wrongCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	step := time.Duration(TOTPPeriod) * time.Second
	valid := map[string]bool{}
	for _, d := range []time.Duration{-step, 0, step} {
		valid[codeAt(t, secret, at.Add(d))] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

func totpUser(t *testing.T, s *SQLiteStore) (string, string) {
	t.Helper()
	u, err := s.Create(context.Background(), User{Username: "otp", Role: "admin"}, storeCredential("otp"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := GenerateTOTPEnrollment(DefaultTOTPIssuer, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTP(context.Background(), u.ID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	return u.ID, enrollment.Secret
}

func TestAcceptTOTPRefusesReplayedSteps(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	path := filepath.Join(t.TempDir(), "users.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, secret := totpUser(t, s)
	// The middle of a step, so the window holds the previous, current and next step.
	now := time.Unix((time.Now().Unix()/TOTPPeriod)*TOTPPeriod+TOTPPeriod/2, 0)
	step := time.Duration(TOTPPeriod) * time.Second

	if err := s.AcceptTOTP(ctx, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong code = %v", err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now), now); err != nil {
		t.Fatalf("current code = %v", err)
	}
	for name, at := range map[string]time.Time{"same step": now, "earlier step": now.Add(-step)} {
		if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, at), now); !errors.Is(err, ErrTOTPReused) {
			t.Fatalf("%s = %v, want ErrTOTPReused", name, err)
		}
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now.Add(step)), now); err != nil {
		t.Fatalf("next step = %v", err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now.Add(step)), now.Add(step)); !errors.Is(err, ErrTOTPReused) {
		t.Fatalf("next step reused after the clock moved = %v", err)
	}

	// The accepted step survives a restart.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.AcceptTOTP(ctx, id, codeAt(t, secret, now.Add(step)), now.Add(step)); !errors.Is(err, ErrTOTPReused) {
		t.Fatalf("reused after restart = %v", err)
	}

	// A new secret starts a new history; no secret accepts nothing.
	enrollment, err := GenerateTOTPEnrollment(DefaultTOTPIssuer, "otp")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTP(ctx, id, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, enrollment.Secret, now), now); err != nil {
		t.Fatalf("new secret, earlier step = %v", err)
	}
	if err := s.DisableTOTP(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptTOTP(ctx, id, codeAt(t, enrollment.Secret, now.Add(step)), now.Add(step)); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("disabled TOTP = %v", err)
	}
	if err := s.AcceptTOTP(ctx, "missing", "123456", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user = %v", err)
	}
}

func TestAcceptTOTPAcceptsACodeOnce(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	id, secret := totpUser(t, s)
	now := time.Now()
	code := codeAt(t, secret, now)
	const callers = 8
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.AcceptTOTP(context.Background(), id, code, now)
		}()
	}
	wg.Wait()
	close(errs)
	accepted := 0
	for err := range errs {
		switch {
		case err == nil:
			accepted++
		case !errors.Is(err, ErrTOTPReused):
			t.Fatalf("concurrent accept = %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d times, want 1", accepted)
	}
}

func TestAcceptTOTPLabModeKeepsReuse(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	s := newTestStore(t)
	id, secret := totpUser(t, s)
	now := time.Now()
	for i := 0; i < 2; i++ {
		if err := s.AcceptTOTP(context.Background(), id, codeAt(t, secret, now), now); err != nil {
			t.Fatalf("lab accept %d = %v", i, err)
		}
	}
	if err := s.AcceptTOTP(context.Background(), id, "12345", now); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("lab wrong code = %v", err)
	}
}
