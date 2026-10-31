// SPDX-License-Identifier: Apache-2.0
package users

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func pairedStores(t *testing.T) (*SQLiteStore, *SQLiteStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.db")
	a, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return a, b, path
}

func TestDemoteLastAdminRefused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, User{Username: "sole", Role: "admin"}, storeCredential("sole"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, u.ID, Patch{Role: "view"}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote = %v", err)
	}
	got, err := s.GetByID(ctx, u.ID)
	if err != nil || got.Role != "admin" {
		t.Fatalf("last admin changed: %+v %v", got, err)
	}
}

func TestConcurrentAdminMutations(t *testing.T) {
	for _, mutation := range []string{"demote-delete", "demote-demote", "delete-delete"} {
		t.Run(mutation, func(t *testing.T) {
			a, b, _ := pairedStores(t)
			ctx := context.Background()
			u, err := a.Create(ctx, User{Username: "one", Role: "admin"}, storeCredential("one"))
			if err != nil {
				t.Fatal(err)
			}
			v, err := a.Create(ctx, User{Username: "two", Role: "admin"}, storeCredential("two"))
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			go func() {
				<-start
				if mutation == "delete-delete" {
					results <- a.Delete(ctx, u.ID)
				} else {
					_, err := a.Update(ctx, u.ID, Patch{Role: "view"})
					results <- err
				}
			}()
			go func() {
				<-start
				if mutation == "demote-demote" {
					_, err := b.Update(ctx, v.ID, Patch{Role: "view"})
					results <- err
				} else {
					results <- b.Delete(ctx, v.ID)
				}
			}()
			close(start)
			successes, refusals := 0, 0
			for i := 0; i < 2; i++ {
				err := <-results
				if err == nil {
					successes++
				} else if errors.Is(err, ErrLastAdmin) {
					refusals++
				} else {
					t.Errorf("mutation = %v", err)
				}
			}
			if successes != 1 || refusals != 1 {
				t.Fatalf("successes=%d refusals=%d", successes, refusals)
			}
			list, err := a.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			admins := 0
			for _, u := range list {
				if u.Role == "admin" {
					admins++
				}
			}
			if admins != 1 {
				t.Fatalf("admins=%d", admins)
			}
		})
	}
}

func challengeFor(t *testing.T, s *SQLiteStore, id, purpose string, now time.Time) string {
	t.Helper()
	u, err := s.GetByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := s.CreateMFAChallenge(context.Background(), u, purpose, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func TestMFAChallengeDurableSingleUse(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s, _, path := pairedStores(t)
	id, secret := totpUser(t, s)
	ctx := context.Background()
	now := time.Now()
	challenge := challengeFor(t, s, id, MFAChallengeLogin, now)
	if err := s.RedeemLoginMFA(ctx, challenge, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.RedeemLoginMFA(ctx, challenge, id, codeAt(t, secret, now), now); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Duration(TOTPPeriod) * time.Second)
	nextCode := codeAt(t, secret, later)
	if err := reopened.RedeemLoginMFA(ctx, challenge, id, nextCode, later); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("replay after restart = %v", err)
	}
	fresh := challengeFor(t, reopened, id, MFAChallengeLogin, later)
	if fresh == challenge {
		t.Fatal("challenge ids repeated")
	}
	if err := reopened.RedeemLoginMFA(ctx, fresh, id, nextCode, later); err != nil {
		t.Fatalf("fresh challenge with later code = %v", err)
	}
}

func TestConcurrentMFAChallengeRedemption(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	a, b, _ := pairedStores(t)
	id, secret := totpUser(t, a)
	now := time.Now()
	challenge := challengeFor(t, a, id, MFAChallengeLogin, now)
	// Different, valid time steps: this tests the nonce, not TOTP replay tracking.
	codes := []string{codeAt(t, secret, now.Add(-time.Duration(TOTPPeriod)*time.Second)), codeAt(t, secret, now)}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, s := range []*SQLiteStore{a, b} {
		go func() { <-start; results <- s.RedeemLoginMFA(context.Background(), challenge, id, codes[i], now) }()
	}
	close(start)
	successes, refusals := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrMFAChallenge) {
			refusals++
		} else {
			t.Errorf("redemption = %v", err)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatalf("successes=%d refusals=%d", successes, refusals)
	}
}

func TestMFAChallengeCredentialChanges(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	for _, name := range []string{"password", "totp", "disable", "role"} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			id, secret := totpUser(t, s)
			ctx := context.Background()
			now := time.Now()
			// A second admin permits demotion while still testing role binding.
			if name == "role" {
				if _, err := s.Create(ctx, User{Username: "other", Role: "admin"}, storeCredential("other")); err != nil {
					t.Fatal(err)
				}
			}
			old, err := s.GetByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			login := challengeFor(t, s, id, MFAChallengeLogin, now)
			enroll := challengeFor(t, s, id, MFAChallengeEnroll, now)
			switch name {
			case "password":
				err = s.SetPassword(ctx, id, storeCredential("changed"))
			case "totp":
				err = s.SetTOTP(ctx, id, secret)
			case "disable":
				err = s.DisableTOTP(ctx, id)
			case "role":
				_, err = s.Update(ctx, id, Patch{Role: "view"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.RedeemLoginMFA(ctx, login, id, codeAt(t, secret, now), now); !errors.Is(err, ErrMFAChallenge) {
				t.Fatalf("old login = %v", err)
			}
			if err := s.RedeemEnrollMFA(ctx, enroll, id, secret, codeAt(t, secret, now), now); !errors.Is(err, ErrMFAChallenge) {
				t.Fatalf("old enrollment = %v", err)
			}
			if _, err := s.CreateMFAChallenge(ctx, old, MFAChallengeLogin, now.Add(time.Minute)); !errors.Is(err, ErrMFAChallenge) {
				t.Fatalf("stale issuance = %v", err)
			}
		})
	}
}

func TestMFAChallengeExpiryAndThrottle(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	id, secret := totpUser(t, s)
	now := time.Now()
	ctx := context.Background()
	expired := challengeFor(t, s, id, MFAChallengeLogin, now.Add(-10*time.Minute))
	fresh := challengeFor(t, s, id, MFAChallengeLogin, now)
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mfa_challenges WHERE id=?`, expired).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired rows=%d %v", count, err)
	}
	for i := 0; i < LimitFor(FactorTOTP).MaxFailures; i++ {
		if err := s.RedeemLoginMFA(ctx, fresh, id, wrongCode(t, secret, now), now); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatal(err)
		}
	}
	if err := s.RedeemLoginMFA(ctx, fresh, id, codeAt(t, secret, now), now); !errors.Is(err, ErrFactorLocked) {
		t.Fatalf("locked redemption = %v", err)
	}
	if err := s.RedeemLoginMFA(ctx, fresh, id, codeAt(t, secret, now), now.Add(6*time.Minute)); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("expired redemption = %v", err)
	}
}

func TestMFAChallengeMigration(t *testing.T) {
	s, _, path := pairedStores(t)
	ctx := context.Background()
	id, secret := totpUser(t, s)
	// Recreate the pre-version users schema while preserving the existing account.
	if _, err := s.db.Exec(`ALTER TABLE users DROP COLUMN credential_version`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migrated.Close() }()
	u, err := migrated.GetByUsername(ctx, "otp")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != id || u.CredentialVersion != 0 {
		t.Fatalf("migration changed account: %+v", u.User)
	}
	now := time.Now()
	challenge := challengeFor(t, migrated, id, MFAChallengeLogin, now)
	if err := migrated.RedeemLoginMFA(ctx, challenge, id, codeAt(t, secret, now), now); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentMFAEnrollmentRedemption(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	a, b, _ := pairedStores(t)
	ctx := context.Background()
	u, err := a.Create(ctx, User{Username: "enroll", Role: "view"}, storeCredential("enroll"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := GenerateTOTPEnrollment(DefaultTOTPIssuer, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	challenge := challengeFor(t, a, u.ID, MFAChallengeEnroll, now)
	code := codeAt(t, enrollment.Secret, now)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, s := range []*SQLiteStore{a, b} {
		go func() { <-start; results <- s.RedeemEnrollMFA(ctx, challenge, u.ID, enrollment.Secret, code, now) }()
	}
	close(start)
	successes, refusals := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrMFAChallenge) {
			refusals++
		} else {
			t.Errorf("enrollment = %v", err)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatalf("successes=%d refusals=%d", successes, refusals)
	}
}
