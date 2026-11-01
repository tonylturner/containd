// SPDX-License-Identifier: Apache-2.0
package users

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMFADisableWithGraceAtomic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
		fail     bool
	}{
		{"required", true, false},
		{"optional", false, false},
		{"rollback", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_LAB_MODE", "0")
			s := newTestStore(t)
			ctx := context.Background()
			u, err := s.Create(ctx, User{Username: "mfa-user", Role: "view"}, storeCredential("mfa-user"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
				t.Fatal(err)
			}
			oldDeadline := time.Now().Add(-time.Hour)
			if err := s.SetMFARequirement(ctx, u.ID, tc.required, &oldDeadline); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE users SET mfa_totp_last_step=42 WHERE id=?`, u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `INSERT INTO factor_failures (user_id,factor,failures) VALUES (?,?,3)`, u.ID, FactorTOTP); err != nil {
				t.Fatal(err)
			}
			before, err := s.GetByID(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := s.CreateMFAChallenge(ctx, before, MFAChallengeLogin, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			acting, err := s.CreateSession(ctx, u.ID, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			other, err := s.CreateSession(ctx, u.ID, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			var notified []string
			unsubscribe := s.SubscribeSessionRevocations(func(ids []string) { notified = append(notified, ids...) })
			defer unsubscribe()
			if tc.fail {
				// Fail at session revocation, after TOTP, grace, failure counts
				// and challenges have already changed inside the transaction.
				// The predicate proves the TOTP update was reached.
				_, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_mfa_disable
BEFORE UPDATE OF revoked ON sessions
WHEN (SELECT mfa_totp_enabled=0 AND mfa_grace_until>0 FROM users WHERE id=OLD.user_id)
BEGIN SELECT RAISE(ABORT, 'injected disable failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Truncate(time.Second)
			err = s.DisableTOTPWithGrace(WithActingSession(ctx, acting.ID), u.ID, now)
			if tc.fail {
				if err == nil || !strings.Contains(err.Error(), "injected disable failure") {
					t.Fatalf("disable error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			after, err := s.GetByID(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.fail {
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("failed disable changed user: before=%+v after=%+v", before, after)
				}
			} else {
				if after.MFAEnabled || after.TOTPSecret != "" || after.MFARequired != tc.required || after.CredentialVersion != before.CredentialVersion+1 {
					t.Fatalf("disabled user = %+v", after)
				}
				if tc.required {
					want := MFAGraceDeadline(now)
					if after.MFAGraceUntil == nil || !after.MFAGraceUntil.Equal(want) {
						t.Fatalf("grace = %v, want %v", after.MFAGraceUntil, want)
					}
				} else if after.MFAGraceUntil != nil {
					t.Fatalf("optional user has grace: %v", after.MFAGraceUntil)
				}
			}
			var step, failures, challenges int
			if err := s.db.QueryRowContext(ctx, `SELECT mfa_totp_last_step,
(SELECT COALESCE(SUM(failures),0) FROM factor_failures WHERE user_id=users.id),
(SELECT COUNT(*) FROM mfa_challenges WHERE id=?) FROM users WHERE id=?`, challenge, u.ID).Scan(&step, &failures, &challenges); err != nil {
				t.Fatal(err)
			}
			if tc.fail {
				if step != 42 || failures != 3 || challenges != 1 || len(notified) != 0 {
					t.Fatalf("rollback: step=%d failures=%d challenges=%d notifications=%v", step, failures, challenges, notified)
				}
			} else if step != 0 || failures != 0 || challenges != 0 || !reflect.DeepEqual(notified, []string{other.ID}) {
				t.Fatalf("cleanup: step=%d failures=%d challenges=%d notifications=%v", step, failures, challenges, notified)
			}
			for _, session := range []*Session{acting, other} {
				got, err := s.GetSession(ctx, session.ID)
				if err != nil {
					t.Fatal(err)
				}
				wantRevoked := !tc.fail && session.ID == other.ID
				if got.Revoked != wantRevoked {
					t.Fatalf("session %s revoked=%v, want %v", session.ID, got.Revoked, wantRevoked)
				}
			}
		})
	}
}

func TestMFADisableWithGraceMissingUser(t *testing.T) {
	s := newTestStore(t)
	if err := s.DisableTOTPWithGrace(context.Background(), "missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
}
