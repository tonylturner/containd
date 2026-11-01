// SPDX-License-Identifier: Apache-2.0
package users

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestEnrollmentConsumesTOTPStep(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	for _, offset := range []int64{-1, 0, 1} {
		t.Run(strconv.FormatInt(offset, 10), func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			user, err := s.Create(ctx, User{Username: "enrolling", Role: "admin"}, storeCredential("enrolling"))
			if err != nil {
				t.Fatal(err)
			}
			u, err := s.GetByID(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Truncate(time.Duration(TOTPPeriod) * time.Second)
			enrollment, err := GenerateTOTPEnrollment(DefaultTOTPIssuer, u.Username)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := s.CreateMFAChallenge(ctx, u, MFAChallengeEnroll, now.Add(5*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			at := now.Add(time.Duration(offset*TOTPPeriod) * time.Second)
			code := codeAt(t, enrollment.Secret, at)
			if err := s.RedeemEnrollMFA(ctx, challenge, u.ID, enrollment.Secret, code, now); err != nil {
				t.Fatal(err)
			}
			// The stored marker must be the matched step, not the wall clock.
			var step int64
			if err := s.db.QueryRowContext(ctx, `SELECT mfa_totp_last_step FROM users WHERE id=?`, u.ID).Scan(&step); err != nil {
				t.Fatal(err)
			}
			if step != at.Unix()/TOTPPeriod {
				t.Errorf("stored step = %d, want %d", step, at.Unix()/TOTPPeriod)
			}
			if err := s.AcceptTOTP(ctx, u.ID, code, now); !errors.Is(err, ErrTOTPReused) {
				t.Errorf("enrollment code replay = %v, want ErrTOTPReused", err)
			}
			next := at.Add(time.Duration(TOTPPeriod) * time.Second)
			if err := s.AcceptTOTP(ctx, u.ID, codeAt(t, enrollment.Secret, next), next); err != nil {
				t.Fatalf("next step = %v", err)
			}
		})
	}
}
