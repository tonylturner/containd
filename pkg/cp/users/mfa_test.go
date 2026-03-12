// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPEnrollment(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("containd", "alice")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	if enrollment.Secret == "" {
		t.Fatal("expected secret")
	}
	if !strings.HasPrefix(enrollment.URL, "otpauth://totp/") {
		t.Fatalf("unexpected otpauth URL: %q", enrollment.URL)
	}
	if !strings.HasPrefix(enrollment.QRDataURL, "data:image/png;base64,") {
		t.Fatalf("unexpected qr data url: %q", enrollment.QRDataURL)
	}
}

func TestNormalizeAndValidateTOTP(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("containd", "alice")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	now := time.Now().UTC()
	code, err := totp.GenerateCodeCustom(enrollment.Secret, now, totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	if NormalizeOTP(code[:3]+" "+code[3:]) != code {
		t.Fatalf("NormalizeOTP did not remove spaces")
	}
	if !ValidateTOTP(enrollment.Secret, code[:3]+" "+code[3:], now) {
		t.Fatal("ValidateTOTP should accept a normalized valid code")
	}
	if ValidateTOTP(enrollment.Secret, "000000", now) {
		t.Fatal("ValidateTOTP should reject an invalid code")
	}
}

func TestSetAndDisableTOTP(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, User{Username: "mfa-user", Role: "admin"}, "Password1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.SetTOTP(ctx, u.ID, "BASE32SECRET"); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after SetTOTP: %v", err)
	}
	if !got.MFAEnabled || got.TOTPSecret != "BASE32SECRET" {
		t.Fatalf("expected MFA enabled with stored secret, got enabled=%v secret=%q", got.MFAEnabled, got.TOTPSecret)
	}
	if err := s.DisableTOTP(ctx, u.ID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	got, err = s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after DisableTOTP: %v", err)
	}
	if got.MFAEnabled || got.TOTPSecret != "" {
		t.Fatalf("expected MFA disabled, got enabled=%v secret=%q", got.MFAEnabled, got.TOTPSecret)
	}
}

func TestSetMFARequirement(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, User{Username: "required-user", Role: "admin"}, "Password1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	deadline := MFAGraceDeadline(time.Now())
	if err := s.SetMFARequirement(ctx, u.ID, true, &deadline); err != nil {
		t.Fatalf("SetMFARequirement require: %v", err)
	}
	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after require: %v", err)
	}
	if !got.MFARequired || got.MFAGraceUntil == nil {
		t.Fatalf("expected pending MFA requirement with grace, got %+v", got.User)
	}

	if err := s.SetMFARequirement(ctx, u.ID, false, nil); err != nil {
		t.Fatalf("SetMFARequirement clear: %v", err)
	}
	got, err = s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after clear: %v", err)
	}
	if got.MFARequired || got.MFAGraceUntil != nil {
		t.Fatalf("expected cleared MFA requirement, got %+v", got.User)
	}
}

func TestMFAGraceHelpers(t *testing.T) {
	enrollment, err := GenerateTOTPEnrollment("containd", "alice")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)

	if HasPendingMFARequirement(nil) {
		t.Fatal("nil user should not have a pending MFA requirement")
	}

	u := &StoredUser{
		User: User{
			MFARequired:   true,
			MFAGraceUntil: &future,
		},
	}
	if !HasPendingMFARequirement(u) {
		t.Fatal("expected pending MFA requirement")
	}
	if IsMFAGraceExpired(u, time.Now()) {
		t.Fatal("future grace deadline should not be expired")
	}

	u.MFAGraceUntil = &past
	if !IsMFAGraceExpired(u, time.Now()) {
		t.Fatal("past grace deadline should be expired")
	}

	u.MFAEnabled = true
	u.TOTPSecret = enrollment.Secret
	if IsMFAGraceExpired(u, time.Now()) {
		t.Fatal("enabled MFA should satisfy the requirement")
	}
}
