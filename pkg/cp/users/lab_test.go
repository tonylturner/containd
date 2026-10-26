// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLabMode(t *testing.T) {
	for value, want := range map[string]bool{
		"": false, "0": false, "false": false, "yes": false,
		"1": true, "true": true, "TRUE": true, "True": true,
	} {
		t.Setenv("CONTAIND_LAB_MODE", value)
		if got := LabMode(); got != want {
			t.Errorf("LabMode() with CONTAIND_LAB_MODE=%q = %v, want %v", value, got, want)
		}
		wantErr := error(nil)
		if want {
			wantErr = ErrPasswordChangeLabMode
		}
		if err := CheckPasswordChange(); !errors.Is(err, wantErr) {
			t.Errorf("CheckPasswordChange() with CONTAIND_LAB_MODE=%q = %v, want %v", value, err, wantErr)
		}
	}
}

func TestSetPasswordRefusedInLabMode(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, User{Username: "lab-view", Role: "view"}, storeCredential("lab-view"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	t.Setenv("CONTAIND_LAB_MODE", "1")
	for name, tc := range map[string]struct{ id, password string }{
		"valid password": {u.ID, storeCredential("lab-view-new")},
		"weak password":  {u.ID, "weak"},
		"unknown user":   {"bogus", storeCredential("bogus")},
	} {
		if err := s.SetPassword(ctx, tc.id, tc.password); !errors.Is(err, ErrPasswordChangeLabMode) {
			t.Errorf("%s: SetPassword in lab mode = %v, want ErrPasswordChangeLabMode", name, err)
		}
	}
	after, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("refused password change still replaced the stored hash")
	}
}

func TestLabModeSeedsDefaultCredential(t *testing.T) {
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	t.Setenv("CONTAIND_LAB_MODE", "1")
	s := newTestStore(t)
	ctx := context.Background()

	assertSeeded := func(stage string) {
		t.Helper()
		admin, err := s.GetByUsername(ctx, "containd")
		if err != nil {
			t.Fatalf("%s: default admin missing: %v", stage, err)
		}
		if admin.Role != "admin" || admin.MustChangePassword {
			t.Fatalf("%s: unexpected lab default admin state: %+v", stage, admin.User)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte("containd")); err != nil {
			t.Fatalf("%s: lab default credential does not authenticate: %v", stage, err)
		}
	}

	if err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}
	assertSeeded("first boot")

	if err := s.ResetToDefaultAdmin(ctx); err != nil {
		t.Fatalf("ResetToDefaultAdmin: %v", err)
	}
	assertSeeded("factory reset")
}
