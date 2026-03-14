// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func storeCredential(label string) string {
	return label + "-Aa1!"
}

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGetByUsername(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	userPassword := storeCredential("alice-admin")

	u, err := s.Create(ctx, User{Username: "alice", Role: "admin"}, userPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == "" {
		t.Fatal("user ID should be set")
	}
	if u.Username != "alice" {
		t.Fatalf("username = %q, want alice", u.Username)
	}

	got, err := s.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("ID mismatch: %q != %q", got.ID, u.ID)
	}
	if got.PasswordHash == "" {
		t.Fatal("password hash should be set")
	}
}

func TestCreateDuplicateUsername(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Create(ctx, User{Username: "bob", Role: "admin"}, storeCredential("bob-admin"))
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err = s.Create(ctx, User{Username: "bob", Role: "view"}, storeCredential("bob-view"))
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("expected ErrUsernameTaken, got %v", err)
	}
}

func TestGetByIDNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetByID(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetByUsernameNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetByUsername(ctx, "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Empty list
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 users, got %d", len(list))
	}

	s.Create(ctx, User{Username: "charlie", Role: "admin"}, storeCredential("charlie-admin"))
	s.Create(ctx, User{Username: "alice", Role: "view"}, storeCredential("alice-view"))

	list, err = s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list))
	}
	// Should be sorted by username
	if list[0].Username != "alice" {
		t.Fatalf("expected alice first (sorted), got %q", list[0].Username)
	}
}

func TestUpdateUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "dana", Role: "view"}, storeCredential("dana-view"))
	updated, err := s.Update(ctx, u.ID, User{FirstName: "Dana", Email: "dana@example.com"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.FirstName != "Dana" {
		t.Fatalf("FirstName = %q, want Dana", updated.FirstName)
	}
	if updated.Email != "dana@example.com" {
		t.Fatalf("Email = %q", updated.Email)
	}
}

func TestUpdateInvalidRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "eve", Role: "admin"}, storeCredential("eve-admin"))
	_, err := s.Update(ctx, u.ID, User{Role: "superadmin"})
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestDeleteUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1, _ := s.Create(ctx, User{Username: "admin1", Role: "admin"}, storeCredential("admin-one"))
	u2, _ := s.Create(ctx, User{Username: "admin2", Role: "admin"}, storeCredential("admin-two"))

	if err := s.Delete(ctx, u1.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.GetByID(ctx, u1.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user should not be found, got %v", err)
	}

	// u2 still exists
	_, err = s.GetByID(ctx, u2.ID)
	if err != nil {
		t.Fatalf("remaining user should exist: %v", err)
	}
}

func TestDeleteLastAdminFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "solo", Role: "admin"}, storeCredential("solo-admin"))
	err := s.Delete(ctx, u.ID)
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		pw      string
		wantErr bool
	}{
		{"", true},
		{"short", true},
		{"alllowercase1", true}, // no uppercase
		{"ALLUPPERCASE1", true}, // no lowercase
		{"NoDigitsHere", true},  // no digit
		{"Valid1pw", false},     // 8 chars, upper, lower, digit
		{"C0mpl3x!Pass", false}, // complex valid
	}
	for _, tt := range tests {
		err := validatePassword(tt.pw)
		if (err != nil) != tt.wantErr {
			t.Errorf("validatePassword(%q) err=%v, wantErr=%v", tt.pw, err, tt.wantErr)
		}
	}
}

func TestSetPassword(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "frank", Role: "view"}, storeCredential("frank-view"))

	// Invalid password
	err := s.SetPassword(ctx, u.ID, "weak")
	if err == nil {
		t.Fatal("weak password should be rejected")
	}

	// Valid password
	err = s.SetPassword(ctx, u.ID, storeCredential("frank-reset"))
	if err == nil {
		// verify it changed
		got, _ := s.GetByID(ctx, u.ID)
		if got.MustChangePassword {
			t.Fatal("mustChangePassword should be cleared after SetPassword")
		}
	}

	// Nonexistent user
	err = s.SetPassword(ctx, "bogus", storeCredential("bogus-reset"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for bogus ID, got %v", err)
	}
}

func TestCreateInvalidRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Create(ctx, User{Username: "bad", Role: "root"}, storeCredential("bad-role"))
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestCreateEmptyUsername(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Create(ctx, User{Username: "", Role: "admin"}, storeCredential("empty-user"))
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "sessuser", Role: "admin"}, storeCredential("session-user"))

	sess, err := s.CreateSession(ctx, u.ID, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("session ID should be set")
	}
	if sess.UserID != u.ID {
		t.Fatalf("session userID = %q, want %q", sess.UserID, u.ID)
	}

	// Get session
	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Revoked {
		t.Fatal("session should not be revoked")
	}

	// Touch session
	touched, err := s.TouchSession(ctx, sess.ID, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if touched.LastSeen.Before(got.LastSeen) {
		t.Fatal("LastSeen should be updated")
	}

	// Revoke session
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	revoked, _ := s.GetSession(ctx, sess.ID)
	if !revoked.Revoked {
		t.Fatal("session should be revoked")
	}

	// Touch revoked session should fail
	_, err = s.TouchSession(ctx, sess.ID, 15*time.Minute, time.Hour)
	if err == nil {
		t.Fatal("touching revoked session should fail")
	}
}

func TestSessionNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetSession(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeNonexistentSession(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.RevokeSession(ctx, "bogus")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteUserCascadesSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1, _ := s.Create(ctx, User{Username: "with-sess", Role: "admin"}, storeCredential("with-session"))
	s.Create(ctx, User{Username: "other-admin", Role: "admin"}, storeCredential("other-admin"))

	sess, _ := s.CreateSession(ctx, u1.ID, 15*time.Minute, time.Hour)

	if err := s.Delete(ctx, u1.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Session should be gone
	_, err := s.GetSession(ctx, sess.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be deleted with user, got %v", err)
	}
}

func TestEnsureDefaultAdmin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// On a fresh DB, should create default admin
	if err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}

	u, err := s.GetByUsername(ctx, "containd")
	if err != nil {
		t.Fatalf("default admin should exist: %v", err)
	}
	if u.Role != "admin" {
		t.Fatalf("default admin role = %q, want admin", u.Role)
	}

	// Calling again should be idempotent
	if err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatalf("second EnsureDefaultAdmin: %v", err)
	}

	list, _ := s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("should still have 1 user, got %d", len(list))
	}
}

func TestSessionIdleTTLCappedByMaxTTL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "ttl", Role: "admin"}, storeCredential("ttl-admin"))

	// idleTTL > maxTTL — should be capped
	sess, err := s.CreateSession(ctx, u.ID, 2*time.Hour, 30*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	maxExp := sess.IssuedAt.Add(30 * time.Minute)
	if sess.ExpiresAt.After(maxExp.Add(time.Second)) {
		t.Fatalf("ExpiresAt %v should not exceed maxTTL %v", sess.ExpiresAt, maxExp)
	}
}

func TestWipeAll(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, _ := s.Create(ctx, User{Username: "wipe", Role: "admin"}, storeCredential("wipe-admin"))
	s.CreateSession(ctx, u.ID, time.Hour, 2*time.Hour)

	if err := s.WipeAll(ctx); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}

	list, _ := s.List(ctx)
	if len(list) != 0 {
		t.Fatalf("expected 0 users after wipe, got %d", len(list))
	}
}
