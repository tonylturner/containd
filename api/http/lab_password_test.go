// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cp/users"
)

type labPasswordFixture struct {
	server http.Handler
	store  *users.SQLiteStore
	userID string
	token  string
}

// newLabPasswordFixture serves the API over a real users store holding one
// session-backed admin whose password is testPassword.
func newLabPasswordFixture(t *testing.T, labMode string) labPasswordFixture {
	t.Helper()
	t.Setenv("CONTAIND_LAB_MODE", labMode)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	resetTestRateLimiters()

	store, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	admin, err := store.Create(ctx, users.User{Username: "lab-admin", Role: "admin"}, testPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess, err := store.CreateSession(ctx, admin.ID, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return labPasswordFixture{
		server: NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, store),
		store:  store,
		userID: admin.ID,
		token:  signTestJWT([]byte(testJWTSecret), admin.ID, admin.Username, admin.Role, sess.ID, sess.ExpiresAt),
	}
}

func (f labPasswordFixture) post(t *testing.T, path string, body map[string]string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, path, bytes.NewBuffer(raw), f.token))
	var resp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp.Error
}

func (f labPasswordFixture) passwordHash(t *testing.T) string {
	t.Helper()
	u, err := f.store.GetByID(context.Background(), f.userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return u.PasswordHash
}

func TestLabModeRefusesAPIPasswordChanges(t *testing.T) {
	newPassword := testSensitiveValue("lab-rotated")
	requests := map[string]struct {
		path string
		body map[string]string
	}{
		"self change": {"/api/v1/auth/me/password", map[string]string{"currentPassword": testPassword, "newPassword": newPassword}},
		"self change with wrong current password": {"/api/v1/auth/me/password", map[string]string{"currentPassword": "wrong", "newPassword": newPassword}},
		"admin set":                    {"/api/v1/users/:id/password", map[string]string{"password": newPassword}},
		"admin set with weak password": {"/api/v1/users/:id/password", map[string]string{"password": "weak"}},
	}
	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			f := newLabPasswordFixture(t, "1")
			before := f.passwordHash(t)
			code, msg := f.post(t, strings.ReplaceAll(req.path, ":id", f.userID), req.body)
			if code != http.StatusForbidden || msg != users.ErrPasswordChangeLabMode.Error() {
				t.Fatalf("got %d %q, want 403 %q", code, msg, users.ErrPasswordChangeLabMode.Error())
			}
			if f.passwordHash(t) != before {
				t.Fatal("refused request changed the stored password")
			}
		})
	}
}

func TestAPIPasswordChangesOutsideLabMode(t *testing.T) {
	newPassword := testSensitiveValue("rotated")
	requests := map[string]struct {
		path string
		body map[string]string
	}{
		"self change": {"/api/v1/auth/me/password", map[string]string{"currentPassword": testPassword, "newPassword": newPassword}},
		"admin set":   {"/api/v1/users/:id/password", map[string]string{"password": newPassword}},
	}
	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			f := newLabPasswordFixture(t, "0")
			if code, msg := f.post(t, strings.ReplaceAll(req.path, ":id", f.userID), req.body); code != http.StatusOK {
				t.Fatalf("got %d %q, want 200", code, msg)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(f.passwordHash(t)), []byte(newPassword)); err != nil {
				t.Fatalf("new password not stored: %v", err)
			}
		})
	}
}

func TestSetPasswordErrorStatus(t *testing.T) {
	for err, want := range map[error]int{
		users.ErrPasswordChangeLabMode:                            http.StatusForbidden,
		fmt.Errorf("wrapped: %w", users.ErrPasswordChangeLabMode): http.StatusForbidden,
		users.ErrNotFound:                                         http.StatusNotFound,
		errors.New("password required"):                           http.StatusBadRequest,
	} {
		if got := setPasswordErrorStatus(err); got != want {
			t.Errorf("setPasswordErrorStatus(%v) = %d, want %d", err, got, want)
		}
	}
}
