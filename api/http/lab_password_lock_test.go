// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLabModeLocksPasswordChange pins the workshop-deployment invariant
// that lab-mode containd refuses to drift the canonical credential. The
// HTTP password-change endpoints (/auth/me/password and
// /users/:id/password) must return 403 with a clear lab-mode message,
// and /auth/me must NOT advertise mustChangePassword (which would
// trigger the UI's force-change flow that hits the same locked endpoint).
//
// Without these locks, a student who completes the first-login force-
// change would drift the cred away from the documented `containd/containd`
// default, which silently breaks every workshop step that uses
// SSH-on-:2222 or proxied containd UI access against that credential.
func TestLabModeLocksPasswordChange(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)

	us := newMockUserStore()
	tok, uid := addTestAdmin(us, []byte(testJWTSecret))
	s := NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, us)

	t.Run("change-my-password locked", func(t *testing.T) {
		body := bytes.NewBufferString(`{"currentPassword":"containd","newPassword":"newhotness"}`)
		rec := httptest.NewRecorder()
		req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/password", body, tok)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for /auth/me/password in lab mode, got %d body=%s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("lab mode")) {
			t.Errorf("expected 'lab mode' in error message, got %s", rec.Body.String())
		}
	})

	t.Run("set-user-password locked", func(t *testing.T) {
		body := bytes.NewBufferString(`{"password":"newhotness"}`)
		rec := httptest.NewRecorder()
		req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+uid+"/password", body, tok)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for /users/:id/password in lab mode, got %d body=%s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("lab mode")) {
			t.Errorf("expected 'lab mode' in error message, got %s", rec.Body.String())
		}
	})

	t.Run("me does not advertise mustChangePassword", func(t *testing.T) {
		// Force the underlying user record to have MustChangePassword=true
		// — replicates the seed state from a fresh DB without lab-mode
		// suppression. The handler should still hide the flag because lab
		// mode pins the cred.
		if u, err := us.GetByID(context.Background(), uid); err == nil && u != nil {
			u.MustChangePassword = true
			us.users[uid] = u
		}

		rec := httptest.NewRecorder()
		req := jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, tok)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /auth/me, got %d body=%s", rec.Code, rec.Body.String())
		}
		var me map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
			t.Fatalf("invalid /auth/me JSON: %v", err)
		}
		if _, present := me["mustChangePassword"]; present {
			t.Errorf("/auth/me must not advertise mustChangePassword in lab mode; got %+v", me)
		}
	})
}
