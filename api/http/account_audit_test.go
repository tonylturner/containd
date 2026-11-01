// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type accountFixture struct {
	server  http.Handler
	users   *users.SQLiteStore
	audits  *audit.SQLiteStore
	adminID string
}

// newAccountFixture serves the API in standard mode over real users and audit
// stores holding one admin whose password is testPassword.
func newAccountFixture(t *testing.T) accountFixture {
	t.Helper()
	t.Setenv("CONTAIND_LAB_MODE", "")
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	resetTestRateLimiters()
	dir := t.TempDir()
	userStore, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = userStore.Close() })
	auditStore, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	admin, err := userStore.Create(context.Background(), users.User{Username: "acct-admin", Role: "admin"}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return accountFixture{
		server:  NewServerWithEngineAndServices(&mockStore{}, auditStore, nil, nil, userStore),
		users:   userStore,
		audits:  auditStore,
		adminID: admin.ID,
	}
}

// session returns a bearer token and its session ID for userID.
func (f accountFixture) session(t *testing.T, userID string) (string, string) {
	t.Helper()
	u, err := f.users.GetByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := f.users.CreateSession(context.Background(), u.ID, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return signTestJWT([]byte(testJWTSecret), u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt), sess.ID
}

func (f accountFixture) do(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewBuffer(raw)
	}
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, f.server, rec, jwtAuthedRequest(method, path, buf, token))
	return rec.Code, rec.Body.Bytes()
}

func (f accountFixture) mustDo(t *testing.T, method, path, token string, body any) []byte {
	t.Helper()
	code, resp := f.do(t, method, path, token, body)
	if code != http.StatusOK {
		t.Fatalf("%s %s = %d %s", method, path, code, resp)
	}
	return resp
}

func (f accountFixture) revoked(t *testing.T, sessionID string) bool {
	t.Helper()
	sess, err := f.users.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Revoked
}

func requireAudit(t *testing.T, store audit.Store, action, target, result string) {
	t.Helper()
	records, err := store.List(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Action == action && r.Target == target && r.Result == result {
			if r.Actor != "acct-admin" {
				t.Fatalf("%s actor = %q", action, r.Actor)
			}
			return
		}
	}
	t.Fatalf("no %s %s audit for %q in %+v", result, action, target, records)
}

func TestAccountMutationsAreAudited(t *testing.T) {
	f := newAccountFixture(t)
	token, _ := f.session(t, f.adminID)

	var created users.User
	resp := f.mustDo(t, http.MethodPost, "/api/v1/users", token, map[string]string{"username": "operator", "role": "view", "password": testPassword})
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	requireAudit(t, f.audits, "auth.user.create", "operator", "success")

	f.mustDo(t, http.MethodPatch, "/api/v1/users/"+created.ID, token, map[string]string{"role": "admin"})
	requireAudit(t, f.audits, "auth.user.update", "operator", "success")

	_, operatorSession := f.session(t, created.ID)
	f.mustDo(t, http.MethodPost, "/api/v1/users/"+created.ID+"/password", token, map[string]string{"password": testSensitiveValue("operator-reset")})
	requireAudit(t, f.audits, "auth.password.set_admin", "operator", "success")
	if !f.revoked(t, operatorSession) {
		t.Fatal("admin password set kept the account's session")
	}

	f.mustDo(t, http.MethodPatch, "/api/v1/auth/me", token, map[string]string{"firstName": "Ada"})
	requireAudit(t, f.audits, "auth.profile.update", "acct-admin", "success")

	f.mustDo(t, http.MethodDelete, "/api/v1/users/"+created.ID, token, nil)
	requireAudit(t, f.audits, "auth.user.delete", "operator", "success")
	if code, _ := f.do(t, http.MethodDelete, "/api/v1/users/"+created.ID, token, nil); code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", code)
	}
}

func TestOwnPasswordChangeKeepsOnlyCurrentSession(t *testing.T) {
	f := newAccountFixture(t)
	token, current := f.session(t, f.adminID)
	_, other := f.session(t, f.adminID)

	if code, _ := f.do(t, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": "wrong", "newPassword": testSensitiveValue("own")}); code != http.StatusUnauthorized {
		t.Fatalf("wrong current password = %d", code)
	}
	requireAudit(t, f.audits, "auth.password.change", "acct-admin", "denied")
	if f.revoked(t, other) {
		t.Fatal("refused change revoked a session")
	}
	if code, body := f.do(t, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": testPassword, "newPassword": testPassword}); code != http.StatusBadRequest {
		t.Fatalf("password reuse = %d %s", code, body)
	}

	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": testPassword, "newPassword": testSensitiveValue("own")})
	requireAudit(t, f.audits, "auth.password.change", "acct-admin", "success")
	if f.revoked(t, current) || !f.revoked(t, other) {
		t.Fatalf("revoked current=%v other=%v, want false true", f.revoked(t, current), f.revoked(t, other))
	}
	f.mustDo(t, http.MethodGet, "/api/v1/auth/me", token, nil)
}

func TestMFAChangesRevokeOtherSessions(t *testing.T) {
	f := newAccountFixture(t)
	token, current := f.session(t, f.adminID)
	_, stale := f.session(t, f.adminID)

	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enroll", token, map[string]string{}), &enrollment); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enrollment.ChallengeToken, "code": code})
	if f.revoked(t, current) || !f.revoked(t, stale) {
		t.Fatal("MFA enable must keep only the enrolling session")
	}

	// An admin resetting another account's MFA ends all of that account's sessions.
	target, err := f.users.Create(context.Background(), users.User{Username: "mfa-user", Role: "view"}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetTOTP(context.Background(), target.ID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	_, targetSession := f.session(t, target.ID)
	f.mustDo(t, http.MethodPost, "/api/v1/users/"+target.ID+"/mfa/disable", token, map[string]string{})
	if !f.revoked(t, targetSession) || f.revoked(t, current) {
		t.Fatal("admin MFA reset must revoke only the target's sessions")
	}
}

func TestTLSCertificateReplacementIsAudited(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
	cfg.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	audits := &mockAuditStore{}
	router := gin.New()
	router.Use(withAuditStore(audits))
	router.POST("/upload", func(c *gin.Context) { c.Set("actor", "acct-admin") }, tlsCertUploadHandler(&mockStore{cfg: cfg}, dataDir))
	certPEM, keyPEM := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tls", "server.pem")); err != nil {
		t.Fatal(err)
	}
	requireAudit(t, audits, "system.tls.cert.set", filepath.Join(dataDir, "tls", "server.pem"), "success")
	if detail := audits.records[0].Detail; detail == "" || !bytes.Contains([]byte(detail), []byte("CN=containd.local")) {
		t.Fatalf("audit detail = %q", detail)
	}
}
