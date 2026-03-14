// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestLoginEmptyCredentials(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := loginBody("", "")
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty creds, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	us.users["u1"] = &users.StoredUser{
		User:         users.User{ID: "u1", Username: "admin", Role: "admin"},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := loginBody("admin", "deliberately-wrong")
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad password, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginSuccess(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	us.users["u1"] = &users.StoredUser{
		User:         users.User{ID: "u1", Username: "admin", Role: "admin"},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid login, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token in login response")
	}
}

func TestLoginRejectsOversizedBody(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = defaultJSONBodyLimit + 1
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized login body, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteAllowsNonBrowserAutomation(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "")
	req.Host = "containd.local"
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-browser cookie-authenticated write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteAllowsSameOrigin(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://containd.local")
	req.Host = "containd.local"
	req.TLS = &tls.ConnectionState{}
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for same-origin cookie-authenticated write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteAllowsSameOriginWithDefaultHTTPSPort(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://containd.local:443")
	req.Host = "containd.local"
	req.TLS = &tls.ConnectionState{}
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for same-origin cookie-authenticated write with default port, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteAllowsForwardedDefaultHTTPSPort(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://containd.local")
	req.Host = "internal.containd:8080"
	req.Header.Set("X-Forwarded-Host", "containd.local:443")
	req.Header.Set("X-Forwarded-Proto", "https")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for forwarded same-origin cookie-authenticated write with default port, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteRejectsCrossOrigin(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://portal.example.com")
	req.Host = "containd.local"
	req.TLS = &tls.ConnectionState{}
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin cookie-authenticated write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedCrossOriginWriteDoesNotRefreshSession(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, userID := addTestAdmin(us, []byte(testJWTSecret))
	sessID := "sess-" + userID
	originalSeen := time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC)
	us.sessions[sessID].IssuedAt = originalSeen.Add(-10 * time.Minute)
	us.sessions[sessID].LastSeen = originalSeen
	us.sessions[sessID].ExpiresAt = originalSeen.Add(30 * time.Minute)

	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://portal.example.com")
	req.Host = "containd.local"
	req.TLS = &tls.ConnectionState{}
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin cookie-authenticated write, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := us.sessions[sessID].LastSeen; !got.Equal(originalSeen) {
		t.Fatalf("expected cross-origin rejection to leave session untouched, lastSeen=%s want=%s", got.Format(time.RFC3339Nano), originalSeen.Format(time.RFC3339Nano))
	}
}

func TestCookieAuthedWriteAllowsConfiguredOrigin(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_ALLOWED_ORIGINS", "https://portal.example.com")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "https://portal.example.com")
	req.Host = "containd.local"
	req.TLS = &tls.ConnectionState{}
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowlisted origin, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuthedWriteRejectsCrossSiteFetch(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := cookieAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token, "")
	req.Host = "containd.local"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-site cookie-authenticated write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBearerAuthedWriteDoesNotRequireOrigin(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), token)
	req.Host = "containd.local"
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for bearer-authenticated write without origin, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginRequiresMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	enrollment, err := users.GenerateTOTPEnrollment("containd", "admin")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	us.users["u1"] = &users.StoredUser{
		User: users.User{
			ID:         "u1",
			Username:   "admin",
			Role:       "admin",
			MFAEnabled: true,
		},
		PasswordHash: string(hash),
		TOTPSecret:   enrollment.Secret,
	}
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for MFA challenge, got %d body=%s", rec.Code, rec.Body.String())
	}
	var challenge mfaLoginChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("invalid mfa challenge response: %v", err)
	}
	if !challenge.MFARequired || challenge.MFAChallengeToken == "" {
		t.Fatalf("expected MFA challenge response, got %+v", challenge)
	}

	verifyBody, _ := json.Marshal(map[string]string{
		"challengeToken": challenge.MFAChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", bytes.NewBuffer(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for MFA verify login, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token after MFA verification")
	}
}

func TestLoginAllowsPendingMFADuringGrace(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	deadline := time.Now().UTC().Add(24 * time.Hour)
	us.users["u1"] = &users.StoredUser{
		User: users.User{
			ID:            "u1",
			Username:      "admin",
			Role:          "admin",
			MFARequired:   true,
			MFAGraceUntil: &deadline,
		},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for grace-period login, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token during MFA grace login")
	}
	if !resp.User.MFARequired || resp.User.MFAEnabled {
		t.Fatalf("expected pending MFA requirement in login response, got %+v", resp.User)
	}
}

func TestLoginRateLimiting(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	s := setupJWTServer(&mockStore{}, us)

	var lastCode int
	for i := 0; i < 15; i++ {
		rec := httptest.NewRecorder()
		body := loginBody("nobody", "wrong")
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.99:12345"
		s.ServeHTTP(rec, req)
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after many attempts, got %d", lastCode)
	}
}

func TestLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/logout", nil, tok)
	req.AddCookie(&http.Cookie{Name: "containd_token", Value: tok})
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for logout, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !us.sessions["sess-"+uid].Revoked {
		t.Fatal("expected logout to revoke the active session")
	}
	if setCookie := rec.Header().Get("Set-Cookie"); !strings.Contains(setCookie, "containd_token=") {
		t.Fatalf("expected auth cookie to be cleared, got Set-Cookie=%q", setCookie)
	}
}

func TestLegacyAuthAccountHandlersWithoutUserStore(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", "")
	t.Setenv("CONTAIND_ADMIN_TOKEN", testAdminToken)
	t.Setenv("CONTAIND_LAB_MODE", "0")

	s := NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/auth/me", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me with legacy auth, got %d body=%s", rec.Code, rec.Body.String())
	}
	var me map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("invalid /auth/me JSON: %v", err)
	}
	if me["role"] != "admin" {
		t.Fatalf("expected admin role, got %v", me["role"])
	}
	if me["labMode"] != false {
		t.Fatalf("expected labMode false, got %v", me["labMode"])
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/auth/session", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/session with legacy auth, got %d body=%s", rec.Code, rec.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("invalid /auth/session JSON: %v", err)
	}
	if session["role"] != "admin" {
		t.Fatalf("expected session role admin, got %v", session["role"])
	}
	if got := int(session["idleTTLSeconds"].(float64)); got != int(idleTTL.Seconds()) {
		t.Fatalf("expected idleTTLSeconds=%d, got %d", int(idleTTL.Seconds()), got)
	}
	if got := int(session["maxTTLSeconds"].(float64)); got != int(maxTTL.Seconds()) {
		t.Fatalf("expected maxTTLSeconds=%d, got %d", int(maxTTL.Seconds()), got)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPatch, "/api/v1/auth/me", bytes.NewBufferString(`{"firstName":"Legacy"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for /auth/me patch without user store, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/auth/me/password", bytes.NewBufferString(`{"currentPassword":"x","newPassword":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for /auth/me/password without user store, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionAndAccountSelfServiceHandlers(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	us.users[uid].FirstName = "Ada"
	us.users[uid].LastName = "Lovelace"
	us.users[uid].Email = "ada@example.com"
	us.users[uid].MFAEnabled = true
	us.users[uid].MFARequired = true
	grace := time.Now().UTC().Add(24 * time.Hour)
	us.users[uid].MFAGraceUntil = &grace
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, tok)
	req.RemoteAddr = "203.0.113.10:4123"
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me, got %d body=%s", rec.Code, rec.Body.String())
	}
	var me map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("invalid /auth/me JSON: %v", err)
	}
	if me["firstName"] != "Ada" || me["lastName"] != "Lovelace" || me["email"] != "ada@example.com" {
		t.Fatalf("expected profile fields in /auth/me, got %+v", me)
	}
	if me["mfaEnabled"] != true || me["mfaRequired"] != true {
		t.Fatalf("expected MFA flags in /auth/me, got %+v", me)
	}
	if _, ok := me["mfaGraceUntil"].(string); !ok {
		t.Fatalf("expected mfaGraceUntil string, got %+v", me)
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/auth/session", nil, tok)
	req.RemoteAddr = "203.0.113.10:4123"
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/session, got %d body=%s", rec.Code, rec.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("invalid /auth/session JSON: %v", err)
	}
	if session["sessionId"] != "sess-"+uid {
		t.Fatalf("expected sessionId sess-%s, got %v", uid, session["sessionId"])
	}
	if session["authenticatedAs"] != "containd" {
		t.Fatalf("expected authenticatedAs containd, got %v", session["authenticatedAs"])
	}
	if session["clientIP"] != "203.0.113.10" {
		t.Fatalf("expected clientIP 203.0.113.10, got %v", session["clientIP"])
	}
	userObj, ok := session["user"].(map[string]any)
	if !ok || userObj["username"] != "containd" {
		t.Fatalf("expected session user payload, got %+v", session["user"])
	}
	for _, field := range []string{"expiresAt", "issuedAt", "lastSeen"} {
		if _, ok := session[field].(string); !ok {
			t.Fatalf("expected %s in /auth/session, got %+v", field, session)
		}
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPatch, "/api/v1/auth/me", bytes.NewBufferString(`{"firstName":"Grace","lastName":"Hopper","email":"grace@example.com"}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me patch, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[uid].FirstName != "Grace" || us.users[uid].LastName != "Hopper" || us.users[uid].Email != "grace@example.com" {
		t.Fatalf("expected user profile to be updated, got %+v", us.users[uid].User)
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/password", bytes.NewBufferString(`{"currentPassword":"wrong","newPassword":"Containd9"}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid current password, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/password", bytes.NewBufferString(`{"currentPassword":"`+testPassword+`"}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing newPassword, got %d body=%s", rec.Code, rec.Body.String())
	}

	us.users[uid].MustChangePassword = true
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/password", bytes.NewBufferString(`{"currentPassword":"`+testPassword+`","newPassword":"Containd9"}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid password change, got %d body=%s", rec.Code, rec.Body.String())
	}
	if bcrypt.CompareHashAndPassword([]byte(us.users[uid].PasswordHash), []byte("Containd9")) != nil {
		t.Fatal("expected password hash to be updated")
	}
	if us.users[uid].MustChangePassword {
		t.Fatal("expected successful password change to clear MustChangePassword")
	}
}

func TestJWTProtectedEndpointWithValidToken(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid JWT, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestJWTProtectedEndpointRejectsExpiredSession(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)

	sess := us.sessions["sess-"+uid]
	sess.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)

	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestJWTProtectedEndpointRejectsRevokedSession(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	us.sessions["sess-"+uid].Revoked = true

	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked session, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUserCRUD(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := createUserBody("viewer1", "view", testPassword)
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users", body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created users.User
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Username != "viewer1" {
		t.Fatalf("expected username viewer1, got %q", created.Username)
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/users", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"firstName":"Test"}`)
	req = jwtAuthedRequest(http.MethodPatch, "/api/v1/users/"+created.ID, body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update user expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodDelete, "/api/v1/users/"+created.ID, nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSelfMFAEnrollEnableDisable(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollment); err != nil {
		t.Fatalf("invalid enroll response: %v", err)
	}
	if enrollment.Secret == "" || enrollment.ChallengeToken == "" {
		t.Fatalf("expected enrollment secret and challenge token, got %+v", enrollment)
	}

	enableBody, _ := json.Marshal(map[string]string{
		"challengeToken": enrollment.ChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enable", bytes.NewBuffer(enableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !us.users[uid].MFAEnabled {
		t.Fatal("expected MFA to be enabled")
	}

	disableBody, _ := json.Marshal(map[string]string{
		"currentPassword": testPassword,
		"code":            currentTOTPCode(t, us.users[uid].TOTPSecret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/disable", bytes.NewBuffer(disableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[uid].MFAEnabled {
		t.Fatal("expected MFA to be disabled")
	}
}

func TestRequiredUserCannotSelfDisableMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	us.users[uid].MFARequired = true
	enrollment, err := users.GenerateTOTPEnrollment("containd", "admin")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	us.users[uid].MFAEnabled = true
	us.users[uid].TOTPSecret = enrollment.Secret
	s := setupJWTServer(&mockStore{}, us)

	disableBody, _ := json.Marshal(map[string]string{
		"currentPassword": testPassword,
		"code":            currentTOTPCode(t, us.users[uid].TOTPSecret),
	})
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/disable", bytes.NewBuffer(disableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when required user disables MFA, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminCanDisableUserMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-2", "viewer2", "view", false)
	us.users[userID].MFAEnabled = true
	us.users[userID].TOTPSecret = "JBSWY3DPEHPK3PXP"
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/disable", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAEnabled {
		t.Fatal("expected target MFA to be disabled by admin")
	}
}

func TestAdminDisableRequiredUserMFASetsGrace(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-3", "viewer3", "view", false)
	us.users[userID].MFARequired = true
	us.users[userID].MFAEnabled = true
	us.users[userID].TOTPSecret = "JBSWY3DPEHPK3PXP"
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/disable", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAEnabled {
		t.Fatal("expected target MFA to be disabled by admin")
	}
	if !us.users[userID].MFARequired || us.users[userID].MFAGraceUntil == nil {
		t.Fatalf("expected required MFA user to receive new grace window, got %+v", us.users[userID].User)
	}
}

func TestAdminCanRequireClearAndExtendUserMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-4", "viewer4", "view", false)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/require", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("require mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !us.users[userID].MFARequired || us.users[userID].MFAGraceUntil == nil {
		t.Fatalf("expected user MFA requirement with grace, got %+v", us.users[userID].User)
	}
	firstDeadline := us.users[userID].MFAGraceUntil.UTC()

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/grace", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("extend mfa grace expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAGraceUntil == nil || !us.users[userID].MFAGraceUntil.After(firstDeadline) {
		t.Fatalf("expected extended grace deadline after %v, got %+v", firstDeadline, us.users[userID].MFAGraceUntil)
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/clear", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear mfa requirement expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFARequired || us.users[userID].MFAGraceUntil != nil {
		t.Fatalf("expected cleared MFA requirement, got %+v", us.users[userID].User)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	body := createUserBody("containd", "view", testPassword)
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users", body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate username, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeleteLastAdminRejected(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodDelete, "/api/v1/users/"+uid, nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for deleting last admin, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMustChangePasswordEnforcement(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestUser(us, secret, "forced-1", "forced", "admin", true)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for must-change-password user on /config, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me even with must-change-password, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExpiredMFARequirementRestrictsUntilEnabled(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	expired := time.Now().UTC().Add(-1 * time.Hour)
	us.users[uid].MFARequired = true
	us.users[uid].MFAGraceUntil = &expired
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired MFA requirement on /config, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me/mfa/enroll during restricted session, got %d body=%s", rec.Code, rec.Body.String())
	}
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollment); err != nil {
		t.Fatalf("invalid enroll response: %v", err)
	}

	enableBody, _ := json.Marshal(map[string]string{
		"challengeToken": enrollment.ChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enable", bytes.NewBuffer(enableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me/mfa/enable during restricted session, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /config after enabling MFA, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestViewerCannotAccessAdminEndpoints(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestUser(us, secret, "viewer-1", "viewer", "view", false)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"zones":[{"name":"it"}]}`)
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/config", body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer on admin endpoint, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer on read endpoint, got %d body=%s", rec.Code, rec.Body.String())
	}
}
