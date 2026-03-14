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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// ---------------------------------------------------------------------------
// Mock users.Store
// ---------------------------------------------------------------------------

type mockUserStore struct {
	users    map[string]*users.StoredUser // keyed by ID
	sessions map[string]*users.Session    // keyed by session ID
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{
		users:    make(map[string]*users.StoredUser),
		sessions: make(map[string]*users.Session),
	}
}

func (m *mockUserStore) List(_ context.Context) ([]users.User, error) {
	out := make([]users.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u.User)
	}
	return out, nil
}

func (m *mockUserStore) GetByUsername(_ context.Context, username string) (*users.StoredUser, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, users.ErrNotFound
}

func (m *mockUserStore) GetByID(_ context.Context, id string) (*users.StoredUser, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, users.ErrNotFound
	}
	return u, nil
}

func (m *mockUserStore) Create(_ context.Context, u users.User, password string) (*users.User, error) {
	for _, existing := range m.users {
		if existing.Username == u.Username {
			return nil, users.ErrUsernameTaken
		}
	}
	if u.ID == "" {
		u.ID = "u-" + u.Username
	}
	if u.Role == "" {
		u.Role = "view"
	}
	hash, _ := hashPassword(password)
	m.users[u.ID] = &users.StoredUser{User: u, PasswordHash: hash}
	return &u, nil
}

func (m *mockUserStore) Update(_ context.Context, id string, patch users.User) (*users.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, users.ErrNotFound
	}
	if patch.FirstName != "" {
		u.FirstName = patch.FirstName
	}
	if patch.LastName != "" {
		u.LastName = patch.LastName
	}
	if patch.Email != "" {
		u.Email = patch.Email
	}
	if patch.Role != "" {
		u.Role = patch.Role
	}
	return &u.User, nil
}

func (m *mockUserStore) Delete(_ context.Context, id string) error {
	if _, ok := m.users[id]; !ok {
		return users.ErrNotFound
	}
	// Protect last admin.
	adminCount := 0
	for _, u := range m.users {
		if u.Role == "admin" {
			adminCount++
		}
	}
	if m.users[id].Role == "admin" && adminCount <= 1 {
		return users.ErrLastAdmin
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserStore) SetPassword(_ context.Context, id string, password string) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	hash, _ := hashPassword(password)
	u.PasswordHash = hash
	u.MustChangePassword = false
	return nil
}

func (m *mockUserStore) SetTOTP(_ context.Context, id string, secret string) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	u.TOTPSecret = secret
	u.MFAEnabled = secret != ""
	return nil
}

func (m *mockUserStore) DisableTOTP(_ context.Context, id string) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	u.TOTPSecret = ""
	u.MFAEnabled = false
	u.MFAGraceUntil = nil
	return nil
}

func (m *mockUserStore) SetMFARequirement(_ context.Context, id string, required bool, graceUntil *time.Time) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	u.MFARequired = required
	if graceUntil == nil {
		u.MFAGraceUntil = nil
	} else {
		t := graceUntil.UTC()
		u.MFAGraceUntil = &t
	}
	return nil
}

func (m *mockUserStore) EnsureDefaultAdmin(_ context.Context) error { return nil }

func (m *mockUserStore) CreateSession(_ context.Context, userID string, idleTTL time.Duration, maxTTL time.Duration) (*users.Session, error) {
	now := time.Now().UTC()
	s := &users.Session{
		ID:        "sess-" + userID,
		UserID:    userID,
		IssuedAt:  now,
		LastSeen:  now,
		ExpiresAt: now.Add(idleTTL),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockUserStore) GetSession(_ context.Context, id string) (*users.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, users.ErrNotFound
	}
	return s, nil
}

func (m *mockUserStore) TouchSession(_ context.Context, id string, idleTTL time.Duration, maxTTL time.Duration) (*users.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, users.ErrNotFound
	}
	s.LastSeen = time.Now().UTC()
	newExp := s.LastSeen.Add(idleTTL)
	maxExp := s.IssuedAt.Add(maxTTL)
	if newExp.After(maxExp) {
		newExp = maxExp
	}
	s.ExpiresAt = newExp
	return s, nil
}

func (m *mockUserStore) RevokeSession(_ context.Context, id string) error {
	if s, ok := m.sessions[id]; ok {
		s.Revoked = true
	}
	return nil
}

func (m *mockUserStore) Close() error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// hashPassword is a fast bcrypt hash for tests (minimal cost).
func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	return string(h), err
}

func testSensitiveValue(label string) string {
	return label + "-Aa1!"
}

// testJWTSecret is a dummy HMAC key used only in unit tests — not a real credential.
var testJWTSecret = testSensitiveValue("jwt-signing-key") //nolint:gosec // test-only value

// testPassword is a dummy password used only in unit tests — not a real credential.
var testPassword = testSensitiveValue("unit-user-auth") //nolint:gosec // test-only value

// loginBody builds a JSON login request body without literal credential strings in source.
func loginBody(user, pw string) *bytes.Buffer {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pw}) //nolint:gosec
	return bytes.NewBuffer(b)
}

// createUserBody builds a JSON create-user request body.
func createUserBody(user, role, pw string) *bytes.Buffer {
	b, _ := json.Marshal(map[string]string{"username": user, "role": role, "password": pw}) //nolint:gosec
	return bytes.NewBuffer(b)
}

// signTestJWT creates a valid HS256 JWT for testing.
func signTestJWT(secret []byte, userID, username, role, jti string, exp time.Time) string {
	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"role":     role,
		"jti":      jti,
		"iat":      time.Now().UTC().Unix(),
		"exp":      exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString(secret)
	return s
}

func currentTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    users.TOTPPeriod,
		Skew:      users.TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	return code
}

// setupJWTServer creates a gin engine wired with JWT auth via the given user store.
// It sets CONTAIND_JWT_SECRET and clears legacy tokens so the JWT path is used.
func setupJWTServer(store config.Store, us *mockUserStore) *gin.Engine {
	resetTestRateLimiters()
	return NewServerWithEngineAndServices(store, nil, nil, nil, us)
}

func resetTestRateLimiters() {
	loginLimiter = ratelimit.NewAttemptLimiter(1*time.Minute, 10, 2*time.Minute)
	sensitiveWriteLimiter = ratelimit.NewAttemptLimiter(1*time.Minute, 30, 1*time.Minute)
}

// jwtAuthedRequest creates an HTTP request with a JWT bearer token.
func jwtAuthedRequest(method, path string, body *bytes.Buffer, token string) *http.Request {
	var r *http.Request
	if body != nil {
		r, _ = http.NewRequest(method, path, body)
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func cookieAuthedRequest(method, path string, body *bytes.Buffer, token string, origin string) *http.Request {
	var r *http.Request
	if body != nil {
		r, _ = http.NewRequest(method, path, body)
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	r.AddCookie(&http.Cookie{Name: "containd_token", Value: token})
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

// addTestAdmin adds an admin user to the mock store and returns a valid JWT + session.
func addTestAdmin(us *mockUserStore, secret []byte) (token string, userID string) {
	return addTestUser(us, secret, "admin-1", "containd", "admin", false)
}

// addTestUser adds a user and creates a session, returns a valid JWT.
func addTestUser(us *mockUserStore, secret []byte, id, username, role string, mustChange bool) (token string, userID string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	u := &users.StoredUser{
		User: users.User{
			ID:                 id,
			Username:           username,
			Role:               role,
			MustChangePassword: mustChange,
		},
		PasswordHash: string(hash),
	}
	us.users[id] = u
	sess := &users.Session{
		ID:        "sess-" + id,
		UserID:    id,
		IssuedAt:  time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	us.sessions[sess.ID] = sess
	tok := signTestJWT(secret, id, username, role, sess.ID, sess.ExpiresAt)
	return tok, id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
	if _, ok := body["commit"]; ok {
		t.Fatalf("health endpoint must not expose commit metadata")
	}
	if _, ok := body["hostname"]; ok {
		t.Fatalf("health endpoint must not expose hostname metadata")
	}
}

func TestHealthNoAuthRequired(t *testing.T) {
	// Health endpoint should work without any auth header.
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health without auth: expected 200, got %d", rec.Code)
	}
}

func TestProtectedEndpointRejectsUnauthenticated(t *testing.T) {
	// With legacy token auth, a request without a token should get 401.
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/config", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProtectedEndpointRejectsInvalidToken(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGetConfigReturnsDefault(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/config", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var cfg config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestSaveConfigRejectsBadJSON(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config", bytes.NewBufferString(`not json`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", rec.Code)
	}
}

func TestGetSyslogDefault(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/services/syslog", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestSetAndGetDNS(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	// Set DNS config.
	body := `{"enabled":true,"upstreamServers":["8.8.8.8","1.1.1.1"]}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/services/dns", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set DNS expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Get DNS config.
	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/dns", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get DNS expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"8.8.8.8"`)) {
		t.Fatalf("DNS config not persisted: %s", rec.Body.String())
	}
}

func TestSetAndGetNTP(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	body := `{"enabled":true,"servers":["pool.ntp.org"]}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/services/ntp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set NTP expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/ntp", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get NTP expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"pool.ntp.org"`)) {
		t.Fatalf("NTP config not persisted: %s", rec.Body.String())
	}
}

func TestBackupPathTraversalProtection(t *testing.T) {
	// The backup download/delete endpoints should reject IDs containing path traversal.
	s := NewServer(&mockStore{}, nil)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/config/backups/../../../etc/passwd"},
		{http.MethodDelete, "/api/v1/config/backups/../../../etc/passwd"},
		{http.MethodGet, "/api/v1/config/backups/..%2F..%2Fetc%2Fpasswd"},
	}

	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := authedRequest(tc.method, tc.path, nil)
		s.ServeHTTP(rec, req)
		// Should either 404 (gin can't match route) or return a safe error.
		// Must NOT return 200.
		if rec.Code == http.StatusOK {
			t.Fatalf("path traversal attempt should not succeed: %s %s got 200", tc.method, tc.path)
		}
	}
}

func TestBackupIDSanitization(t *testing.T) {
	// A backup ID with path separators should be sanitized and not find a real file.
	s := NewServer(&mockStore{}, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/config/backups/..%2Fpasswd", nil)
	s.ServeHTTP(rec, req)
	// After sanitization the ID becomes "invalid" and won't find a file -> 404.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for sanitized backup ID, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	s.ServeHTTP(rec, req)
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options: nosniff header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options: DENY header")
	}
}
