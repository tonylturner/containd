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
	"golang.org/x/crypto/bcrypt"

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

// testJWTSecret is the secret used when CONTAIND_JWT_SECRET is set for JWT tests.
const testJWTSecret = "test-jwt-secret-for-handlers"

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

// setupJWTServer creates a gin engine wired with JWT auth via the given user store.
// It sets CONTAIND_JWT_SECRET and clears legacy tokens so the JWT path is used.
func setupJWTServer(store config.Store, us *mockUserStore) *gin.Engine {
	return NewServerWithEngineAndServices(store, nil, nil, nil, us)
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

// addTestAdmin adds an admin user to the mock store and returns a valid JWT + session.
func addTestAdmin(us *mockUserStore, secret []byte) (token string, userID string) {
	return addTestUser(us, secret, "admin-1", "containd", "admin", false)
}

// addTestUser adds a user and creates a session, returns a valid JWT.
func addTestUser(us *mockUserStore, secret []byte, id, username, role string, mustChange bool) (token string, userID string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 4)
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

func TestLoginEmptyCredentials(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username":"","password":""}`)
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
	// Add a user to try wrong password against.
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), 4)
	us.users["u1"] = &users.StoredUser{
		User:         users.User{ID: "u1", Username: "admin", Role: "admin"},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username":"admin","password":"wrong-password"}`)
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
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), 4)
	us.users["u1"] = &users.StoredUser{
		User:         users.User{ID: "u1", Username: "admin", Role: "admin"},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username":"admin","password":"correct-password"}`)
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

func TestLoginRateLimiting(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	s := setupJWTServer(&mockStore{}, us)

	// Fire many failed login attempts to trigger rate limiting.
	// The loginLimiter allows 10 attempts per minute, so 11 should trigger it.
	var lastCode int
	for i := 0; i < 15; i++ {
		rec := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"username":"nobody","password":"wrong"}`)
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

	// Expire the session.
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

	// Revoke the session.
	us.sessions["sess-"+uid].Revoked = true

	s := setupJWTServer(&mockStore{}, us)
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked session, got %d body=%s", rec.Code, rec.Body.String())
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

func TestUserCRUD(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, _ := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	// Create user.
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username":"viewer1","role":"view","password":"Str0ng!Pass"}`)
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

	// List users.
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/users", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users expected 200, got %d", rec.Code)
	}

	// Update user.
	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"firstName":"Test"}`)
	req = jwtAuthedRequest(http.MethodPatch, "/api/v1/users/"+created.ID, body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update user expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Delete user.
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodDelete, "/api/v1/users/"+created.ID, nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user expected 200, got %d body=%s", rec.Code, rec.Body.String())
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

	body := `{"username":"containd","role":"view","password":"Str0ng!Pass"}`
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body), tok)
	s.ServeHTTP(rec, req)
	// "containd" username is already taken by the admin we added.
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

	// Non-password endpoints should return 403.
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for must-change-password user on /config, got %d body=%s", rec.Code, rec.Body.String())
	}

	// /auth/me should still work.
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me even with must-change-password, got %d body=%s", rec.Code, rec.Body.String())
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

	// POST /config requires admin.
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"zones":[{"name":"it"}]}`)
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/config", body, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer on admin endpoint, got %d body=%s", rec.Code, rec.Body.String())
	}

	// GET /config should work for viewer (read-only).
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer on read endpoint, got %d body=%s", rec.Code, rec.Body.String())
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
