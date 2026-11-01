// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestLabJWTRequiresExpiration(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	us := newMockUserStore()
	_, uid := addTestAdmin(us, []byte(testJWTSecret))
	// No session exists: lab tokens must not consult sessions, even with a jti.
	us.sessions = map[string]*users.Session{}
	router := gin.New()
	router.Use(authMiddleware(us), requireAdmin())
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user": c.GetString(ctxUserKey)})
	})
	for _, tc := range []struct {
		name string
		sub  string
		exp  any
		want int
	}{
		{"missing expiration", uid, nil, http.StatusUnauthorized},
		{"malformed expiration", uid, "tomorrow", http.StatusUnauthorized},
		{"expired", uid, time.Now().Add(-time.Minute).Unix(), http.StatusUnauthorized},
		{"within leeway", uid, time.Now().Add(-10 * time.Second).Unix(), http.StatusOK},
		{"unexpired", uid, time.Now().Add(time.Hour).Unix(), http.StatusOK},
		{"RangerDanger session-less admin", "rangerdanger-backend", time.Now().Add(24 * time.Hour).Unix(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"sub": tc.sub, "role": "admin"}
			if tc.sub == uid {
				claims["jti"] = "absent-session"
			}
			if tc.exp != nil {
				claims["exp"] = tc.exp
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/", nil, token))
			if rec.Code != tc.want {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if tc.want == http.StatusOK && rec.Body.String() != `{"user":"`+uid+`"}` {
				t.Fatalf("lab user context = %s, want %s", rec.Body.String(), uid)
			}
		})
	}
}

func TestLabLoginResolvesActualAccount(t *testing.T) {
	for _, username := range []string{"containd", "workshop-admin"} {
		t.Run(username, func(t *testing.T) {
			t.Setenv("CONTAIND_LAB_MODE", "1")
			t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
			t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", username)
			t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
			resetTestRateLimiters()
			store, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.EnsureDefaultAdmin(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Keep another account named containd to catch wrong-account resolution.
			if username != "containd" {
				if _, err := store.Create(context.Background(), users.User{Username: "containd", Role: "admin"}, testPassword); err != nil {
					t.Fatal(err)
				}
			}
			server := NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, store)
			body, err := json.Marshal(map[string]string{"username": username, "password": "containd"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			var login struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &login); err != nil || rec.Code != http.StatusOK || login.Token == "" {
				t.Fatalf("login = %d %s, %v", rec.Code, rec.Body.String(), err)
			}
			rec = httptest.NewRecorder()
			server.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, login.Token))
			var me users.User
			if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != http.StatusOK || me.Username != username {
				t.Fatalf("profile = %d %s, %v; want %s", rec.Code, rec.Body.String(), err, username)
			}
			// A signed token for a different local account must not select the
			// configured bootstrap account merely because lab mode is enabled.
			other, err := store.Create(context.Background(), users.User{Username: "other-user", Role: "view"}, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			otherToken := signTestJWT([]byte(testJWTSecret), other.ID, other.Username, other.Role, "", time.Now().Add(time.Hour))
			rec = httptest.NewRecorder()
			server.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, otherToken))
			if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != http.StatusOK || me.ID != other.ID {
				t.Fatalf("other profile = %d %s, %v; want %s", rec.Code, rec.Body.String(), err, other.ID)
			}
			automationToken := signTestJWT([]byte(testJWTSecret), "rangerdanger-backend", "", "admin", "", time.Now().Add(time.Hour))
			rec = httptest.NewRecorder()
			server.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/api/v1/auth/me", nil, automationToken))
			if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || rec.Code != http.StatusOK || me.Username != username {
				t.Fatalf("automation profile = %d %s, %v; want %s", rec.Code, rec.Body.String(), err, username)
			}
		})
	}
}

func TestLabWithoutSecretUsesConfiguredBootstrapAccount(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "workshop-admin")
	us := newMockUserStore()
	_, uid := addTestUser(us, nil, "custom-admin", "workshop-admin", "admin", false)
	router := gin.New()
	router.Use(authMiddleware(us))
	router.GET("/", func(c *gin.Context) { c.String(http.StatusOK, c.GetString(ctxUserKey)) })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/", nil, "lab-token"))
	if rec.Code != http.StatusOK || rec.Body.String() != uid {
		t.Fatalf("unsigned lab context = %d %q, want %q", rec.Code, rec.Body.String(), uid)
	}
}
