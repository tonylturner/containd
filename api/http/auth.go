// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type role string

const (
	roleAdmin role = "admin"
	roleView  role = "view"
)

const ctxRoleKey = "role"
const ctxUserKey = "user"
const ctxSessionKey = "session"

const (
	idleTTL = 30 * time.Minute
	maxTTL  = 4 * time.Hour
)

func abortJSON(c *gin.Context, status int, msg string) {
	// Mirror the JSON error message in a header so it's easy to spot in browser DevTools
	// even when the response body isn't surfaced.
	c.Header("X-Containd-Auth-Error", msg)
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}

func jwtSecret() []byte {
	return []byte(strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET")))
}

// authMiddleware enforces JWT bearer auth unless lab mode is enabled.
// If users store is nil, falls back to legacy env tokens for compatibility.
func authMiddleware(userStore users.Store) gin.HandlerFunc {
	cfg := authModeConfig{
		lab:          labmode.Enabled(),
		adminToken:   strings.TrimSpace(os.Getenv("CONTAIND_ADMIN_TOKEN")),
		auditorToken: strings.TrimSpace(os.Getenv("CONTAIND_AUDITOR_TOKEN")),
		secret:       jwtSecret(),
	}
	return func(c *gin.Context) {
		switch {
		case cfg.lab:
			handleLabAuth(c, userStore, cfg)
		case userStore == nil || len(cfg.secret) == 0:
			handleLegacyAuth(c, cfg)
		default:
			handleSessionAuth(c, userStore, cfg)
		}
	}
}

type authModeConfig struct {
	lab          bool
	adminToken   string
	auditorToken string
	secret       []byte
}

func handleLabAuth(c *gin.Context, userStore users.Store, cfg authModeConfig) {
	raw := bearerOrCookie(c)
	if raw == "" {
		abortJSON(c, http.StatusUnauthorized, "login required")
		return
	}
	sub, ok := parseLabSubject(raw, cfg.secret)
	if !ok {
		abortJSON(c, http.StatusUnauthorized, "invalid token")
		return
	}
	c.Set(ctxRoleKey, effectiveUserRole(cfg.lab, ""))
	if userStore != nil {
		var u *users.StoredUser
		var err error
		if len(cfg.secret) > 0 && sub != "" {
			u, err = userStore.GetByID(c.Request.Context(), sub)
		}
		// Session-less automation subjects need not name a local account.
		// They retain the configured bootstrap identity, as do unsigned labs.
		if u == nil && (err == nil || errors.Is(err, users.ErrNotFound)) {
			username := strings.TrimSpace(os.Getenv("CONTAIND_DEFAULT_ADMIN_USERNAME"))
			if username == "" {
				username = "containd"
			}
			u, err = userStore.GetByUsername(c.Request.Context(), username)
		}
		if err == nil && u != nil {
			c.Set(ctxUserKey, u.ID)
			c.Set(ctxSessionKey, "lab")
		}
	}
	c.Next()
}

func handleLegacyAuth(c *gin.Context, cfg authModeConfig) {
	if cfg.adminToken == "" && cfg.auditorToken == "" {
		abortJSON(c, http.StatusServiceUnavailable, "auth not configured; set CONTAIND_JWT_SECRET or legacy CONTAIND_ADMIN_TOKEN")
		return
	}
	tok := requireBearerToken(c)
	if tok == "" {
		return
	}
	switch {
	case cfg.adminToken != "" && tok == cfg.adminToken:
		c.Set(ctxRoleKey, string(roleAdmin))
		c.Next()
	case cfg.auditorToken != "" && tok == cfg.auditorToken:
		c.Set(ctxRoleKey, string(roleView))
		c.Next()
	default:
		abortJSON(c, http.StatusUnauthorized, "invalid token")
	}
}

func handleSessionAuth(c *gin.Context, userStore users.Store, cfg authModeConfig) {
	raw := bearerOrCookie(c)
	if raw == "" {
		abortJSON(c, http.StatusUnauthorized, "missing token")
		return
	}
	claims, ok := parseSessionClaims(c, raw, cfg.secret)
	if !ok {
		return
	}
	sess, ok := loadActiveSession(c, userStore, claims.jti)
	if !ok {
		return
	}
	sess = maybeRefreshSession(c, userStore, cfg.secret, claims, sess)
	u, ok := loadSessionUser(c, userStore, sess, claims.sub)
	if !ok {
		return
	}
	setAuthenticatedContext(c, u, claims.jti)
	if !allowRestrictedAccountPath(c, u) {
		return
	}
	c.Next()
}

func parseLabSubject(raw string, secret []byte) (string, bool) {
	if len(secret) == 0 {
		return "", true
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, jwtKeyFunc(secret), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return "", false
	}
	sub, _ := claims["sub"].(string)
	return sub, true
}

func requireBearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		abortJSON(c, http.StatusUnauthorized, "missing bearer token")
		return ""
	}
	return strings.TrimSpace(h[len("bearer "):])
}

type sessionClaims struct {
	jti string
	sub string
	exp time.Time
}

func parseSessionClaims(c *gin.Context, raw string, secret []byte) (sessionClaims, bool) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, jwtKeyFunc(secret), jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		abortJSON(c, http.StatusUnauthorized, "invalid token")
		return sessionClaims{}, false
	}
	jti, _ := claims["jti"].(string)
	sub, _ := claims["sub"].(string)
	if jti == "" || sub == "" {
		abortJSON(c, http.StatusUnauthorized, "invalid token claims")
		return sessionClaims{}, false
	}
	exp := time.Time{}
	if expFloat, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(expFloat), 0).UTC()
	}
	return sessionClaims{jti: jti, sub: sub, exp: exp}, true
}

func jwtKeyFunc(secret []byte) func(*jwt.Token) (any, error) {
	return func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "HS256" {
			return nil, jwt.ErrSignatureInvalid
		}
		return secret, nil
	}
}

func loadActiveSession(c *gin.Context, userStore users.Store, jti string) (*users.Session, bool) {
	sess, err := userStore.GetSession(c.Request.Context(), jti)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			abortJSON(c, http.StatusUnauthorized, "session revoked")
		} else {
			abortJSON(c, http.StatusServiceUnavailable, "auth backend unavailable")
		}
		return nil, false
	}
	if sess.Revoked {
		abortJSON(c, http.StatusUnauthorized, "session revoked")
		return nil, false
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = userStore.RevokeSession(c.Request.Context(), jti)
		abortJSON(c, http.StatusUnauthorized, "session expired")
		return nil, false
	}
	return sess, true
}

func maybeRefreshSession(c *gin.Context, userStore users.Store, secret []byte, claims sessionClaims, sess *users.Session) *users.Session {
	updated, err := userStore.TouchSession(c.Request.Context(), claims.jti, idleTTL, maxTTL)
	if err != nil {
		return sess
	}
	if claims.exp.IsZero() || expirationMoved(updated.ExpiresAt, claims.exp) {
		u, err := userStore.GetByID(c.Request.Context(), claims.sub)
		if err == nil && u != nil {
			newTok, _ := signJWT(secret, u.ID, u.Username, effectiveUserRole(false, u.Role), claims.jti, updated.ExpiresAt)
			if newTok != "" {
				c.Header("X-Auth-Token", newTok)
				setAuthCookie(c, newTok, updated.ExpiresAt)
			}
		}
	}
	return updated
}

func expirationMoved(updated, tokenExp time.Time) bool {
	return updated.Sub(tokenExp) > 10*time.Second || tokenExp.Sub(updated) > 10*time.Second
}

func loadSessionUser(c *gin.Context, userStore users.Store, sess *users.Session, sub string) (*users.StoredUser, bool) {
	u, err := userStore.GetByID(c.Request.Context(), sub)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			abortJSON(c, http.StatusUnauthorized, "user not found")
		} else {
			abortJSON(c, http.StatusServiceUnavailable, "auth backend unavailable")
		}
		return nil, false
	}
	if u == nil {
		abortJSON(c, http.StatusUnauthorized, "user not found")
		return nil, false
	}
	if sess.UserID != "" && sess.UserID != u.ID {
		abortJSON(c, http.StatusUnauthorized, "session mismatch")
		return nil, false
	}
	return u, true
}

// effectiveUserRole is shared by local-account authentication and login
// responses. Lab subjects select a profile, never a privilege level.
func effectiveUserRole(lab bool, storedRole string) string {
	if lab {
		return string(roleAdmin)
	}
	if storedRole == "" {
		return string(roleView)
	}
	return storedRole
}

// callerProfile copies the account profile without changing its persisted role.
func callerProfile(c *gin.Context, u users.User) users.User {
	u.Role = c.GetString(ctxRoleKey)
	return u
}

func setAuthenticatedContext(c *gin.Context, u *users.StoredUser, jti string) {
	c.Set(ctxRoleKey, effectiveUserRole(false, u.Role))
	c.Set(ctxUserKey, u.ID)
	c.Set(ctxSessionKey, jti)
	c.Set("actor", u.Username)
	// A password or MFA change made by this request keeps this session.
	c.Request = c.Request.WithContext(users.WithActingSession(c.Request.Context(), jti))
}

func allowRestrictedAccountPath(c *gin.Context, u *users.StoredUser) bool {
	passwordChangeRequired := u.MustChangePassword
	mfaSetupRequired := users.IsMFAGraceExpired(u, time.Now())
	if !passwordChangeRequired && !mfaSetupRequired {
		return true
	}
	path := c.Request.URL.Path
	allowed := isBaseRestrictedAuthPath(path)
	if passwordChangeRequired && strings.HasSuffix(path, "/auth/me/password") {
		allowed = true
	}
	if mfaSetupRequired && isMFASetupPath(path) {
		allowed = true
	}
	if allowed {
		return true
	}
	if passwordChangeRequired {
		abortJSON(c, http.StatusForbidden, "password change required")
		return false
	}
	abortJSON(c, http.StatusForbidden, "mfa setup required")
	return false
}

func isBaseRestrictedAuthPath(path string) bool {
	return strings.HasSuffix(path, "/auth/me") ||
		strings.HasSuffix(path, "/auth/session") ||
		strings.HasSuffix(path, "/auth/logout") ||
		strings.HasSuffix(path, "/health")
}

func isMFASetupPath(path string) bool {
	return strings.HasSuffix(path, "/auth/me/mfa/enroll") ||
		strings.HasSuffix(path, "/auth/me/mfa/enable")
}

func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		v, _ := c.Get(ctxRoleKey)
		if v != string(roleAdmin) {
			abortJSON(c, http.StatusForbidden, "admin role required")
			return
		}
		c.Next()
	}
}

func bearerOrCookie(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[len("bearer "):])
	}
	if ck, err := c.Cookie("containd_token"); err == nil {
		return ck
	}
	return ""
}

func setAuthCookie(c *gin.Context, token string, exp time.Time) {
	maxAge := int(time.Until(exp).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	c.SetSameSite(http.SameSiteStrictMode)
	secure := cookieSecure(c)
	c.SetCookie("containd_token", token, maxAge, "/", "", secure, true)
}

func clearAuthCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	secure := cookieSecure(c)
	c.SetCookie("containd_token", "", -1, "/", "", secure, true)
}

// cookieSecure returns true if the Secure flag should be set on auth cookies.
// Auto-detects TLS from the request, and can be overridden via CONTAIND_COOKIE_SECURE.
func cookieSecure(c *gin.Context) bool {
	env := strings.TrimSpace(os.Getenv("CONTAIND_COOKIE_SECURE"))
	if env != "" {
		return env == "1" || strings.EqualFold(env, "true")
	}
	return c.Request.TLS != nil
}

func signJWT(secret []byte, userID string, username any, role any, jti string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"role":     role,
		"jti":      jti,
		"iat":      time.Now().UTC().Unix(),
		"exp":      exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}
