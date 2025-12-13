package httpapi

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/containd/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
	idleTTL = 5 * time.Minute
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
	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	adminToken := strings.TrimSpace(os.Getenv("CONTAIND_ADMIN_TOKEN"))
	auditorToken := strings.TrimSpace(os.Getenv("CONTAIND_AUDITOR_TOKEN"))
	secret := jwtSecret()
	return func(c *gin.Context) {
		if lab {
			// In lab mode we still require a token to keep login/logout semantics,
			// but we do not validate signatures or sessions.
			if bearerOrCookie(c) == "" {
				abortJSON(c, http.StatusUnauthorized, "login required")
				return
			}
			c.Set(ctxRoleKey, string(roleAdmin))
			if userStore != nil {
				if u, err := userStore.GetByUsername(c.Request.Context(), "containd"); err == nil {
					c.Set(ctxUserKey, u.ID)
					c.Set(ctxSessionKey, "lab")
				}
			}
			c.Next()
			return
		}

		// Legacy token mode if users store or secret is not configured.
		if userStore == nil || len(secret) == 0 {
			if adminToken == "" && auditorToken == "" {
				abortJSON(c, http.StatusServiceUnavailable, "auth not configured; set CONTAIND_JWT_SECRET or legacy CONTAIND_ADMIN_TOKEN")
				return
			}
			h := c.GetHeader("Authorization")
			if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
				abortJSON(c, http.StatusUnauthorized, "missing bearer token")
				return
			}
			tok := strings.TrimSpace(h[len("bearer "):])
			switch {
			case adminToken != "" && tok == adminToken:
				c.Set(ctxRoleKey, string(roleAdmin))
				c.Next()
			case auditorToken != "" && tok == auditorToken:
				c.Set(ctxRoleKey, string(roleView))
				c.Next()
			default:
				abortJSON(c, http.StatusUnauthorized, "invalid token")
			}
			return
		}

		raw := bearerOrCookie(c)
		if raw == "" {
			abortJSON(c, http.StatusUnauthorized, "missing token")
			return
		}

		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		})
		if err != nil || !parsed.Valid {
			abortJSON(c, http.StatusUnauthorized, "invalid token")
			return
		}

		jti, _ := claims["jti"].(string)
		sub, _ := claims["sub"].(string)
		if jti == "" || sub == "" {
			abortJSON(c, http.StatusUnauthorized, "invalid token claims")
			return
		}

		sess, err := userStore.GetSession(c.Request.Context(), jti)
		if err != nil {
			// Distinguish not-found (expired/revoked) from backend errors (e.g. SQLITE_BUSY),
			// otherwise the UI will treat transient storage failures as "session expired".
			if errors.Is(err, users.ErrNotFound) {
				abortJSON(c, http.StatusUnauthorized, "session revoked")
			} else {
				abortJSON(c, http.StatusServiceUnavailable, "auth backend unavailable")
			}
			return
		}
		if sess.Revoked {
			abortJSON(c, http.StatusUnauthorized, "session revoked")
			return
		}
		if time.Now().UTC().After(sess.ExpiresAt) {
			_ = userStore.RevokeSession(c.Request.Context(), jti)
			abortJSON(c, http.StatusUnauthorized, "session expired")
			return
		}

		// Sliding expiration with max cap.
		updated, err := userStore.TouchSession(c.Request.Context(), jti, idleTTL, maxTTL)
		if err == nil {
			// If expiration moved, issue fresh JWT.
			if expFloat, ok := claims["exp"].(float64); ok {
				tokenExp := time.Unix(int64(expFloat), 0).UTC()
				if updated.ExpiresAt.Sub(tokenExp) > 10*time.Second || tokenExp.Sub(updated.ExpiresAt) > 10*time.Second {
					// Re-hydrate identity from DB so role changes take effect immediately.
					u, err := userStore.GetByID(c.Request.Context(), sub)
					if err == nil && u != nil {
						newTok, _ := signJWT(secret, u.ID, u.Username, u.Role, jti, updated.ExpiresAt)
						if newTok != "" {
							c.Header("X-Auth-Token", newTok)
							setAuthCookie(c, newTok, updated.ExpiresAt)
						}
					}
				}
			}
			sess = updated
		}

		// Role/username are sourced from DB (not the token claims) to prevent stale role elevation.
		u, err := userStore.GetByID(c.Request.Context(), sub)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				abortJSON(c, http.StatusUnauthorized, "user not found")
			} else {
				abortJSON(c, http.StatusServiceUnavailable, "auth backend unavailable")
			}
			return
		}
		if u == nil {
			abortJSON(c, http.StatusUnauthorized, "user not found")
			return
		}
		if sess.UserID != "" && sess.UserID != u.ID {
			abortJSON(c, http.StatusUnauthorized, "session mismatch")
			return
		}
		r := u.Role
		if r == "" {
			r = string(roleView)
		}
		c.Set(ctxRoleKey, r)
		c.Set(ctxUserKey, u.ID)
		c.Set(ctxSessionKey, jti)
		// Populate audit actor hooks.
		c.Set("actor", u.Username)
		c.Next()
	}
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
	c.SetSameSite(http.SameSiteLaxMode)
	// Default is non-Secure so local HTTPS with self-signed certs works reliably in browsers.
	// Production deployments should set CONTAIND_COOKIE_SECURE=1 (or terminate TLS in front).
	secure := strings.TrimSpace(os.Getenv("CONTAIND_COOKIE_SECURE")) == "1" ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("CONTAIND_COOKIE_SECURE")), "true")
	c.SetCookie("containd_token", token, maxAge, "/", "", secure, true)
}

func clearAuthCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	secure := strings.TrimSpace(os.Getenv("CONTAIND_COOKIE_SECURE")) == "1" ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("CONTAIND_COOKIE_SECURE")), "true")
	c.SetCookie("containd_token", "", -1, "/", "", secure, true)
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
