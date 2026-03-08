// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string     `json:"token"`
	ExpiresAt string     `json:"expiresAt"`
	User      users.User `json:"user"`
}

var loginLimiter = ratelimit.NewAttemptLimiter(1*time.Minute, 10, 2*time.Minute)

func loginHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil || len(jwtSecret()) == 0 {
			apiError(c, http.StatusServiceUnavailable, "JWT auth not configured")
			return
		}
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			apiError(c, http.StatusBadRequest, "username and password required")
			return
		}

		ip := c.ClientIP()
		key := ip + "|" + strings.ToLower(req.Username)
		if ok, retry := loginLimiter.Allow(key); !ok {
			c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())))
			apiError(c, http.StatusTooManyRequests, "too many login attempts; retry later")
			return
		}

		u, err := userStore.GetByUsername(c.Request.Context(), req.Username)
		if err != nil {
			loginLimiter.Fail(key)
			apiError(c, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
			loginLimiter.Fail(key)
			apiError(c, http.StatusUnauthorized, "invalid credentials")
			return
		}
		loginLimiter.Success(key)
		sess, err := userStore.CreateSession(c.Request.Context(), u.ID, idleTTL, maxTTL)
		if err != nil {
			internalError(c, err)
			return
		}
		secret := jwtSecret()
		token, err := signJWT(secret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to sign token")
			return
		}
		setAuthCookie(c, token, sess.ExpiresAt)
		c.JSON(http.StatusOK, loginResponse{
			Token:     token,
			ExpiresAt: sess.ExpiresAt.Format(time.RFC3339Nano),
			User:      u.User,
		})
	}
}

func logoutHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			clearAuthCookie(c)
			c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
			return
		}

		// Try to revoke the session if we can extract a jti from the token,
		// but always clear cookies even if parsing fails.
		raw := bearerOrCookie(c)
		if raw != "" && len(jwtSecret()) > 0 {
			claims := jwt.MapClaims{}
			parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return jwtSecret(), nil
			}, jwt.WithoutClaimsValidation())
			if err == nil && parsed != nil && parsed.Valid {
				if jti, _ := claims["jti"].(string); jti != "" {
					_ = userStore.RevokeSession(c.Request.Context(), jti)
				}
			}
		}

		// Best-effort: if auth middleware already set the session, revoke it too.
		if sid, ok := c.Get(ctxSessionKey); ok {
			if s, ok := sid.(string); ok && s != "" {
				_ = userStore.RevokeSession(c.Request.Context(), s)
			}
		}

		clearAuthCookie(c)
		c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
	}
}

func meHandler(userStore users.Store) gin.HandlerFunc {
	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	return func(c *gin.Context) {
		if userStore == nil {
			c.JSON(http.StatusOK, gin.H{"role": c.GetString(ctxRoleKey), "labMode": lab})
			return
		}
		uid := c.GetString(ctxUserKey)
		u, err := userStore.GetByID(c.Request.Context(), uid)
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		resp := gin.H{
			"id":       u.ID,
			"username": u.Username,
			"role":     u.Role,
			"labMode":  lab,
		}
		if u.FirstName != "" {
			resp["firstName"] = u.FirstName
		}
		if u.LastName != "" {
			resp["lastName"] = u.LastName
		}
		if u.Email != "" {
			resp["email"] = u.Email
		}
		if u.MustChangePassword {
			resp["mustChangePassword"] = true
		}
		c.JSON(http.StatusOK, resp)
	}
}

func authSessionHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := gin.H{
			"role":            c.GetString(ctxRoleKey),
			"sessionId":       c.GetString(ctxSessionKey),
			"idleTTLSeconds":  int(idleTTL.Seconds()),
			"maxTTLSeconds":   int(maxTTL.Seconds()),
			"clientIP":        c.ClientIP(),
			"authenticatedAs": c.GetString("actor"),
		}

		if userStore != nil {
			if uid := c.GetString(ctxUserKey); uid != "" {
				if u, err := userStore.GetByID(c.Request.Context(), uid); err == nil && u != nil {
					resp["user"] = u.User
				}
			}
			if sid := c.GetString(ctxSessionKey); sid != "" && sid != "lab" {
				if s, err := userStore.GetSession(c.Request.Context(), sid); err == nil && s != nil {
					resp["expiresAt"] = s.ExpiresAt.Format(time.RFC3339Nano)
					resp["issuedAt"] = s.IssuedAt.Format(time.RFC3339Nano)
					resp["lastSeen"] = s.LastSeen.Format(time.RFC3339Nano)
				}
			}
		}
		c.JSON(http.StatusOK, resp)
	}
}

type updateMeRequest struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Email     string `json:"email,omitempty"`
}

func updateMeHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		uid := c.GetString(ctxUserKey)
		var req updateMeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		patch := users.User{FirstName: req.FirstName, LastName: req.LastName, Email: req.Email}
		u, err := userStore.Update(c.Request.Context(), uid, patch)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, u)
	}
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func changeMyPasswordHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		uid := c.GetString(ctxUserKey)
		var req changePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.NewPassword == "" {
			apiError(c, http.StatusBadRequest, "newPassword required")
			return
		}
		if req.CurrentPassword == "" {
			apiError(c, http.StatusBadRequest, "currentPassword required")
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), uid)
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.CurrentPassword)) != nil {
			apiError(c, http.StatusUnauthorized, "current password invalid")
			return
		}
		if err := userStore.SetPassword(c.Request.Context(), uid, req.NewPassword); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "password_set"})
	}
}
