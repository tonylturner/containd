package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/containd/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string      `json:"token"`
	ExpiresAt string      `json:"expiresAt"`
	User      users.User  `json:"user"`
}

func loginHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil || len(jwtSecret()) == 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "JWT auth not configured"})
			return
		}
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
			return
		}
		u, err := userStore.GetByUsername(c.Request.Context(), req.Username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		sess, err := userStore.CreateSession(c.Request.Context(), u.ID, idleTTL, maxTTL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		secret := jwtSecret()
		token, err := signJWT(secret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign token"})
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
			c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
			return
		}
		sid, _ := c.Get(ctxSessionKey)
		if s, ok := sid.(string); ok && s != "" {
			_ = userStore.RevokeSession(c.Request.Context(), s)
		}
		c.SetCookie("containd_token", "", -1, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
	}
}

func meHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			c.JSON(http.StatusOK, gin.H{"role": c.GetString(ctxRoleKey)})
			return
		}
		uid := c.GetString(ctxUserKey)
		u, err := userStore.GetByID(c.Request.Context(), uid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, u.User)
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
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user store unavailable"})
			return
		}
		uid := c.GetString(ctxUserKey)
		var req updateMeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		patch := users.User{FirstName: req.FirstName, LastName: req.LastName, Email: req.Email}
		u, err := userStore.Update(c.Request.Context(), uid, patch)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, u)
	}
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword,omitempty"`
	NewPassword     string `json:"newPassword"`
}

func changeMyPasswordHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user store unavailable"})
			return
		}
		uid := c.GetString(ctxUserKey)
		var req changePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		if req.NewPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "newPassword required"})
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), uid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		// If current password provided, verify before changing.
		if req.CurrentPassword != "" {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.CurrentPassword)) != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "current password invalid"})
				return
			}
		}
		if err := userStore.SetPassword(c.Request.Context(), uid, req.NewPassword); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "password_set"})
	}
}
