package httpapi

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

type role string

const (
	roleAdmin   role = "admin"
	roleAuditor role = "auditor"
)

const ctxRoleKey = "role"

// authMiddleware enforces bearer-token auth unless lab mode is enabled.
// Tokens are provided via environment:
// - CONTAIND_LAB_MODE=1 disables auth checks.
// - CONTAIND_ADMIN_TOKEN required for full access.
// - CONTAIND_AUDITOR_TOKEN optional read-only access.
func authMiddleware() gin.HandlerFunc {
	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	adminToken := strings.TrimSpace(os.Getenv("CONTAIND_ADMIN_TOKEN"))
	auditorToken := strings.TrimSpace(os.Getenv("CONTAIND_AUDITOR_TOKEN"))
	return func(c *gin.Context) {
		if lab {
			c.Set(ctxRoleKey, string(roleAdmin))
			c.Next()
			return
		}
		if adminToken == "" && auditorToken == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "auth not configured; set CONTAIND_ADMIN_TOKEN or enable CONTAIND_LAB_MODE=1",
			})
			return
		}
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		tok := strings.TrimSpace(h[len("bearer "):])
		switch {
		case adminToken != "" && tok == adminToken:
			c.Set(ctxRoleKey, string(roleAdmin))
			c.Next()
		case auditorToken != "" && tok == auditorToken:
			c.Set(ctxRoleKey, string(roleAuditor))
			c.Next()
		default:
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		}
	}
}

func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		v, _ := c.Get(ctxRoleKey)
		if v != string(roleAdmin) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			return
		}
		c.Next()
	}
}

