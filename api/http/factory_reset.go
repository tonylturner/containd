package httpapi

import (
	"net/http"
	"strings"

	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
)

type factoryResetRequest struct {
	Confirm string `json:"confirm"`
}

func factoryResetHandler(cfgStore config.Store, userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req factoryResetRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		if strings.TrimSpace(req.Confirm) != "NUCLEAR" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "confirmation required", "detail": "type NUCLEAR to confirm"})
			return
		}

		ctx := c.Request.Context()

		// Log intent before wiping anything (best-effort). Note: the audit DB itself is wiped
		// during this operation, so only the final "completed" record is guaranteed to remain.
		auditLog(c, audit.Record{Action: "system.factory_reset.requested", Target: "all", Result: "requested"})

		// Wipe users and sessions, then re-seed default admin.
		if userStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "users store unavailable"})
			return
		}

		// Revoke the current session so clients are forced to re-authenticate immediately,
		// even if they keep sending a cached token/cookie.
		if sid := strings.TrimSpace(c.GetString(ctxSessionKey)); sid != "" {
			_ = userStore.RevokeSession(ctx, sid)
		}

		us, ok := userStore.(*users.SQLiteStore)
		if !ok {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "factory reset not supported for this users store"})
			return
		}
		if err := us.WipeAll(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := userStore.EnsureDefaultAdmin(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Wipe config store and re-seed defaults.
		if cfgStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config store unavailable"})
			return
		}
		cs, ok := cfgStore.(*config.SQLiteStore)
		if !ok {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "factory reset not supported for this config store"})
			return
		}
		if err := cs.WipeAll(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		def := config.DefaultConfig()
		def.System.Hostname = "containd"
		def.System.Mgmt.ListenAddr = ":8080"
		def.System.Mgmt.HTTPListenAddr = ":8080"
		def.System.Mgmt.HTTPSListenAddr = ":8443"
		t := true
		def.System.Mgmt.EnableHTTP = &t
		def.System.Mgmt.EnableHTTPS = &t
		def.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
		def.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
		def.System.SSH.ListenAddr = ":2222"
		def.System.SSH.AuthorizedKeysDir = "/data/ssh/authorized_keys.d"
		if err := cfgStore.Save(ctx, def); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Wipe audit log (after the reset) and then write a completion record.
		if storeVal, ok := c.Get("auditStore"); ok && storeVal != nil {
			if a, ok := storeVal.(audit.Store); ok && a != nil {
				if sqlite, ok := a.(*audit.SQLiteStore); ok {
					_ = sqlite.WipeAll(ctx)
				}
			}
		}
		auditLog(c, audit.Record{Action: "system.factory_reset.completed", Target: "all", Result: "success"})

		// Clear cookies on the response so browser sessions immediately drop auth.
		clearAuthCookie(c)

		c.JSON(http.StatusOK, gin.H{
			"status":    "reset",
			"loggedOut": true,
			"login": gin.H{
				"username": "containd",
				"password": "containd",
			},
			"message": "Factory reset completed; you have been logged out.",
			"nextSteps": []string{
				"Log in with containd/containd",
				"Change the default password immediately",
				"Enroll an SSH key and disable SSH password auth",
			},
		})
	}
}
