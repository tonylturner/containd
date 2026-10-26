// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type factoryResetRequest struct {
	Confirm string `json:"confirm"`
}

func factoryResetHandler(cfgStore config.Store, userStore users.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req factoryResetRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		if strings.TrimSpace(req.Confirm) != "NUCLEAR" {
			apiErrorDetail(c, http.StatusBadRequest, "confirmation required", "type NUCLEAR to confirm")
			return
		}

		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		def := ApplianceDefaults(config.ReservationForStore(cfgStore))
		// Validate the exact replacement before revoking sessions or wiping any
		// database. An incompatible factory default is an explicit refusal.
		if err := config.ValidateForStore(cfgStore, def); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Log intent before wiping anything (best-effort). Note: the audit DB itself is wiped
		// during this operation, so only the final "completed" record is guaranteed to remain.
		auditLog(c, audit.Record{Action: "system.factory_reset.requested", Target: "all", Result: "requested"})

		// Check all store capabilities before any destructive mutation.
		if userStore == nil || cfgStore == nil {
			apiError(c, http.StatusServiceUnavailable, "reset stores unavailable")
			return
		}
		us, usersOK := userStore.(*users.SQLiteStore)
		cs, configOK := cfgStore.(*config.SQLiteStore)
		if !usersOK || !configOK {
			apiError(c, http.StatusNotImplemented, "factory reset requires SQLite stores")
			return
		}
		// Preserve the full config state until runtime apply succeeds. In
		// particular, do not stage defaults over the caller's candidate.
		var warnings []string
		attempt := 0
		err := cs.ApplyReset(ctx, def, func(ctx context.Context, previous, next *config.Config) error {
			w, err := applyConfigSnapshot(ctx, cfgStore, engine, services, previous, next)
			if attempt == 0 {
				warnings = w
			}
			attempt++
			return err
		})
		if err != nil {
			factoryResetApplyError(c, err)
			return
		}
		setWarningHeader(c, warnings)

		// Wiping sessions also revokes the current token. No authentication
		// state changes until the configuration has been successfully applied.
		if err := us.ResetToDefaultAdmin(ctx); err != nil {
			internalError(c, err)
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
			"message":   "Factory reset completed. Log in with the default credentials and change the password immediately.",
		})
	}
}

func factoryResetApplyError(c *gin.Context, err error) {
	var failure *config.ApplyError
	if !errors.As(err, &failure) {
		internalError(c, err)
		return
	}
	body := gin.H{
		"error":     "configuration apply failed",
		"detail":    failure.Err.Error(),
		"restored":  failure.RestoreError == nil,
		"reapplied": failure.ReapplyError == nil,
	}
	for key, recoveryErr := range map[string]error{
		"restoreError": failure.RestoreError,
		"reapplyError": failure.ReapplyError,
		"healthError":  failure.HealthError,
	} {
		if recoveryErr != nil {
			body[key] = recoveryErr.Error()
		}
	}
	c.JSON(http.StatusInternalServerError, body)
}
