// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type factoryResetRequest struct {
	Confirm string `json:"confirm"`
}

// FactoryResetSessions terminates management transports after a successful reset.
// sessionID identifies the initiating API session, if it belongs to a transport.
type FactoryResetSessions func(ctx context.Context, sessionID string)

func factoryResetHandler(cfgStore config.Store, userStore users.Store, engine EngineClient, services ServicesApplier, revoke ...FactoryResetSessions) gin.HandlerFunc {
	lab := labmode.Enabled()
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
		revision, err := cs.ApplyReset(ctx, expectedConfigRevision(c), def, func(ctx context.Context, previous, next *config.Config) error {
			w, err := applyConfigSnapshot(ctx, cfgStore, engine, services, previous, next)
			if attempt == 0 {
				warnings = w
			}
			attempt++
			return err
		})
		if revisionMismatchResponse(c, err) {
			return
		}
		recoveryWarnings := reenterRecoveryLocked(ctx, cfgStore, engine, err)
		if err != nil {
			setWarningHeader(c, recoveryWarnings)
			factoryResetApplyError(c, err)
			return
		}
		configRevisionResponse(c, revision)
		// Dynamic blocks and connection revocations are runtime state the
		// applied defaults do not replace. A failed clear leaves them in
		// force, so it is reported as incomplete convergence.
		if err := engine.ClearBlocks(ctx); err != nil {
			warnings = append(warnings, fmt.Sprintf("dynamic blocks: %v", err))
		}
		// Wiping sessions revokes session-backed tokens outside lab mode. Lab
		// authentication deliberately does not consult session records. No user
		// state changes until the configuration has been successfully applied.
		if err := us.ResetToDefaultAdmin(ctx); err != nil {
			internalError(c, err)
			return
		}

		// Wipe audit log (after the reset) and then write a completion record.
		if storeVal, ok := c.Get("auditStore"); ok && storeVal != nil {
			if a, ok := storeVal.(audit.Store); ok && a != nil {
				wiper, ok := a.(interface {
					WipeAll(context.Context) error
				})
				if !ok {
					warnings = append(warnings, "audit reset: store does not support wiping")
				} else if err := wiper.WipeAll(ctx); err != nil {
					warnings = append(warnings, fmt.Sprintf("audit reset: %v", err))
				}
			}
		}
		if len(warnings) == 0 {
			auditLog(c, audit.Record{Action: "system.factory_reset.completed", Target: "all", Result: "success"})
		} else {
			auditLog(c, audit.Record{Action: "system.factory_reset.applied", Target: "all", Result: "warning", Detail: strings.Join(warnings, "; ")})
		}
		setWarningHeader(c, warnings)

		// Clear cookies on the response so browser sessions immediately drop auth.
		clearAuthCookie(c)

		for _, closeSessions := range revoke {
			if closeSessions != nil {
				sessionID := c.GetString(ctxSessionKey)
				// Lab authentication does not identify the JWT session, even
				// with a secret. Preserve the initiating SSH transport by ID.
				if lab || len(jwtSecret()) == 0 {
					sessionID = c.GetHeader("X-Containd-SSH-Connection")
				}
				closeSessions(ctx, sessionID)
			}
		}
		message := "Factory reset completed. Log in with the default credentials."
		if len(warnings) > 0 {
			message = "Factory reset applied with warnings; runtime convergence is incomplete. " + strings.Join(warnings, "; ") + ". Log in with the default credentials."
		}
		if lab {
			message += " Lab web/API tokens remain valid; factory reset does not revoke them."
		}
		c.JSON(http.StatusOK, gin.H{
			"status":    "reset",
			"loggedOut": true,
			"message":   message,
			"warnings":  append([]string{}, warnings...),
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
