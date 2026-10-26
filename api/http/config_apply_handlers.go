// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func commitConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return runningChangeHandler(store, engine, services, config.ChangeCommit)
}
func commitConfirmedHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return runningChangeHandler(store, engine, services, config.ChangeCommitConfirmed)
}
func rollbackConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return runningChangeHandler(store, engine, services, config.ChangeRollback)
}

func runningChangeHandler(store config.Store, engine EngineClient, services ServicesApplier, change config.RunningChange) gin.HandlerFunc {
	return func(c *gin.Context) {
		ttl := 60 * time.Second
		if change == config.ChangeCommitConfirmed {
			body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
			if err != nil {
				apiErrorDetail(c, http.StatusBadRequest, "cannot read commit request", err.Error())
				return
			}
			if len(body) > 0 {
				var req struct {
					TTLSeconds int64 `json:"ttl_seconds"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
					return
				}
				if req.TTLSeconds > 0 {
					// A duration overflow must not accidentally turn a confirmed commit
					// into an unconfirmed promotion.
					if req.TTLSeconds > int64((1<<63-1)/time.Second) {
						apiError(c, http.StatusBadRequest, "ttl_seconds is too large")
						return
					}
					ttl = time.Duration(req.TTLSeconds) * time.Second
				}
			}
		}
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		runtimeStore, ok := store.(config.RuntimeStore)
		if !ok {
			internalError(c, errors.New("store does not support runtime transactions"))
			return
		}
		var warnings []string
		attempt := 0
		err := runtimeStore.ApplyChange(c.Request.Context(), change, ttl, func(ctx context.Context, previous, next *config.Config) error {
			w, err := applyConfigSnapshot(ctx, store, engine, services, previous, next)
			if attempt == 0 {
				warnings = w
			}
			attempt++
			return err
		})
		recoveryWarnings := reenterRecoveryLocked(c.Request.Context(), store, engine, err)
		if err != nil {
			setWarningHeader(c, recoveryWarnings)
			var failure *config.ApplyError
			if errors.As(err, &failure) {
				body := gin.H{"error": "configuration apply failed", "detail": failure.Err.Error(), "restored": failure.RestoreError == nil, "reapplied": failure.ReapplyError == nil}
				if failure.RestoreError != nil {
					body["restoreError"] = failure.RestoreError.Error()
				}
				if failure.ReapplyError != nil {
					body["reapplyError"] = failure.ReapplyError.Error()
				}
				if failure.HealthError != nil {
					body["healthError"] = failure.HealthError.Error()
				}
				c.JSON(http.StatusInternalServerError, body)
			} else {
				apiError(c, http.StatusBadRequest, err.Error())
			}
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "config." + string(change), Target: "running"})
		status := "committed"
		if change == config.ChangeRollback {
			status = "rolled back"
		}
		committedConfigResponse(c, status)
	}
}

func confirmCommitHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		if err := store.ConfirmCommit(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "config.confirm_commit", Target: "running"})
		committedConfigResponse(c, "confirmed")
	}
}
