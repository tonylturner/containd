// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
)

type ProtectionRetryClient interface {
	RetryProtection(context.Context, string, string) error
}

func getProtectionHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusServiceUnavailable, "engine unavailable")
			return
		}
		hc, ok := engine.(RuntimeHealthClient)
		if !ok {
			apiError(c, http.StatusBadGateway, "engine protection status unavailable: health unsupported")
			return
		}
		health, err := hc.RuntimeHealth(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, "engine protection status unavailable: "+err.Error())
			return
		}
		st := engineclient.NormalizeProtection(health.Protection, "")
		if st.BootID != health.BootID {
			st = engineclient.UnknownProtection("")
		}
		c.JSON(http.StatusOK, st)
	}
}

func retryProtectionHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			BootID  string `json:"bootId"`
			ApplyID string `json:"applyId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.BootID) == "" || strings.TrimSpace(req.ApplyID) == "" || len(req.ApplyID) > 64 {
			apiError(c, http.StatusBadRequest, "bootId and applyId are required (applyId: 1 to 64 bytes)")
			return
		}
		result := "failed"
		defer func() {
			auditLog(c, audit.Record{Action: "dataplane.protection.retry", Target: req.ApplyID, Result: result})
		}()
		if engine == nil {
			apiError(c, http.StatusServiceUnavailable, "engine unavailable")
			return
		}
		rc, ok := engine.(ProtectionRetryClient)
		if !ok {
			apiError(c, http.StatusBadGateway, "engine protection retry unavailable")
			return
		}
		if err := rc.RetryProtection(c.Request.Context(), req.BootID, req.ApplyID); err != nil {
			var conflict *engineclient.ProtectionConflict
			if errors.As(err, &conflict) {
				c.JSON(http.StatusConflict, gin.H{"error": strings.ReplaceAll(conflict.Code, "_", " "), "code": conflict.Code})
				return
			}
			apiError(c, http.StatusBadGateway, "engine protection retry unavailable: "+err.Error())
			return
		}
		result = "success"
		c.JSON(http.StatusAccepted, gin.H{"status": "retrying", "applyId": req.ApplyID})
	}
}
