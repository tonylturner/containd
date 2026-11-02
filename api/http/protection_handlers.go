// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/audit"
)

func getProtectionHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		coordinator, ok := requestCoordinator(c)
		if !ok {
			return
		}
		view, err := authenticatedProtection(c.Request.Context(), coordinator, engine)
		if err != nil {
			c.JSON(http.StatusBadGateway, view)
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func retryProtectionHandler(_ EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			BootID          protection.BootID   `json:"bootId"`
			ApplyID         protection.ApplyID  `json:"applyId"`
			DesiredRevision protection.Revision `json:"desiredRevision"`
		}
		decoder := json.NewDecoder(io.LimitReader(c.Request.Body, 4096))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&req)
		target := protection.Metadata{BootID: req.BootID, ApplyID: req.ApplyID, RunningRevision: req.DesiredRevision, Mode: protection.ModeNormal}
		if err != nil || decoder.Decode(new(any)) != io.EOF || !target.Valid() {
			apiError(c, http.StatusBadRequest, "valid bootId, applyId and desiredRevision are required")
			return
		}
		result := "failed"
		defer func() {
			auditLog(c, audit.Record{Action: "dataplane.protection.retry", Target: string(req.ApplyID), Result: result})
		}()
		coordinator, ok := requestCoordinator(c)
		if !ok {
			return
		}
		if err := coordinator.Retry(target); err != nil {
			if errors.Is(err, convergence.ErrSuperseded) || errors.Is(err, convergence.ErrUncertain) {
				c.JSON(http.StatusConflict, gin.H{"error": "protection observation was superseded or is uncertain", "code": "protection_superseded"})
				return
			}
			apiError(c, http.StatusBadGateway, "protection retry unavailable")
			return
		}
		result = "success"
		c.JSON(http.StatusAccepted, gin.H{"status": "retrying", "applyId": req.ApplyID, "desiredRevision": req.DesiredRevision})
	}
}
