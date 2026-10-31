// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func listSignaturesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		sigs, err := sc.ListSignatures(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		if sigs == nil {
			sigs = []signatures.Signature{}
		}
		c.JSON(http.StatusOK, sigs)
	}
}

func addSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		var sig signatures.Signature
		if err := c.ShouldBindJSON(&sig); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := sig.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := sc.AddSignature(c.Request.Context(), sig); err != nil {
			if errors.Is(err, engineclient.ErrSignatureExists) {
				apiError(c, http.StatusConflict, "signature already exists")
				return
			}
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		auditLog(c, audit.Record{Action: "signatures.add", Target: sig.ID})
		c.JSON(http.StatusOK, sig)
	}
}

func deleteSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		id := c.Param("id")
		removed, err := sc.RemoveSignature(c.Request.Context(), id)
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine signatures unavailable")
			return
		}
		if !removed {
			apiError(c, http.StatusNotFound, "signature not found")
			return
		}
		auditLog(c, audit.Record{Action: "signatures.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listSignatureMatchesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine signature matches unavailable")
			return
		}
		limit := 100
		if v := c.Query("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		matches, err := sc.ListSignatureMatches(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine signature matches unavailable")
			return
		}
		if matches == nil {
			matches = []signatures.Match{}
		}
		c.JSON(http.StatusOK, matches)
	}
}
