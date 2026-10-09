// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// IEC104HealthClient reads the engine's IEC104 enforcement health.
type IEC104HealthClient interface {
	IEC104Enforcement(ctx context.Context) (dpengine.IEC104Enforcement, error)
}

// engineHealthTimeout keeps liveness fast when the engine is slow.
const engineHealthTimeout = time.Second

// engineUnreachable is reported when the engine cannot be asked: health
// never invents a healthy engine (contracts K6).
var engineUnreachable = dpengine.IEC104Enforcement{Active: false, Healthy: false, Reason: "engine unreachable"}

// healthHandler is unauthenticated liveness. It is always 200; the
// iec104Enforcement object carries the engine's enforcement health.
func healthHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		iec := engineUnreachable
		if hc, ok := engine.(IEC104HealthClient); ok && hc != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
			if st, err := hc.IEC104Enforcement(ctx); err == nil {
				iec = st
			}
			cancel()
		}
		c.JSON(http.StatusOK, gin.H{
			"status":            "ok",
			"component":         "mgmt",
			"build":             config.BuildVersion,
			"time":              time.Now().UTC().Format(time.RFC3339Nano),
			"iec104Enforcement": iec,
		})
	}
}
