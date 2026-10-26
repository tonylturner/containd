// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

type iec104DiagnosticsClient interface {
	IEC104Diagnostics(context.Context) (engine.IEC104Pressure, error)
}

func iec104DiagnosticsHandler(client any) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, ok := client.(iec104DiagnosticsClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine IEC104 diagnostics unavailable")
			return
		}
		out, err := cl.IEC104Diagnostics(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine IEC104 diagnostics unavailable")
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
