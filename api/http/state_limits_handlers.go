// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

type stateLimitsClient interface {
	StateLimits(context.Context) (limits.Snapshot, error)
}

func stateLimitsHandler(client any) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, ok := client.(stateLimitsClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine state limits diagnostics unavailable")
			return
		}
		out, err := cl.StateLimits(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine state limits diagnostics unavailable")
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
