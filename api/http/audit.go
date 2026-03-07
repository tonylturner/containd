// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
)

// auditHandlers registers audit listing endpoint.
func auditHandlers(r *gin.RouterGroup, store audit.Store) {
	r.GET("/audit", func(c *gin.Context) {
		limit := 100
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 1000 {
				limit = v
			}
		}
		offset := 0
		if q := c.Query("offset"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v >= 0 {
				offset = v
			}
		}
		records, err := store.List(c.Request.Context(), limit, offset)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, records)
	})
}
