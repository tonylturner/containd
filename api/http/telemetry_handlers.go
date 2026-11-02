// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
)

// TelemetryStore is supplied by management, never created on a request path.
type TelemetryStore interface {
	Query(context.Context, history.Query, time.Time) (wire.SeriesResponse, error)
}

func telemetrySeriesHandler(store TelemetryStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		q, err := history.ParseQuery(c.Request.URL.Query())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "telemetry store unavailable"})
			return
		}
		response, err := store.Query(c.Request.Context(), q, time.Now())
		if err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, history.ErrOverflow) {
				code = http.StatusInternalServerError
			}
			c.JSON(code, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, response)
	}
}
