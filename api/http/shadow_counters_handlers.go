// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

type ShadowCountersClient interface {
	ShadowCounters(context.Context) (dpengine.ShadowCounters, error)
}

func shadowCountersHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, ok := engine.(ShadowCountersClient)
		if !ok || client == nil {
			c.JSON(http.StatusOK, dpengine.ShadowCounters{Reason: "engine unavailable"})
			return
		}
		counters, err := client.ShadowCounters(c.Request.Context())
		if err != nil {
			counters = dpengine.ShadowCounters{Reason: err.Error()}
		}
		c.JSON(http.StatusOK, counters)
	}
}
