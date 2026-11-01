// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
)

func withAuditStore(store audit.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store != nil {
			c.Set("auditStore", store)
			if actor := c.GetHeader("X-User"); actor != "" {
				c.Set("actor", actor)
			}
			if source := c.GetHeader("X-Source"); source != "" {
				c.Set("source", source)
			}
		}
		c.Next()
	}
}

func auditLog(c *gin.Context, rec audit.Record) {
	if c == nil {
		return
	}
	storeVal, ok := c.Get("auditStore")
	if !ok || storeVal == nil {
		return
	}
	store, ok := storeVal.(audit.Store)
	if !ok || store == nil {
		return
	}
	if rec.Actor == "" {
		if actor := c.GetString("actor"); actor != "" {
			rec.Actor = actor
		} else if actor := c.GetHeader("X-User"); actor != "" {
			rec.Actor = actor
		} else {
			rec.Actor = "unknown"
		}
	}
	if rec.Source == "" {
		if src := c.GetString("source"); src != "" {
			rec.Source = src
		} else if src := c.GetHeader("X-Source"); src != "" {
			rec.Source = src
		} else {
			rec.Source = "api"
		}
	}
	if rec.Result == "" {
		rec.Result = "success"
	}
	audit.Write(c.Request.Context(), store, rec)
}
