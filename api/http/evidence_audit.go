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
		if actor := c.GetString(ctxActorKey); actor != "" {
			rec.Actor = actor
		} else {
			rec.Actor = "unknown"
		}
	}
	rec.Source = "api"
	if rec.Result == "" {
		rec.Result = "success"
	}
	audit.Write(c.Request.Context(), store, rec)
}
