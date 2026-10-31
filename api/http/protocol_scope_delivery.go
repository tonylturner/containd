// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/scopeaudit"
)

// Deliver only after persistence has completed, outside any store lock. Failed
// delivery remains in the transactional outbox for the next request or boot.
func deliverScopeMigrations(store config.Store, log audit.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 10*time.Second)
		defer cancel()
		if _, err := scopeaudit.Publish(ctx, store, log); err != nil && !audit.IsObservedFailure(err) {
			slog.Error("deliver industrial scope migration audit failed; outbox retained for retry")
		}
	}
}
