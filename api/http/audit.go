package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/containd/containd/pkg/cp/audit"
)

// auditHandlers registers audit listing endpoint.
func auditHandlers(r *gin.RouterGroup, store audit.Store) {
	r.GET("/audit", func(c *gin.Context) {
		records, err := store.List(c.Request.Context(), 100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, records)
	})
}
