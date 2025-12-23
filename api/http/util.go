package httpapi

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/containd/containd/pkg/cp/config"
)

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func httpError(c *gin.Context, err error) {
	if errors.Is(err, config.ErrNotFound) {
		c.JSON(404, gin.H{"error": "config not found"})
		return
	}
	c.JSON(500, gin.H{"error": err.Error()})
}
