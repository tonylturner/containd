// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// sensitiveWriteLimiter rate-limits sensitive write operations (password changes,
// user CRUD, factory reset, config imports) per client IP.
var sensitiveWriteLimiter = ratelimit.NewAttemptLimiter(1*time.Minute, 30, 1*time.Minute)

// rateLimitSensitive is a gin middleware that enforces the sensitiveWriteLimiter.
func rateLimitSensitive() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if ok, retry := sensitiveWriteLimiter.Allow(key); !ok {
			c.Header("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())+1))
			apiError(c, http.StatusTooManyRequests, "rate limit exceeded")
			c.Abort()
			return
		}
		sensitiveWriteLimiter.Fail(key) // count every attempt
		c.Next()
	}
}

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

// apiError sends a standardized JSON error response.
func apiError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// apiErrorDetail sends a standardized JSON error response with detail.
func apiErrorDetail(c *gin.Context, status int, msg string, detail string) {
	c.JSON(status, gin.H{"error": msg, "detail": detail})
}

func setWarningHeader(c *gin.Context, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	trimmed := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		if msg := strings.TrimSpace(warning); msg != "" {
			trimmed = append(trimmed, msg)
		}
	}
	if len(trimmed) == 0 {
		return
	}
	c.Header("X-Containd-Warnings", strings.Join(trimmed, "\n"))
}

func httpError(c *gin.Context, err error) {
	if errors.Is(err, config.ErrNotFound) {
		apiError(c, http.StatusNotFound, "config not found")
		return
	}
	internalError(c, err)
}

// internalError logs the real error and returns a generic message to the client.
// This prevents leaking file paths, stack traces, or other implementation details.
func internalError(c *gin.Context, err error) {
	slog.Error("internal error", "method", c.Request.Method, "path", c.Request.URL.Path, "error", err)
	apiError(c, http.StatusInternalServerError, "internal server error")
}
