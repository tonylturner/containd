// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// sensitiveWriteLimiter rate-limits sensitive write operations (password changes,
// user CRUD, factory reset, config imports) per client IP.
var sensitiveWriteLimiter = ratelimit.NewAttemptLimiter(1*time.Minute, 30, 1*time.Minute)

const (
	defaultJSONBodyLimit      int64 = 8 << 20  // 8 MiB
	defaultMultipartBodyLimit int64 = 80 << 20 // 80 MiB
)

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

func limitRequestBody(maxJSONBytes, maxMultipartBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request == nil || c.Request.Body == nil {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		limit := maxJSONBytes
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(c.GetHeader("Content-Type"), ";")[0]))
		if strings.HasPrefix(contentType, "multipart/form-data") {
			limit = maxMultipartBytes
		}
		if limit <= 0 {
			c.Next()
			return
		}
		if c.Request.ContentLength > limit {
			apiError(c, http.StatusRequestEntityTooLarge, "request body too large")
			c.Abort()
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func enforceSameOriginOnCookieAuth(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		if normalized, ok := normalizeOrigin(origin); ok {
			allowed[normalized] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		if c.Request == nil || isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		authz := strings.TrimSpace(c.GetHeader("Authorization"))
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			c.Next()
			return
		}
		if _, err := c.Cookie("containd_token"); err != nil {
			c.Next()
			return
		}
		if fetchSite := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site"))); fetchSite != "" {
			switch fetchSite {
			case "same-origin", "same-site", "none":
			case "cross-site":
				apiError(c, http.StatusForbidden, "cross-site request denied")
				c.Abort()
				return
			}
		}
		origin, ok := requestOrigin(c.Request)
		if !ok {
			c.Next()
			return
		}
		if _, ok := allowed[origin]; ok || sameOrigin(origin, c.Request) {
			c.Next()
			return
		}
		apiError(c, http.StatusForbidden, "cross-site request denied")
		c.Abort()
	}
}

func allowedOriginsFromEnv() []string {
	val := strings.TrimSpace(os.Getenv("CONTAIND_ALLOWED_ORIGINS"))
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if normalized, ok := normalizeOrigin(part); ok {
			out = append(out, normalized)
		}
	}
	return out
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func requestOrigin(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	if normalized, ok := normalizeOrigin(r.Header.Get("Origin")); ok {
		return normalized, true
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return "", false
	}
	u, err := url.Parse(referer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return normalizeOrigin(u.Scheme + "://" + u.Host)
}

func normalizeOrigin(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}

func sameOrigin(origin string, r *http.Request) bool {
	if r == nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	reqScheme := requestScheme(r)
	reqHost := requestHost(r)
	if reqScheme == "" || reqHost == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, reqScheme) && strings.EqualFold(u.Host, reqHost)
}

func requestScheme(r *http.Request) string {
	if r == nil {
		return ""
	}
	if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
		return strings.ToLower(proto)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); host != "" {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.TrimSpace(r.Host))
}
