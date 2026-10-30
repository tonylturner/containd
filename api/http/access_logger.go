// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Preserve non-secret query bytes, including their ordering and escaping.
// Decode keys individually so malformed values cannot defeat redaction.
func redactAccessPath(path string) string {
	base, query, ok := strings.Cut(path, "?")
	if !ok {
		return path
	}
	parts := strings.Split(query, "&")
	for i, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			continue
		}
		switch strings.ToLower(decoded) {
		case "token", "ticket", "access_token", "refresh_token", "id_token",
			"password", "secret", "api_key", "apikey", "authorization":
			parts[i] = key + "=<redacted>"
		}
	}
	return base + "?" + strings.Join(parts, "&")
}

func accessLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		// Match Gin's default formatter, changing only secret query values.
		var statusColor, methodColor, resetColor string
		if p.IsOutputColor() {
			statusColor = p.StatusCodeColor()
			methodColor = p.MethodColor()
			resetColor = p.ResetColor()
		}
		if p.Latency > time.Minute {
			p.Latency = p.Latency.Truncate(time.Second)
		}
		return fmt.Sprintf("[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %#v\n%s",
			p.TimeStamp.Format("2006/01/02 - 15:04:05"),
			statusColor, p.StatusCode, resetColor, p.Latency, p.ClientIP,
			methodColor, p.Method, resetColor, redactAccessPath(p.Path), p.ErrorMessage)
	})
}
