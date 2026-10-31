// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAccessLoggerRedactsSecretQueries(t *testing.T) {
	var out bytes.Buffer
	old := gin.DefaultWriter
	gin.DefaultWriter = &out
	defer func() { gin.DefaultWriter = old }()
	r := gin.New()
	r.Use(accessLogger())
	r.GET("/ws", func(c *gin.Context) {
		if c.Query("token") != "jwt-secret" || c.Query("ticket") != "ticket-secret" {
			t.Error("logger modified actual request credentials")
		}
		c.Status(http.StatusUnauthorized)
	})
	path := "/ws?token=jwt-secret&ticket=ticket-secret&%74oken=encoded-secret&ToKeN=duplicate-secret&password=bad%zz&api_key=key-secret&line=show%20version"
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	log := out.String()
	for _, secret := range []string{"jwt-secret", "ticket-secret", "encoded-secret", "duplicate-secret", "bad%zz", "key-secret"} {
		if strings.Contains(log, secret) {
			t.Errorf("secret %q leaked: %s", secret, log)
		}
	}
	if strings.Count(log, "<redacted>") != 6 || !strings.Contains(log, "line=show%20version") ||
		!strings.Contains(log, "[GIN]") || !strings.Contains(log, "401") || !strings.Contains(log, "GET") {
		t.Fatalf("unexpected access log: %s", log)
	}
}
