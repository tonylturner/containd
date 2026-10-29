// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestIDSExportDownload(t *testing.T) {
	for _, tc := range []struct {
		name, query, count, contentType string
		rules                           []config.IDSRule
		status                          int
	}{
		{"partial", "snort", "1", "text/plain", []config.IDSRule{{ID: "1", Proto: "tcp"}, {ID: "2", Proto: "modbus"}}, 200},
		{"suricata partial", "suricata", "1", "text/plain", []config.IDSRule{{ID: "1", Proto: "tcp"}, {ID: "2", Proto: "cip"}}, 200},
		{"suricata all refused", "suricata", "1", "text/plain", []config.IDSRule{{ID: "2", Proto: "modbus"}}, 200},
		{"default refused", "", "1", "text/plain", []config.IDSRule{{ID: "2", Proto: "iec104"}}, 200},
		{"all refused", "snort", "1", "text/plain", []config.IDSRule{{ID: "2", Proto: "modbus"}}, 200},
		{"empty", "snort", "0", "text/plain", nil, 200},
		{"case", "SNORT", "0", "text/plain", []config.IDSRule{{ID: "1", Proto: "tcp"}}, 200},
		{"default", "", "0", "text/plain", []config.IDSRule{{ID: "1", Proto: "tcp"}}, 200},
		{"sigma", "sigma", "0", "text/yaml", []config.IDSRule{{ID: "1", Title: "Sigma"}}, 200},
		{"yara", "yara", "0", "text/plain", []config.IDSRule{{ID: "1", Title: "YARA"}}, 200},
		{"unsupported", "unknown", "", "", nil, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := stageStore(t)
			if err := store.SaveIDSRules(context.Background(), tc.rules); err != nil {
				t.Fatal(err)
			}
			server := gin.New()
			server.GET("/export", idsExportHandler(store))
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/export?format="+tc.query, nil))
			if rec.Code != tc.status {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			if tc.status != http.StatusOK {
				return
			}
			if rec.Header().Get("X-Containd-IDS-Refused") != tc.count ||
				!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment; filename=") ||
				!strings.HasPrefix(rec.Header().Get("Content-Type"), tc.contentType) {
				t.Fatalf("headers = %v", rec.Header())
			}
			if tc.count == "1" && (!strings.Contains(rec.Body.String(), `# refused: {"rule_id":"2"`) ||
				!strings.Contains(rec.Body.String(), "proto=") || strings.Contains(rec.Body.String(), "alert ip ")) {
				t.Fatalf("missing refusal or widened rule: %s", rec.Body)
			}
			if strings.Contains(tc.name, "partial") && !strings.Contains(rec.Body.String(), "alert tcp ") {
				t.Fatalf("lost accepted rule: %s", rec.Body)
			}
		})
	}
}
