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
	cpids "github.com/tonylturner/containd/pkg/cp/ids"
)

func TestIDSExportDownload(t *testing.T) {
	sigmaRules, err := cpids.ConvertSigmaFile([]byte("title: Sigma\nid: sigma-1\nlevel: high\ntags: [containd.proto.modbus, containd.kind.request]\ndetection: {selection: {function_code: 5}, condition: selection}\n"))
	if err != nil {
		t.Fatal(err)
	}
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
		{"sigma", "sigma", "0", "text/yaml", sigmaRules, 200},
		{"yara", "yara", "0", "text/plain", []config.IDSRule{{ID: "1", Title: "YARA", YARAStrings: []config.YARAString{{Name: "$a", Pattern: "test"}}}}, 200},
		{"sigma refused", "sigma", "1", "text/yaml", []config.IDSRule{{ID: "2", SrcAddr: "10.0.0.0/8"}}, 200},
		{"yara refused", "yara", "1", "text/plain", []config.IDSRule{{ID: "2", Proto: "modbus"}}, 200},
		{"sigma partial", "sigma", "1", "text/yaml", append([]config.IDSRule{{ID: "2", SrcAddr: "10.0.0.0/8"}}, sigmaRules...), 200},
		{"yara partial", "yara", "1", "text/plain", []config.IDSRule{
			{ID: "2", Proto: "modbus"},
			{ID: "1", Title: "YARA", YARAStrings: []config.YARAString{{Name: "$a", Pattern: "test"}}},
		}, 200},
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
			prefix := "#"
			if tc.query == "yara" {
				prefix = "//"
			}
			predicate := "proto="
			if tc.query == "sigma" {
				predicate = "srcAddr="
			}
			if tc.count == "1" && (!strings.Contains(rec.Body.String(), prefix+` refused: {"rule_id":"2"`) ||
				!strings.Contains(rec.Body.String(), predicate) || strings.Contains(rec.Body.String(), "alert ip ")) {
				t.Fatalf("missing refusal or widened rule: %s", rec.Body)
			}
			if tc.name == "sigma" && rec.Body.String() != sigmaRules[0].RawSource {
				t.Fatalf("Sigma source changed: %s", rec.Body)
			}
			if strings.Contains(tc.name, "partial") {
				acceptedText := "alert tcp "
				switch tc.query {
				case "sigma":
					acceptedText = "title: Sigma"
				case "yara":
					acceptedText = "rule YARA"
				}
				if !strings.Contains(rec.Body.String(), acceptedText) {
					t.Fatalf("lost accepted rule: %s", rec.Body)
				}
			}
		})
	}
}

func TestIDSExportEditedImportedSnort(t *testing.T) {
	source := `alert tcp any any -> any any (msg:"Cache"; sid:77; rev:9;)`
	rule, err := cpids.ParseSnortLine(source)
	if err != nil {
		t.Fatal(err)
	}
	// The edit narrows the destination port, but leaves the old source attached,
	// just as editing an imported rule through the management UI does.
	rule.DstPort = "10001"
	store := stageStore(t)
	if err := store.SaveIDSRules(context.Background(), []config.IDSRule{rule}); err != nil {
		t.Fatal(err)
	}
	server := gin.New()
	server.GET("/export", idsExportHandler(store))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/export?format=snort", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("X-Containd-IDS-Refused") != "0" {
		t.Fatalf("response=%d,%v,%s", rec.Code, rec.Header(), rec.Body)
	}
	text := strings.TrimSpace(rec.Body.String())
	if text == source || !strings.HasPrefix(text, "alert tcp any any -> any 10001 (") {
		t.Fatalf("export widened the edited port: %s", text)
	}
	exported, err := cpids.ParseSnortLine(text)
	if err != nil || exported.DstPort != rule.DstPort {
		t.Fatalf("edited import=%+v,%v", exported, err)
	}
	if rule.RawSource != source {
		t.Fatal("export changed the stored source cache")
	}
}
