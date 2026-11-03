// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestIDSImportReportsStorageOnlyRules(t *testing.T) {
	server := newTestServerWithEngine(stageStore(t), &mockAuditStore{}, &mockEngine{})
	for _, duplicate := range []bool{false, true} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		file, err := writer.CreateFormFile("file", "stored.yar")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(`rule stored { strings: $a = "test" condition: $a }`)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		req := authedRequest(http.MethodPost, "/api/v1/ids/import", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, server, rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("import: %d %s", rec.Code, rec.Body)
		}
		var result struct {
			Imported, Skipped int
			Rules             []config.IDSRule
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if duplicate {
			if result.Imported != 0 || result.Skipped != 1 || result.Rules == nil || len(result.Rules) != 0 {
				t.Fatalf("duplicate result: %+v", result)
			}
		} else if result.Imported != 1 || result.Skipped != 0 || len(result.Rules) != 1 {
			t.Fatalf("import result: %+v", result)
		} else if r := result.Rules[0]; r.Labels["evaluable"] != "false" || len(r.ConversionNotes) == 0 {
			t.Fatalf("missing storage-only evidence: %+v", r)
		}
	}
}
