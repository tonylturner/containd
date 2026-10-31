// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
)

func TestPreviewRuleHandler(t *testing.T) {
	dp := newCountingDP(t)
	dp.Events().Append(events.Event{Proto: "iec104", Kind: "request", Transport: "tcp",
		SrcIP: "10.1.0.2", DstIP: "10.2.0.2", SrcPort: 40000, DstPort: 2404,
		Attributes: map[string]any{"apci_type": "I", "type_id": uint8(100), "ca": uint16(1), "direction": "request"}})
	handler := previewRuleHandler(dp.Engine)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/rules/preview",
		strings.NewReader(`{"entry":{"Action":"ALLOW","ICS":{"Protocol":"iec104","ReadOnly":true}},"forwardMatches":{}}`)))
	var got engine.PreviewRuleResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		got.MatchCount != 1 || got.TotalEvents != 1 || len(got.SampleMatches) != 1 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, tc := range []struct {
		method, body string
		want         int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, "{", http.StatusBadRequest},
		{http.MethodPost, `{"Action":"ALLOW"}`, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, "/internal/rules/preview", strings.NewReader(tc.body)))
		if rec.Code != tc.want {
			t.Fatalf("status=%d want=%d", rec.Code, tc.want)
		}
	}
	rec = httptest.NewRecorder()
	previewRuleHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/rules/preview", strings.NewReader("{}")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
}
