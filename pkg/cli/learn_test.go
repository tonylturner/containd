// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/learn"
)

func TestLearnShowIsViewOnlyAndPaged(t *testing.T) {
	called := false
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/learn/suggestions": func(r *http.Request) (*http.Response, error) {
			called = true
			if r.URL.Query().Get("cursor") != "next" || r.URL.Query().Get("datasetId") != "dataset" {
				t.Fatal("paging/filter lost")
			}
			return jsonHTTPResponse(200, map[string]any{"items": []any{}, "nextCursor": "last"}, nil), nil
		},
	}}
	api := &API{BaseURL: "http://test", Client: client}
	var out bytes.Buffer
	if err := showLearn(api, "/learn/suggestions", false)(context.Background(), &out, []string{"--cursor", "next", "--dataset", "dataset"}); err != nil {
		t.Fatal(err)
	}
	if !called || !strings.Contains(out.String(), "last") {
		t.Fatal("show generated permission or hid paging")
	}
	registry := NewRegistry(nil, api)
	if !slices.Contains(registry.CommandsForRole(RoleView), "show learn suggestions") || slices.Contains(registry.CommandsForRole(RoleView), "generate learn") || slices.Contains(registry.CommandsForRole(RoleView), "analyze pcap") {
		t.Fatal("learner command roles incorrect")
	}
}

func TestLearnCLIStagesOnlySelectedRevisions(t *testing.T) {
	called := 0
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/learn/apply": func(r *http.Request) (*http.Response, error) {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var req learn.ApplyRequest
			if err := json.Unmarshal(data, &req); err != nil || req.RequestID != "request-one" || len(req.Selections) != 1 || req.Selections[0].Revision != 3 {
				t.Fatalf("stage request %s: %v", data, err)
			}
			called++
			return jsonHTTPResponse(200, map[string]bool{"staged": true}, map[string]string{"X-Containd-Config": "staged"}), nil
		},
	}}
	cmd := applyLearn(&API{BaseURL: "http://test", Client: client})
	for _, args := range [][]string{nil, {"request-one", "one"}, {"request-one", "one@0"}, {"request-one", "one@1", "one@2"}} {
		if err := cmd(context.Background(), io.Discard, args); err == nil {
			t.Fatal("bulk/ambiguous selection accepted")
		}
	}
	if err := cmd(context.Background(), io.Discard, []string{"request-one", "one@3"}); err != nil || called != 1 {
		t.Fatal("selected stage failed", err)
	}
}

func TestAnalyzePcapUsesNestedImportStatistics(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "input.pcap")
	if err := os.WriteFile(filename, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/pcap/analyze": func(r *http.Request) (*http.Response, error) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Fatal(err)
			}
			return jsonHTTPResponse(200, map[string]any{"dataset": map[string]string{"id": "imported"}, "stats": map[string]any{"packetCount": 42, "byteCount": 99, "flows": []any{}}}, nil), nil
		},
	}}
	var out bytes.Buffer
	if err := analyzePcapAPI(&API{BaseURL: "http://test", Client: client})(context.Background(), &out, []string{filename}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Dataset:   imported") || !strings.Contains(out.String(), "Packets:   42") {
		t.Fatalf("response flattened: %s", &out)
	}
}
