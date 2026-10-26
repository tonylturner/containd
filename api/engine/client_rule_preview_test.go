// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestClientPreviewRule(t *testing.T) {
	entry := rules.Entry{ID: "candidate", SourceZones: []string{"control"}, DestZones: []string{"plant"},
		Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}}}
	want := engine.PreviewRuleResponse{MatchCount: 2, TotalEvents: 20, SampleMatches: []events.Event{{ID: 3}},
		Warnings: []enforce.RuleWarning{{RuleID: "candidate", Predicate: enforce.PredicateSchedule, Action: rules.ActionAllow,
			Message: "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got rules.Entry
		if r.Method != http.MethodPost || r.URL.Path != "/internal/rules/preview" ||
			r.Header.Get("Content-Type") != "application/json" ||
			json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got, entry) {
			t.Errorf("request %s %s entry=%+v", r.Method, r.URL, got)
		}
		if err := json.NewEncoder(w).Encode(want); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	got, err := NewHTTPClient(server.URL).PreviewRule(context.Background(), entry)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("preview=%+v err=%v", got, err)
	}
}

func TestClientPreviewRuleFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"engine error", http.StatusServiceUnavailable, "offline"},
		{"bad JSON", http.StatusOK, "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			_, err := NewHTTPClient(server.URL).PreviewRule(context.Background(), rules.Entry{})
			if err == nil || (tc.status != http.StatusOK && !strings.Contains(err.Error(), "offline")) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewHTTPClient("http://unused.invalid").PreviewRule(ctx, rules.Entry{}); err == nil {
		t.Fatal("canceled request succeeded")
	}
}
