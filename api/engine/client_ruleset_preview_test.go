// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestClientRulesetPreview(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{EnforceTable: "candidate", NFLogGroup: 205, NFQueueGroup: 209}
	want := engine.RulesetPreview{Ruleset: "candidate rules", Runtime: engine.RulesetPreviewRuntime{IEC104EnvelopeOpen: true, Reason: "owned"},
		Warnings: []enforce.RuleWarning{{RuleID: "maint", Predicate: enforce.PredicateIdentity, Action: rules.ActionAllow, Message: "matches nothing"}}}
	// Management has bound HTTP elsewhere until a restart; a separate
	// engine process cannot know that, so the request carries it.
	config.SetBoundManagementListeners(config.ManagementListeners{HTTP: config.ManagementListener{Addr: ":18080", Enabled: true}})
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
	wantSnap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(wantSnap.LocalInput, func(r rules.LocalServiceRule) bool { return r.Port == 18080 }) {
		t.Fatalf("fixture compiles no bound listener INPUT: %+v", wantSnap.LocalInput)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got rulesetPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/internal/ruleset/preview" ||
			r.Header.Get("Content-Type") != "application/json" || !reflect.DeepEqual(got.Config, cfg) {
			t.Errorf("request %s %s config=%+v", r.Method, r.URL, got.Config)
		}
		// The snapshot is this process's compile, management INPUT included.
		if !reflect.DeepEqual(got.Snapshot, wantSnap) {
			t.Errorf("snapshot=%+v, want %+v", got.Snapshot, wantSnap)
		}
		if err := json.NewEncoder(w).Encode(want); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	got, err := NewHTTPClient(server.URL).PreviewRuleset(context.Background(), cfg)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("preview=%+v err=%v", got, err)
	}
}

func TestClientRulesetPreviewErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"offline", "offline", http.StatusServiceUnavailable},
		{"rejected", "invalid candidate", http.StatusBadRequest},
		{"JSON", "{", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				http.Error(w, tc.body, tc.status)
			}))
			defer server.Close()
			if _, err := NewHTTPClient(server.URL).PreviewRuleset(context.Background(), config.DefaultConfig()); err == nil {
				t.Fatal("preview succeeded")
			}
		})
	}
	invalid := config.DefaultConfig()
	invalid.Firewall.Rules = []config.Rule{{ID: "bad", Action: "INVALID"}}
	if _, err := NewHTTPClient("http://unused.invalid").PreviewRuleset(context.Background(), invalid); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("invalid candidate preview err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewHTTPClient("http://unused.invalid").PreviewRuleset(ctx, config.DefaultConfig()); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("canceled preview err=%v", err)
	}
}
