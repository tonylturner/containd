// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const installedRulesetPath = "/api/v1/dataplane/ruleset/status"

// failingLoadStore fails every config read: the installed status must not
// depend on the candidate.
func failingLoadStore() *mockStore {
	return &mockStore{load: func() (*config.Config, error) { return nil, errors.New("candidate unreadable") }}
}

func getInstalledRuleset(t *testing.T, engine EngineClient) (int, map[string]json.RawMessage, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	NewServerWithEngine(failingLoadStore(), nil, engine).ServeHTTP(rec, authedRequest(http.MethodGet, installedRulesetPath, nil))
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("status=%d body=%s: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, body, rec.Body.String()
}

func TestInstalledRulesetStatusReportsFailedApplyWithoutRulesetText(t *testing.T) {
	appliedAt := time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC)
	failedAt := appliedAt.Add(time.Hour)
	status := dpengine.RulesetStatus{
		Ruleset: "nft-ruleset-text", SnapshotVersion: "v41", AppliedAt: appliedAt,
		Error: "nft: Error: Could not process rule", FailedSnapshotVersion: "v42", FailedAt: &failedAt,
		Warnings:    []enforce.RuleWarning{{RuleID: "block-ssh", ShadowedBy: "allow-ssh", Action: rules.ActionDeny, Message: "shadowed"}},
		ICSCoverage: []coverage.Rule{{RuleID: "modbus-read", Protocol: "modbus", Mode: "enforce", State: coverage.Enforcing}},
		SchedulePlanner: &dpengine.SchedulePlan{LastRefill: appliedAt, HorizonEnd: appliedAt.Add(time.Hour),
			State: dpengine.SchedulePlannerDegraded, Reason: "the schedule horizon ends within an hour"},
	}
	code, body, raw := getInstalledRuleset(t, &mockEngine{ruleset: status})
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%s", code, raw)
	}
	if _, ok := body["ruleset"]; ok || strings.Contains(raw, "nft-ruleset-text") {
		t.Fatalf("installed status carries the ruleset text: %s", raw)
	}
	if string(body["installed"]) != "true" {
		t.Fatalf("installed = %s, want true", body["installed"])
	}
	var got dpengine.RulesetStatus
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	want := status
	want.Ruleset = ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
}

// Installed follows the ruleset in force, not the last apply time: disabling
// enforcement releases the ruleset but keeps its apply time.
func TestInstalledRulesetStatusInstalled(t *testing.T) {
	appliedAt := time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		status dpengine.RulesetStatus
		want   string
	}{
		"before any apply":       {dpengine.RulesetStatus{}, "false"},
		"first apply failed":     {dpengine.RulesetStatus{Error: "nft failed"}, "false"},
		"in force":               {dpengine.RulesetStatus{Ruleset: "table inet containd_policy {}", AppliedAt: appliedAt}, "true"},
		"released after disable": {dpengine.RulesetStatus{AppliedAt: appliedAt, SnapshotVersion: "v41"}, "false"},
	} {
		t.Run(name, func(t *testing.T) {
			code, body, raw := getInstalledRuleset(t, &mockEngine{ruleset: tc.status})
			if code != http.StatusOK || string(body["installed"]) != tc.want {
				t.Fatalf("status=%d installed=%s, want %s: %s", code, body["installed"], tc.want, raw)
			}
		})
	}
}

func TestInstalledRulesetStatusWithoutEngine(t *testing.T) {
	for name, tc := range map[string]struct {
		engine EngineClient
		code   int
		error  string
	}{
		"no engine":    {nil, http.StatusServiceUnavailable, `"engine unavailable"`},
		"engine error": {&healthRulesetEngine{mockEngine: &mockEngine{}, err: errors.New("connection refused")}, http.StatusBadGateway, `"engine ruleset status unavailable: connection refused"`},
	} {
		t.Run(name, func(t *testing.T) {
			code, body, raw := getInstalledRuleset(t, tc.engine)
			if code != tc.code || string(body["error"]) != tc.error {
				t.Fatalf("status=%d body=%s, want %d %s", code, raw, tc.code, tc.error)
			}
		})
	}
}

// Viewers read the installed status; the preview that compiles the
// candidate stays admin-only.
func TestViewerReadsInstalledRulesetStatus(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	us := newMockUserStore()
	tok, _ := addTestUser(us, []byte(testJWTSecret), "viewer-ruleset", "viewerruleset", "view", false)
	resetTestRateLimiters()
	engine := &mockEngine{ruleset: dpengine.RulesetStatus{Ruleset: "nft-ruleset-text", AppliedAt: time.Now(), Error: "nft failed"}}
	s := NewServerWithEngineAndServices(failingLoadStore(), nil, engine, nil, us)
	for path, want := range map[string]int{
		installedRulesetPath:        http.StatusOK,
		"/api/v1/dataplane/ruleset": http.StatusForbidden,
	} {
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, s, rec, jwtAuthedRequest(http.MethodGet, path, &bytes.Buffer{}, tok))
		if rec.Code != want {
			t.Fatalf("viewer %s = %d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
		if path == installedRulesetPath && (!strings.Contains(rec.Body.String(), `"error":"nft failed"`) || strings.Contains(rec.Body.String(), "nft-ruleset-text")) {
			t.Fatalf("viewer installed status = %s", rec.Body.String())
		}
	}
}
