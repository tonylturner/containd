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
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

// icsCoverageConfig is a valid candidate with one Modbus enforce rule.
func icsCoverageConfig(queue uint16) *config.Config {
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true, DPIEnabled: true, DPIMode: "enforce", NFQueueGroup: queue}
	cfg.Firewall.Rules = []config.Rule{{ID: "modbus-read", Action: config.ActionAllow,
		Protocols: []config.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       config.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}}}
	return cfg
}

func getICSCoverage(t *testing.T, store config.Store, engine EngineClient) map[string]json.RawMessage {
	t.Helper()
	rec := httptest.NewRecorder()
	NewServerWithEngine(store, nil, engine).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/dataplane/ics-coverage", nil))
	var body map[string]json.RawMessage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := body["ruleset"]; ok || strings.Contains(rec.Body.String(), "nft-ruleset-text") {
		t.Fatalf("coverage response carries the ruleset: %s", rec.Body.String())
	}
	return body
}

func decodeRules(t *testing.T, raw json.RawMessage) []coverage.Rule {
	t.Helper()
	var out []coverage.Rule
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func TestICSCoverageReportsCandidateAndApplied(t *testing.T) {
	appliedAt := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	applied := []coverage.Rule{{RuleID: "modbus-read", Protocol: "modbus", Mode: "enforce", State: coverage.NotEnforcing,
		Reasons: []coverage.Reason{{Code: coverage.QueueUnavailable, Message: "queue", Runtime: true}}}}
	engine := &mockEngine{ruleset: dpengine.RulesetStatus{Ruleset: "nft-ruleset-text", AppliedAt: appliedAt,
		Error: "nft apply failed", ICSCoverage: applied}}
	body := getICSCoverage(t, &mockStore{cfg: icsCoverageConfig(101)}, engine)
	want := []coverage.Rule{{RuleID: "modbus-read", Protocol: "modbus", Mode: "enforce", State: coverage.Enforcing}}
	if got := decodeRules(t, body["candidate"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate = %+v, want %+v", got, want)
	}
	if got := decodeRules(t, body["applied"]); !reflect.DeepEqual(got, applied) {
		t.Fatalf("applied = %+v, want %+v", got, applied)
	}
	var at time.Time
	if json.Unmarshal(body["appliedAt"], &at) != nil || !at.Equal(appliedAt) {
		t.Fatalf("appliedAt = %s", body["appliedAt"])
	}
	if string(body["applyError"]) != `"nft apply failed"` {
		t.Fatalf("applyError = %s", body["applyError"])
	}
	for _, key := range []string{"candidateError", "engineStatusError"} {
		if _, ok := body[key]; ok {
			t.Fatalf("unexpected %s: %s", key, body[key])
		}
	}
}

// An invalid candidate hides neither the applied coverage nor the reason;
// the ruleset preview keeps refusing it.
func TestICSCoverageWithInvalidCandidate(t *testing.T) {
	store := &mockStore{cfg: icsCoverageConfig(0)}
	applied := []coverage.Rule{{RuleID: "modbus-read", Protocol: "modbus", Mode: "monitor", State: coverage.Monitoring}}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{ruleset: dpengine.RulesetStatus{AppliedAt: time.Now(), ICSCoverage: applied}}}
	body := getICSCoverage(t, store, engine)
	if _, ok := body["candidate"]; ok {
		t.Fatalf("invalid candidate evaluated: %s", body["candidate"])
	}
	if !strings.Contains(string(body["candidateError"]), "dataplane.nfqueueGroup") {
		t.Fatalf("candidateError = %s", body["candidateError"])
	}
	if got := decodeRules(t, body["applied"]); !reflect.DeepEqual(got, applied) {
		t.Fatalf("applied = %+v", got)
	}
	rec := httptest.NewRecorder()
	NewServerWithEngine(store, nil, engine).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ruleset preview of an invalid candidate = %d, want 400", rec.Code)
	}
}

func TestICSCoverageWithUnreadableCandidate(t *testing.T) {
	store := &mockStore{load: func() (*config.Config, error) { return nil, errors.New("disk gone") }}
	applied := []coverage.Rule{{RuleID: "modbus-read", Protocol: "modbus", Mode: "monitor", State: coverage.Monitoring}}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{ruleset: dpengine.RulesetStatus{AppliedAt: time.Now(), ICSCoverage: applied}}}
	body := getICSCoverage(t, store, engine)
	if _, ok := body["candidate"]; ok {
		t.Fatalf("unreadable candidate evaluated: %s", body["candidate"])
	}
	if got := string(body["candidateError"]); got != `"candidate config unavailable"` {
		t.Fatalf("candidateError = %s", got)
	}
	if got := decodeRules(t, body["applied"]); !reflect.DeepEqual(got, applied) {
		t.Fatalf("applied = %+v", got)
	}
}

func TestICSCoverageWithoutEngine(t *testing.T) {
	for name, engine := range map[string]EngineClient{
		"no engine":    nil,
		"engine error": &healthRulesetEngine{mockEngine: &mockEngine{}, err: errors.New("connection refused")},
	} {
		t.Run(name, func(t *testing.T) {
			body := getICSCoverage(t, &mockStore{cfg: config.DefaultConfig()}, engine)
			if _, ok := body["applied"]; ok {
				t.Fatalf("applied reported without an engine: %s", body["applied"])
			}
			if !strings.HasPrefix(string(body["engineStatusError"]), `"engine ruleset status unavailable`) {
				t.Fatalf("engineStatusError = %s", body["engineStatusError"])
			}
			if string(body["candidate"]) != "[]" {
				t.Fatalf("candidate without ICS rules = %s, want []", body["candidate"])
			}
		})
	}
	body := getICSCoverage(t, &mockStore{cfg: config.DefaultConfig()}, &mockEngine{})
	if string(body["applied"]) != "[]" {
		t.Fatalf("applied without ICS rules = %s, want []", body["applied"])
	}
	if _, ok := body["appliedAt"]; ok {
		t.Fatalf("appliedAt before any apply: %s", body["appliedAt"])
	}
}

// Viewers read coverage; the ruleset preview stays admin-only.
func TestViewerReadsICSCoverage(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	us := newMockUserStore()
	tok, _ := addTestUser(us, []byte(testJWTSecret), "viewer-cov", "viewercov", "view", false)
	s := setupJWTServer(&mockStore{cfg: icsCoverageConfig(101)}, us)
	for path, want := range map[string]int{
		"/api/v1/dataplane/ics-coverage":   http.StatusOK,
		"/api/v1/firewall/shadow-counters": http.StatusOK,
		"/api/v1/dataplane/ruleset":        http.StatusForbidden,
	} {
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, s, rec, jwtAuthedRequest(http.MethodGet, path, &bytes.Buffer{}, tok))
		if rec.Code != want {
			t.Fatalf("viewer %s = %d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
	}
}
