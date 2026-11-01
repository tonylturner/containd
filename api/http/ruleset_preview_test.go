// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type rulesetPreviewEngine struct {
	*mockEngine
	cfg    *config.Config
	result dpengine.RulesetPreview
	err    error
}

func (e *rulesetPreviewEngine) PreviewRuleset(_ context.Context, cfg *config.Config) (dpengine.RulesetPreview, error) {
	e.cfg = cfg
	return e.result, e.err
}

func TestRulesetPreviewDelegatesCandidate(t *testing.T) {
	cfg := config.DefaultConfig()
	// Stored candidates have a schema stamp; preview must not normalize its
	// source document in place just to obtain a comparable runtime snapshot.
	cfg.SchemaVersion = config.SchemaVersionCurrent
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true, EnforceTable: "custom", NFLogGroup: 205, NFQueueGroup: 209}
	warnings := []enforce.RuleWarning{{RuleID: "maint", Predicate: enforce.PredicateIdentity, Action: rules.ActionAllow,
		Message: "no bound address can match identities operator; the rule matches nothing until one is bound"}}
	applied := dpengine.RulesetStatus{Ruleset: "engine-applied", Warnings: warnings}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{ruleset: applied}, result: dpengine.RulesetPreview{Ruleset: "engine-compiled",
		Runtime: dpengine.RulesetPreviewRuntime{IEC104EnvelopeOpen: true, Reason: "owned"}, Warnings: warnings}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
	getRulesetPreviewHandler(&mockStore{cfg: cfg}, engine)(c)
	var got struct {
		dpengine.RulesetPreview
		EngineStatus dpengine.RulesetStatus `json:"engineStatus"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		!reflect.DeepEqual(got.RulesetPreview, engine.result) || !reflect.DeepEqual(engine.cfg, cfg) {
		t.Fatalf("status=%d body=%s forwarded=%+v", rec.Code, rec.Body.String(), engine.cfg)
	}
	if !reflect.DeepEqual(got.EngineStatus, applied) {
		t.Fatalf("engineStatus = %+v, want %+v", got.EngineStatus, applied)
	}
}

func TestRulesetPreviewOmitsEmptyWarnings(t *testing.T) {
	cfg := config.DefaultConfig()
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{}, result: dpengine.RulesetPreview{Ruleset: "engine-compiled"}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
	getRulesetPreviewHandler(&mockStore{cfg: cfg}, engine)(c)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"warnings"`) || strings.Contains(rec.Body.String(), `"icsCoverage"`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// The candidate's coverage is evaluated from the candidate settings and the
// compiled snapshot; engineStatus keeps the applied coverage the engine
// reported, so the two can differ.
func TestRulesetPreviewCarriesCandidateCoverage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true, DPIEnabled: true, DPIMode: "enforce", NFQueueGroup: 101,
		DPIExclusions: []config.DPIExclusion{{Value: "10.1.0.4", Type: "ip"}}}
	snap := rules.Snapshot{Firewall: []rules.Entry{
		{ID: "read", Destinations: []string{"10.1.0.4/32"}, ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}, Action: rules.ActionAllow},
		{ID: "l4", Action: rules.ActionAllow},
	}}
	applied := dpengine.RulesetStatus{Ruleset: "applied", ICSCoverage: []coverage.Rule{
		{RuleID: "read", Protocol: "modbus", Mode: "enforce", State: coverage.NotEnforcing,
			Reasons: []coverage.Reason{{Code: coverage.QueueUnavailable, Message: "queue"}}},
	}}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{ruleset: applied}, result: dpengine.RulesetPreview{Snapshot: snap, Ruleset: "compiled"}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
	getRulesetPreviewHandler(&mockStore{cfg: cfg}, engine)(c)
	var got struct {
		ICSCoverage  []coverage.Rule        `json:"icsCoverage"`
		EngineStatus dpengine.RulesetStatus `json:"engineStatus"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	want := []coverage.Rule{{RuleID: "read", Protocol: "modbus", Mode: "enforce", State: coverage.Partial,
		Reasons: []coverage.Reason{{Code: coverage.ExclusionOverlap, Value: "10.1.0.4",
			Message: "DPI exclusion 10.1.0.4 meets this rule's addresses; its flows skip inspection"}}}}
	if !reflect.DeepEqual(got.ICSCoverage, want) {
		t.Fatalf("icsCoverage = %+v, want %+v", got.ICSCoverage, want)
	}
	if !reflect.DeepEqual(got.EngineStatus, applied) {
		t.Fatalf("engineStatus = %+v, want %+v", got.EngineStatus, applied)
	}
}

func TestRulesetPreviewEnforcementDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = false
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{}, result: dpengine.RulesetPreview{
		Runtime: dpengine.RulesetPreviewRuntime{Reason: "Enforcement is disabled; nothing would be applied"},
	}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
	getRulesetPreviewHandler(&mockStore{cfg: cfg}, engine)(c)
	var got map[string]json.RawMessage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, exists := got["ruleset"]; exists {
		t.Fatalf("disabled candidate returned a ruleset: %s", rec.Body.String())
	}
	if !strings.Contains(string(got["runtime"]), "Enforcement is disabled; nothing would be applied") {
		t.Fatalf("disabled status missing: %s", rec.Body.String())
	}
}

func TestRulesetPreviewUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine EngineClient
		status int
	}{
		{"no engine", nil, http.StatusServiceUnavailable},
		{"unsupported engine", &mockEngine{}, http.StatusServiceUnavailable},
		{"unreachable engine", &rulesetPreviewEngine{err: errors.New("engine unreachable")}, http.StatusBadGateway},
		{"compile failure", &rulesetPreviewEngine{err: errors.New("engine rejected candidate")}, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
			getRulesetPreviewHandler(&mockStore{cfg: config.DefaultConfig()}, tc.engine)(c)
			if rec.Code != tc.status || strings.Contains(rec.Body.String(), `"ruleset"`) {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
