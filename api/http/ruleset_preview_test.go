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
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
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
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true, EnforceTable: "custom", NFLogGroup: 205, NFQueueGroup: 209}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{}, result: dpengine.RulesetPreview{Ruleset: "engine-compiled", Runtime: dpengine.RulesetPreviewRuntime{IEC104EnvelopeOpen: true, Reason: "owned"}}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/ruleset", nil)
	getRulesetPreviewHandler(&mockStore{cfg: cfg}, engine)(c)
	var got dpengine.RulesetPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		!reflect.DeepEqual(got, engine.result) || !reflect.DeepEqual(engine.cfg, cfg) {
		t.Fatalf("status=%d body=%s forwarded=%+v", rec.Code, rec.Body.String(), engine.cfg)
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
