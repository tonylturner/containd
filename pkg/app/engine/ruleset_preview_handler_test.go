// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestRulesetPreviewHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true, DPIEnabled: true, EnforceTable: "candidate", NFLogGroup: 205, NFQueueGroup: 209}
	cfg.Firewall.Rules = []config.Rule{
		{ID: "iec", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "logged", Action: config.ActionDeny, Log: true, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}},
		{ID: "modbus", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "modbus"},
			Protocols: []config.Protocol{{Name: "tcp", Port: "502"}}},
	}
	// The running engine has different settings; preview must use the candidate.
	dp, err := engine.New(engine.Config{NFQueueGroup: 101, ResetInjector: &session.Fake{}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	previewRulesetHandler(dp).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/ruleset/preview", bytes.NewReader(body)))
	var preview engine.RulesetPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &preview) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want, err := enforce.NewCompilerWithSettings(compilerSettings(cfg.DataPlane), nil).CompileFirewall(&snap)
	if err != nil || preview.Ruleset != want || preview.Runtime.IEC104EnvelopeOpen {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	if !strings.Contains(preview.Ruleset, "group 205") || !strings.Contains(preview.Ruleset, "table inet candidate") ||
		!strings.Contains(preview.Ruleset, "tcp dport 502 queue num 209") ||
		!strings.Contains(preview.Runtime.Reason, "not owned") || dp.CurrentRules() != nil {
		t.Fatalf("candidate preview = %+v", preview)
	}
}

func TestRulesetPreviewSettingsMapping(t *testing.T) {
	for _, table := range []string{"", "custom"} {
		cfg := config.DataPlaneConfig{Enforcement: true, EnforceTable: table, NFLogGroup: 205}
		dp, err := newEngineFor(zap.NewNop().Sugar(), cfg, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := compile.CompileSnapshot(config.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		preview, err := dp.PreviewRuleset(snap, compilerSettings(cfg))
		want := table
		if want == "" {
			want = "containd"
		}
		if err != nil || !strings.Contains(preview.Ruleset, "table inet "+want+" {") {
			t.Fatalf("preview=%+v err=%v", preview, err)
		}
	}
}

func TestRulesetPreviewHandlerErrors(t *testing.T) {
	dp := newCountingDP(t).Engine
	for _, tc := range []struct {
		name, method, body string
		engine             *engine.Engine
		status             int
	}{
		{"method", http.MethodGet, "", dp, http.StatusMethodNotAllowed},
		{"offline", http.MethodPost, "{}", nil, http.StatusServiceUnavailable},
		{"JSON", http.MethodPost, "{", dp, http.StatusBadRequest},
		{"candidate", http.MethodPost, `{"firewall":{"rules":[{"id":"bad","action":"INVALID"}]}}`, dp, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			previewRulesetHandler(tc.engine).ServeHTTP(rec, httptest.NewRequest(tc.method, "/internal/ruleset/preview", strings.NewReader(tc.body)))
			if rec.Code != tc.status || strings.Contains(rec.Body.String(), `"ruleset"`) {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
