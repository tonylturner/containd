// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
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
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := postRulesetPreview(t, dp, cfg, snap)
	var preview engine.RulesetPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &preview) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	want, err := enforce.NewCompilerWithSettings(compilerSettings(cfg.DataPlane), nil).CompileFirewall(&preview.Snapshot)
	if err != nil || preview.Ruleset != want || preview.Runtime.IEC104EnvelopeOpen {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	// The engine refuses gated connections until its gate manager opens the
	// gate; the preview compiles the candidate's gate with that admission.
	if preview.Runtime.GateAdmit != "refuse" || !strings.Contains(preview.Runtime.GateAdmitReason, "scanning gate refusing") ||
		!strings.Contains(preview.Ruleset, "chain "+enforce.GateAdmitChain+" {") {
		t.Fatalf("gate admission runtime = %+v", preview.Runtime)
	}
	if !strings.Contains(preview.Ruleset, "group 205") || !strings.Contains(preview.Ruleset, "table inet candidate") ||
		!regexp.MustCompile(`tcp dport 502 counter name "rule_[0-9a-f]{16}" jump ics_queue;`).MatchString(preview.Ruleset) ||
		!strings.Contains(preview.Ruleset, "ct status assured meta mark set meta mark and 0xe0ffffff queue num 209;") ||
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
		if err != nil || !strings.Contains(preview.Ruleset, "table inet "+want+"_policy {") || !strings.Contains(preview.Ruleset, "add table inet "+want+"\n") {
			t.Fatalf("preview=%+v err=%v", preview, err)
		}
	}
}

func TestRulesetPreviewHandlerEnforcementDisabled(t *testing.T) {
	for _, runningEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("running-enforcement=%v", runningEnabled), func(t *testing.T) {
			dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{ClearMark: noPolicyMarks, Enabled: runningEnabled}})
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.DataPlane = config.DataPlaneConfig{Enforcement: false, EnforceTable: "never_applied", NFLogGroup: 205, NFQueueGroup: 209}
			snap, err := compile.CompileSnapshot(cfg)
			if err != nil {
				t.Fatal(err)
			}
			before := dp.RulesetStatus()
			rec := postRulesetPreview(t, dp, cfg, snap)
			var got map[string]json.RawMessage
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if _, exists := got["ruleset"]; exists {
				t.Fatalf("disabled candidate returned a ruleset: %s", rec.Body.String())
			}
			var runtime engine.RulesetPreviewRuntime
			if json.Unmarshal(got["runtime"], &runtime) != nil || runtime.IEC104EnvelopeOpen ||
				runtime.Reason != "Enforcement is disabled; nothing would be applied" ||
				strings.Contains(string(got["runtime"]), "gateAdmit") {
				t.Fatalf("runtime = %+v (%s)", runtime, got["runtime"])
			}
			if dp.CurrentRules() != nil || !reflect.DeepEqual(dp.RulesetStatus(), before) {
				t.Fatal("disabled preview changed live enforcement")
			}
		})
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
		{"no config", http.MethodPost, `{"snapshot":{}}`, dp, http.StatusBadRequest},
		{"snapshot", http.MethodPost, `{"config":{"dataplane":{"enforcement":true}},"snapshot":{"ZoneIfaces":{"lan":["interface-name-too-long"]}}}`, dp, http.StatusBadRequest},
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

// The engine previews the snapshot management sent, so its management INPUT
// is management's: a separate engine process neither re-resolves the
// listeners under its own environment nor drops management's bound ones.
func TestRulesetPreviewHandlerUsesManagementSnapshot(t *testing.T) {
	dp := newCountingDP(t).Engine
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: true}
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	snap.LocalInput = append(snap.LocalInput, rules.LocalServiceRule{ID: "auto-allow-mgmt-http-bound", Proto: "tcp", Port: 18080, RecoverUnbound: true})
	rec := postRulesetPreview(t, dp, cfg, snap)
	var preview engine.RulesetPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &preview) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(preview.Snapshot.LocalInput, snap.LocalInput) || !strings.Contains(preview.Ruleset, "tcp dport 18080") {
		t.Fatalf("preview dropped management's INPUT: %+v\n%s", preview.Snapshot.LocalInput, preview.Ruleset)
	}
}

func TestRulesetPreviewHandlerRejectsReservationConflict(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "fixture", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, ManagementReservation: r}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DataPlane = config.DataPlaneConfig{Enforcement: false}
	rec := postRulesetPreview(t, dp, cfg, rules.Snapshot{})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved management path") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func postRulesetPreview(t *testing.T, dp *engine.Engine, cfg *config.Config, snap rules.Snapshot) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(rulesetPreviewRequest{Config: cfg, Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	previewRulesetHandler(dp).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/ruleset/preview", bytes.NewReader(body)))
	return rec
}
