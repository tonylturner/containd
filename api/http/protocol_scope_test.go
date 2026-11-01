// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/templates"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func TestRemovedProtocolStageAtomic(t *testing.T) {
	resetTestRateLimiters()
	store := stageStore(t)
	ctx := context.Background()
	if err := testSaveCandidate(store, ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, nil)
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stagedSnapshot1, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	staged := stagedSnapshot1.Candidate
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip", " ENiP "} {
		// Each protocol is an independent validation case, not a rate-limit test.
		resetTestRateLimiters()
		suffix := " is not supported; supported: " + ics.SupportedNames
		if strings.EqualFold(strings.TrimSpace(name), "enip") {
			suffix = `: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`
		}
		for _, kind := range []string{"rule", "toggle-on", "toggle-off", "ids"} {
			cfg := config.DefaultConfig()
			var want string
			switch kind {
			case "rule":
				cfg.Firewall.Rules = []config.Rule{{ID: "bad", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: name}}}
				want = fmt.Sprintf("rule bad ics protocol %q%s", name, suffix)
			case "ids":
				cfg.IDS.Rules = []config.IDSRule{{ID: "bad", Proto: name}}
				want = fmt.Sprintf("ids rule bad proto %q%s", name, suffix)
			default:
				cfg.DataPlane.DPIICSProtocols = map[string]bool{name: kind == "toggle-on"}
				want = fmt.Sprintf("dataplane.dpiIcsProtocols: protocol %q%s", name, suffix)
			}
			for _, path := range []string{"/config", "/config/import"} {
				rec := requestStage(t, server, "POST", path, cfg)
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusBadRequest || body.Error != want {
					t.Fatalf("%s %s: %d %s", name, kind, rec.Code, rec.Body)
				}
			}

			running, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(before, running) {
				t.Fatalf("rejected request changed running: %v", err)
			}
			candidateSnapshot2, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
			candidate := candidateSnapshot2.Candidate
			if err != nil || !reflect.DeepEqual(staged, candidate) {
				t.Fatalf("rejected request changed candidate/bank: %v", err)
			}
		}
	}
}

func TestRemovedProtocolSignature(t *testing.T) {
	eng := &signatureMockEngine{mockEngine: &mockEngine{}}
	server := NewServerWithEngine(&mockStore{}, nil, eng)
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip", " ENiP "} {
		sig := signatures.Signature{ID: "bad", Protocol: name, Conditions: []signatures.Condition{{Field: "kind", Op: "equals", Value: "request"}}}
		rec := requestStage(t, server, "POST", "/signatures", sig)
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("signature bad protocol %q is not supported; supported: %s", name, ics.SupportedNames)
		if strings.EqualFold(strings.TrimSpace(name), "enip") {
			want = fmt.Sprintf(`signature bad protocol %q: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`, name)
		}
		if rec.Code != http.StatusBadRequest || body.Error != want || len(eng.added) != 0 {
			t.Fatalf("signature %s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestRemovedProtocolICSTemplates(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	for _, catalog := range []string{"/templates", "/templates/ics"} {
		rec := requestStage(t, server, "GET", catalog, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("catalog %s: %d %s", catalog, rec.Code, rec.Body)
		}
		for _, name := range []string{"s7comm", "bacnet", "opcua"} {
			if strings.Contains(rec.Body.String(), name) {
				t.Fatalf("catalog advertises %s", name)
			}
		}
	}
	for _, name := range []string{"s7comm-read-only", "bacnet-read-only", "opcua-monitor-only"} {
		if _, err := templates.Get(name); err == nil {
			t.Fatalf("generic registry retained %s", name)
		}
		for _, alias := range []string{name, strings.ReplaceAll(name, "-", "_")} {
			if _, err := buildICSTemplateRules(alias, nil); err == nil || !strings.Contains(err.Error(), alias) {
				t.Fatalf("unknown template error: %v", err)
			}
			for _, path := range []string{"/templates/apply", "/templates/ics/apply"} {
				rec := requestStage(t, server, "POST", path, map[string]string{"template": alias, "name": alias})
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), alias) {
					t.Fatalf("%s %s: %d %s", path, alias, rec.Code, rec.Body)
				}
			}
		}
	}
}
