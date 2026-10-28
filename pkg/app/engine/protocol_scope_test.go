// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"go.uber.org/zap"
)

func TestRemovedProtocolInternalHandlers(t *testing.T) {
	dp := newCountingDP(t)
	config := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{})
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip", " ENiP "} {
		want := fmt.Sprintf("protocol %q is not supported; supported: modbus, dnp3, iec104, cip", name)
		if strings.EqualFold(strings.TrimSpace(name), "enip") {
			want = fmt.Sprintf(`protocol %q: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`, name)
		}
		for _, enabled := range []bool{true, false} {
			body, err := json.Marshal(map[string]any{"dpiIcsProtocols": map[string]bool{name: enabled}})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			config.ServeHTTP(rec, httptest.NewRequest("POST", "/internal/config", bytes.NewReader(body)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
				t.Fatalf("%s toggle: %d %s", name, rec.Code, rec.Body)
			}
		}
		for _, snap := range []rules.Snapshot{
			{Firewall: []rules.Entry{{ID: "bad", ICS: rules.ICSPredicate{Protocol: name}}}},
			{IDS: rules.IDSConfig{Rules: []rules.IDSRule{{ID: "bad", Proto: name}}}},
		} {
			body, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			applyRulesHandler(dp.Engine, nil).ServeHTTP(rec, httptest.NewRequest("POST", "/internal/apply_rules", bytes.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("snapshot: %d %s", rec.Code, rec.Body)
			}
		}
		before := len(dp.SignatureEngine().List())
		sig := signatures.Signature{ID: "bad", Protocol: name, Conditions: []signatures.Condition{{Field: "kind", Op: "equals", Value: "request"}}}
		body, err := json.Marshal(sig)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		signaturesHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest("POST", "/internal/signatures", bytes.NewReader(body)))
		if rec.Code != http.StatusBadRequest || len(dp.SignatureEngine().List()) != before {
			t.Fatalf("signature: %d %s", rec.Code, rec.Body)
		}
	}
	if dp.reconfigs.Load() != 0 || dp.starts.Load() != 0 {
		t.Fatal("rejected config changed the engine")
	}
}
