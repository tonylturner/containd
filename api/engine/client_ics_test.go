// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// CP JSON → compile → rules.Snapshot → the body ApplyRules sends → the
// Snapshot the engine decodes. The IEC104 fields stay numeric/string arrays.
func TestApplyRulesRoundTripsIEC104Predicate(t *testing.T) {
	t.Parallel()

	const ruleJSON = `{
		"id": "iec-cmd",
		"sourceZones": ["scada"],
		"protocols": [{"name": "tcp", "port": "2404"}],
		"ics": {
			"protocol": "iec104",
			"typeIds": [45, 46],
			"classes": ["control"],
			"ca": [1, 65534],
			"ioa": [{"start": 65536, "end": 65567}],
			"mode": "enforce"
		},
		"action": "ALLOW"
	}`
	var rule config.Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("decode CP rule: %v", err)
	}
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  []config.Zone{{Name: "scada"}},
		// An enforce iec104 rule needs inline DPI; validation rejects it otherwise.
		DataPlane: config.DataPlaneConfig{DPIEnabled: true, NFQueueGroup: 101},
		Firewall: config.FirewallConfig{
			DefaultAction: config.ActionDeny,
			Rules:         []config.Rule{rule},
		},
	}
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/apply_rules" {
			http.NotFound(w, r)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewHTTPClient(srv.URL).ApplyRules(context.Background(), snap); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}
	for _, frag := range []string{
		`"typeIds":[45,46]`,
		`"classes":["control"]`,
		`"ca":[1,65534]`,
		`"ioa":[{"start":65536,"end":65567}]`,
	} {
		if !strings.Contains(string(body), frag) {
			t.Fatalf("engine body lacks %s:\n%s", frag, body)
		}
	}

	// Decode as the engine's /internal/apply_rules handler does.
	var got rules.Snapshot
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("engine decode: %v", err)
	}
	want := rules.ICSPredicate{
		Protocol: "iec104",
		Mode:     "enforce",
		TypeIDs:  []int{45, 46},
		Classes:  []string{"control"},
		CA:       []uint16{1, 65534},
		IOA:      []rules.IOARange{{Start: 65536, End: 65567}},
	}
	if len(got.Firewall) != 1 || !reflect.DeepEqual(got.Firewall[0].ICS, want) {
		t.Fatalf("engine ICS = %+v, want %+v", got.Firewall, want)
	}
}
