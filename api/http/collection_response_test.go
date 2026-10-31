// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestConfigCollectionResponses(t *testing.T) {
	for _, cfg := range []*config.Config{
		{},
		{
			Interfaces: []config.Interface{},
			Assets:     []config.Asset{},
			Objects:    []config.Object{},
			Zones:      []config.Zone{},
			Firewall:   config.FirewallConfig{Rules: []config.Rule{}},
		},
		config.DefaultConfig(),
	} {
		before := jsonValue(t, cfg)
		server := NewServer(&mockStore{cfg: cfg}, nil)
		for path, collection := range map[string]any{
			"/firewall/rules": cfg.Firewall.Rules,
			"/interfaces":     cfg.Interfaces,
			"/assets":         cfg.Assets,
			"/objects":        cfg.Objects,
			"/zones":          cfg.Zones,
		} {
			t.Run(path, func(t *testing.T) {
				rec := requestStage(t, server, http.MethodGet, path, nil)
				want := jsonValue(t, collection)
				if reflect.ValueOf(collection).Len() == 0 {
					want = []any{}
				}
				var got any
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || !reflect.DeepEqual(got, want) {
					t.Fatalf("GET %s: status=%d body=%s, want %v", path, rec.Code, rec.Body, want)
				}
			})
		}
		if !reflect.DeepEqual(jsonValue(t, cfg), before) {
			t.Fatal("collection GET mutated stored config")
		}
	}
}

func TestCLIQuickstartCreatesFirstCandidateRule(t *testing.T) {
	store := stageStore(t)
	engine := &stageEngine{mockEngine: &mockEngine{
		state: []config.InterfaceState{{Name: "eth0", Addrs: []string{"192.0.2.7/24"}}},
	}}
	handler := NewServerWithEngine(store, nil, engine)
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "wan", Device: "eth0", Zone: "wan"}}
	cfg.Firewall.Rules = nil
	// Reproduce a full-config write persisting the redacted empty rule list.
	rec := requestStage(t, handler, http.MethodPost, "/config/candidate", cfg)
	if rec.Code != http.StatusOK {
		t.Fatalf("stage ruleless config: %d %s", rec.Code, rec.Body)
	}
	ctx := context.Background()
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	api := &cli.API{BaseURL: server.URL, Client: server.Client(), Token: testAdminToken}
	registry := cli.NewRegistry(store, api)
	var output bytes.Buffer
	if err := registry.ParseAndExecute(cli.WithRole(ctx, string(cli.RoleAdmin)), "set outbound quickstart", &output); err != nil {
		t.Fatal(err)
	}
	candidate, err := store.LoadCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Firewall.Rules) != 1 {
		t.Fatalf("candidate rules = %+v", candidate.Firewall.Rules)
	}
	rule := candidate.Firewall.Rules[0]
	if rule.ID != "allow-lan-mgmt-wan" || rule.Action != config.ActionAllow ||
		!reflect.DeepEqual(rule.SourceZones, []string{"lan", "mgmt"}) ||
		!reflect.DeepEqual(rule.DestZones, []string{"wan"}) || !candidate.Firewall.NAT.Enabled {
		t.Fatalf("unexpected quickstart candidate: %+v", candidate.Firewall)
	}
	after, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) || engine.mutations != 0 {
		t.Fatal("quickstart changed running config or applied to engine")
	}
}
