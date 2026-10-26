// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type bankRoutingStore struct {
	*config.SQLiteStore
	ordinary, bankAware, fullReads, documentReads int
}

func (s *bankRoutingStore) LoadCandidate(ctx context.Context) (*config.Config, error) {
	s.fullReads++
	return s.SQLiteStore.LoadCandidate(ctx)
}

func (s *bankRoutingStore) LoadCandidateDocument(ctx context.Context) (*config.Config, error) {
	s.documentReads++
	return s.SQLiteStore.LoadCandidateDocument(ctx)
}

func (s *bankRoutingStore) MutateCandidate(ctx context.Context, edit func(*config.Config) error) error {
	s.ordinary++
	return s.SQLiteStore.MutateCandidate(ctx, edit)
}

func (s *bankRoutingStore) MutateCandidateIDS(ctx context.Context, edit func(*config.Config) error) error {
	s.bankAware++
	return s.SQLiteStore.MutateCandidateIDS(ctx, edit)
}

func TestCandidateBankRoutingAndResponse(t *testing.T) {
	store := &bankRoutingStore{SQLiteStore: stageStore(t)}
	server := NewServer(store, nil)
	// Even a settings-only IDS request returns the bank and must load it.
	rec := requestStage(t, server, "POST", "/ids/rules", map[string]any{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("IDS settings: %d %s", rec.Code, rec.Body)
	}
	var ids config.IDSConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &ids); err != nil {
		t.Fatal(err)
	}
	if len(ids.Rules) == 0 || store.bankAware != 1 || store.ordinary != 0 {
		t.Fatal("IDS response implied an empty bank or used bank-free path")
	}
	cfg, err := store.LoadCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg.IDS.Rules = nil
	rec = requestStage(t, server, "POST", "/config/candidate", cfg)
	if rec.Code != http.StatusOK || store.ordinary != 1 || store.bankAware != 1 {
		t.Fatalf("omitted bank did not use ordinary path: %d %s", rec.Code, rec.Body)
	}
	cfg, err = store.LoadCandidate(context.Background())
	if err != nil || len(cfg.IDS.Rules) == 0 {
		t.Fatalf("omitted bank dropped rules: %v", err)
	}
	// Config's omitempty would erase an empty slice; use an explicit wire array.
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	document["ids"].(map[string]any)["rules"] = []any{}
	rec = requestStage(t, server, "POST", "/config/candidate", document)
	if rec.Code != http.StatusOK || store.ordinary != 1 || store.bankAware != 2 {
		t.Fatalf("explicit bank did not use IDS path: %d %s", rec.Code, rec.Body)
	}
	cfg, err = store.LoadCandidate(context.Background())
	if err != nil || len(cfg.IDS.Rules) != 0 {
		t.Fatalf("explicit empty bank did not clear rules: %v", err)
	}
}

type bankFreeValidationServices struct{}

func (bankFreeValidationServices) Apply(context.Context, config.ServicesConfig) error    { return nil }
func (bankFreeValidationServices) Validate(context.Context, config.ServicesConfig) error { return nil }

func TestServiceValidationReadsBankFreeDocument(t *testing.T) {
	store := &bankRoutingStore{SQLiteStore: stageStore(t)}
	server := NewServerWithEngineAndServices(store, nil, nil, bankFreeValidationServices{}, nil)
	for _, path := range []string{"/services/dns", "/services/av"} {
		rec := requestStage(t, server, "POST", path, map[string]any{})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if store.fullReads != 0 || store.documentReads != 2 || store.ordinary != 2 || store.bankAware != 0 {
		t.Fatalf("service staging loaded bank: %+v", store)
	}
}
