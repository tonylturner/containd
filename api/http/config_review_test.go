// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

type captureApplyEngine struct {
	*runtimeMockEngine
	starts, stops, settings int
}

func (e *captureApplyEngine) StartPcap(ctx context.Context, cfg config.PCAPConfig) (pcap.Status, error) {
	e.starts++
	return e.runtimeMockEngine.StartPcap(ctx, cfg)
}
func (e *captureApplyEngine) StopPcap(context.Context) (pcap.Status, error) {
	e.stops++
	return pcap.Status{}, nil
}
func (e *captureApplyEngine) SetPcapConfig(ctx context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error) {
	e.settings++
	return e.runtimeMockEngine.SetPcapConfig(ctx, cfg)
}

func TestPromotionReconcilesOnlyChangedPCAPSettings(t *testing.T) {
	for _, action := range []string{"commit", "commit_confirmed", "rollback"} {
		for _, change := range []string{"unrelated", "enable", "disable"} {
			t.Run(action+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				store := stageStore(t)
				first, _ := store.Load(ctx)
				first.PCAP.Enabled = change == "disable"
				first.PCAP.Interfaces = []string{"spare"}
				if err := store.Save(ctx, first); err != nil {
					t.Fatal(err)
				}
				next := *first
				next.Description = "unrelated edit"
				if change != "unrelated" {
					next.PCAP.Enabled = !first.PCAP.Enabled
				}
				// Rollback promotes previous instead of candidate.
				if action == "rollback" {
					if err := testSaveCandidate(store, ctx, &next); err != nil {
						t.Fatal(err)
					}
					if err := testCommit(store, ctx); err != nil {
						t.Fatal(err)
					}
				} else if err := testSaveCandidate(store, ctx, &next); err != nil {
					t.Fatal(err)
				}
				engine := &captureApplyEngine{runtimeMockEngine: newRuntimeMockEngine()}
				server := NewServerWithEngine(store, nil, engine)
				rec := requestStage(t, server, "POST", "/pcap/start", map[string]any{"interfaces": []string{"explicit"}})
				if rec.Code != http.StatusOK || !reflect.DeepEqual(engine.pcapStartCfg.Interfaces, []string{"explicit"}) {
					t.Fatalf("explicit capture failed: %d %s", rec.Code, rec.Body)
				}
				rec = requestStage(t, server, "POST", "/config/"+action, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("promotion failed: %d %s", rec.Code, rec.Body)
				}
				wantStart, wantStop, wantSettings := 1, 0, 0
				if change != "unrelated" {
					wantSettings = 1
					promoted := &next
					if action == "rollback" {
						promoted = first
					}
					if promoted.PCAP.Enabled {
						wantStart++
					} else {
						wantStop++
					}
				}
				if engine.starts != wantStart || engine.stops != wantStop || engine.settings != wantSettings {
					t.Fatalf("capture calls starts/stops/settings=%d/%d/%d want %d/%d/%d", engine.starts, engine.stops, engine.settings, wantStart, wantStop, wantSettings)
				}
			})
		}
	}
}

func TestDiffDetectsSecretsAndSummarizesBank(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	var diff struct {
		Changed         bool
		ChangedSections []string
		Running         *config.Config
		Candidate       *config.Config
		IDSBank         struct{ Running, Candidate idsBankSummary }
	}
	read := func() string {
		t.Helper()
		rec := requestStage(t, server, "GET", "/config/diff", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("diff failed: %d %s", rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &diff); err != nil {
			t.Fatal(err)
		}
		return rec.Body.String()
	}
	read()
	if diff.Changed || len(diff.ChangedSections) != 0 || diff.IDSBank.Running != diff.IDSBank.Candidate {
		t.Fatal("unseeded candidate appears dirty")
	}
	secret := testSensitiveValue("rotated-secret")
	if err := testMutateCandidate(store, context.Background(), func(cfg *config.Config) error {
		cfg.Services.VPN.WireGuard.PrivateKey = secret
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := read()
	if !diff.Changed || !reflect.DeepEqual(diff.ChangedSections, []string{"services"}) || strings.Contains(body, secret) {
		t.Fatalf("secret-only edit lost or leaked: %s", body)
	}
	if !reflect.DeepEqual(diff.Running, diff.Candidate) {
		t.Fatal("secret-only redacted snapshots should be equal")
	}
	if err := testMutateCandidateIDS(store, context.Background(), func(cfg *config.Config) error {
		cfg.IDS.Rules = []config.IDSRule{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read()
	if !reflect.DeepEqual(diff.ChangedSections, []string{"ids", "services"}) ||
		diff.IDSBank.Running.Count == 0 || diff.IDSBank.Candidate.Count != 0 ||
		diff.IDSBank.Running.SHA256 == diff.IDSBank.Candidate.SHA256 ||
		diff.Running.IDS.Rules != nil || diff.Candidate.IDS.Rules != nil {
		t.Fatalf("bank diff incorrect: %+v", diff)
	}
	for _, path := range []string{"/config", "/config/candidate", "/config/export"} {
		rec := requestStage(t, server, "GET", path, nil)
		var got config.Config
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if (path == "/config/export") != (len(got.IDS.Rules) > 0) {
			t.Fatalf("%s bank inclusion incorrect", path)
		}
	}
}

type validationReadServices struct {
	store config.Store
}

func (s validationReadServices) ApplyEffective(_ context.Context, cfg config.ServicesConfig, _ []config.ServiceConfigError) (config.ServicesConfig, []string) {
	return cfg, nil
}
func (s validationReadServices) Validate(ctx context.Context, _ config.ServicesConfig) error {
	return configReadableDuringDiscovery(ctx, s.store)
}

type discoveryReadEngine struct {
	*mockEngine
	store config.Store
}

func (e discoveryReadEngine) ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error) {
	return []config.InterfaceState{{Name: "eth0"}}, configReadableDuringDiscovery(ctx, e.store)
}

func configReadableDuringDiscovery(ctx context.Context, store config.Store) error {
	done := make(chan error, 1)
	go func() { _, err := store.Load(ctx); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		return context.DeadlineExceeded
	}
}

func TestStagingDiscoveryDoesNotHoldStoreMutex(t *testing.T) {
	store := stageStore(t)
	server := NewServerWithEngineAndServices(store, nil, discoveryReadEngine{&mockEngine{}, store}, validationReadServices{store}, nil)
	for _, path := range []string{"/services/dns", "/services/av", "/interfaces/assign"} {
		var body any = map[string]any{}
		if path == "/interfaces/assign" {
			body = map[string]any{"mode": "explicit", "mappings": map[string]string{"spare": "eth0"}}
		}
		rec := requestStage(t, server, "POST", path, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s discovery blocked: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestConfigReadsOmitBankAndRoundTripRetainsIt(t *testing.T) {
	for _, path := range []string{"/config", "/config/candidate", "/config/import"} {
		t.Run(path, func(t *testing.T) {
			store := stageStore(t)
			ctx := context.Background()
			running, _ := store.Load(ctx)
			server := NewServer(store, nil)
			for _, readPath := range []string{"/config", "/config/candidate"} {
				rec := requestStage(t, server, "GET", readPath, nil)
				var cfg config.Config
				if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil || cfg.IDS.Rules != nil {
					t.Fatalf("%s included bank: %s %v", readPath, rec.Body, err)
				}
				cfg.Description = "round-tripped without bank"
				rec = requestStage(t, server, "POST", path, cfg)
				candidateSnapshot1, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				candidate := candidateSnapshot1.Candidate
				if rec.Code != http.StatusOK || err != nil || !reflect.DeepEqual(candidate.IDS.Rules, running.IDS.Rules) {
					t.Fatalf("%s lost omitted bank: %d %s %v", path, rec.Code, rec.Body, err)
				}
			}
		})
	}
}

func (validationReadServices) RecordEngineFaults([]config.ServiceFault) {}
