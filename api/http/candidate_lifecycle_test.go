// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestWholeConfigReplacesCandidateOnly(t *testing.T) {
	for _, path := range []string{"/config", "/config/import", "/config/candidate"} {
		t.Run(path, func(t *testing.T) {
			store := stageStore(t)
			ctx := context.Background()
			running, _ := store.Load(ctx)
			if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
				cfg.Description = "replace-me"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			replacement := config.DefaultConfig()
			replacement.System.Hostname = "replacement"
			replacement.IDS.Rules = config.DefaultIDSConfig().Rules[1:2]
			engine := &stageEngine{mockEngine: &mockEngine{}}
			server := NewServerWithEngine(store, nil, engine)
			rec := requestStage(t, server, "POST", path, replacement)
			if rec.Code != http.StatusOK || engine.mutations != 0 {
				t.Fatalf("replacement failed or applied: %d %s", rec.Code, rec.Body)
			}
			candidate, _ := store.LoadCandidate(ctx)
			after, _ := store.Load(ctx)
			if candidate.System.Hostname != "replacement" || candidate.Description != "" || !reflect.DeepEqual(after, running) {
				t.Fatal("replacement did not exclusively replace candidate")
			}
			rec = requestStage(t, server, "POST", "/config/commit", nil)
			after, _ = store.Load(ctx)
			if rec.Code != http.StatusOK || after.System.Hostname != "replacement" || after.IDS.Rules[0].ID != replacement.IDS.Rules[0].ID {
				t.Fatalf("replacement commit failed: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestImportValidationIsClientErrorAndPreservesCandidate(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
		cfg.Description = "keep-me"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.LoadCandidate(ctx)
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "bad", Zone: "missing"}}
	rec := requestStage(t, NewServer(store, nil), "POST", "/config/import", cfg)
	after, _ := store.LoadCandidate(ctx)
	if rec.Code != http.StatusBadRequest || !reflect.DeepEqual(before, after) {
		t.Fatalf("invalid import status=%d changed candidate=%v", rec.Code, !reflect.DeepEqual(before, after))
	}
}

func TestRunningExportsAndDiffAuthority(t *testing.T) {
	t.Setenv("CONTAIND_CONFIG_BACKUP_DIR", t.TempDir())
	store := stageStore(t)
	ctx := context.Background()
	running, _ := store.Load(ctx)
	server := NewServer(store, nil)
	rec := requestStage(t, server, "GET", "/config/diff", nil)
	var diff struct {
		Running, Candidate *config.Config
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &diff); err != nil || !reflect.DeepEqual(diff.Running, diff.Candidate) {
		t.Fatalf("seed looks pending: %s %v", rec.Body, err)
	}
	if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
		cfg.System.Hostname = "staged"
		cfg.IDS.Rules = config.DefaultIDSConfig().Rules[1:2]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/config", "/config/export"} {
		rec = requestStage(t, server, "GET", path, nil)
		var got config.Config
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(&got, running.RedactedCopy()) {
			t.Fatalf("%s did not read running: %s %v", path, rec.Body, err)
		}
	}
	rec = requestStage(t, server, "GET", "/ids/backup", nil)
	var bank []config.IDSRule
	if err := json.Unmarshal(rec.Body.Bytes(), &bank); err != nil || !reflect.DeepEqual(bank, running.IDS.Rules) {
		t.Fatalf("backup did not read running bank: %s %v", rec.Body, err)
	}
	rec = requestStage(t, server, "GET", "/ids/export?format=sigma", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET export not registered: %d %s", rec.Code, rec.Body)
	}
	rec = requestStage(t, server, "POST", "/ids/export", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST export alias survived: %d", rec.Code)
	}
	rec = requestStage(t, server, "POST", "/config/backups", map[string]any{"name": "running", "redacted": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("backup status=%d %s", rec.Code, rec.Body)
	}
	var backup configBackupInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &backup); err != nil {
		t.Fatal(err)
	}
	rec = requestStage(t, server, "GET", "/config/backups/"+backup.ID, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"hostname":"staged"`) || !strings.Contains(rec.Body.String(), `"hostname": "running"`) {
		t.Fatalf("config backup did not read running: %d %s", rec.Code, rec.Body)
	}
}

func TestPCAPOperationsPreserveRunningAndCandidate(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	running, _ := store.Load(ctx)
	running.PCAP.Interfaces = []string{"running"}
	if err := store.Save(ctx, running); err != nil {
		t.Fatal(err)
	}
	if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
		cfg.PCAP.Interfaces = []string{"candidate"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	candidate, _ := store.LoadCandidate(ctx)
	engine := newRuntimeMockEngine()
	server := NewServerWithEngine(store, nil, engine)
	for _, body := range []string{"", `{"interfaces":["explicit"]}`} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, authedRequest("POST", "/api/v1/pcap/start", strings.NewReader(body)))
		want := "running"
		if body != "" {
			want = "explicit"
		}
		if rec.Code != http.StatusOK || len(engine.pcapStartCfg.Interfaces) != 1 || engine.pcapStartCfg.Interfaces[0] != want {
			t.Fatalf("start used incorrect settings: %d %+v", rec.Code, engine.pcapStartCfg)
		}
		rec = requestStage(t, server, "POST", "/pcap/stop", nil)
		after, _ := store.Load(ctx)
		desired, _ := store.LoadCandidate(ctx)
		if rec.Code != http.StatusOK || !reflect.DeepEqual(after, running) || !reflect.DeepEqual(desired, candidate) {
			t.Fatal("capture start/stop persisted configuration")
		}
	}
}

func TestCandidateRoundTripPreservesStagedSecrets(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	secret := testSensitiveValue("staged-key")
	if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
		cfg.Services.VPN.WireGuard.PrivateKey = secret
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, nil)
	rec := requestStage(t, server, "GET", "/config/candidate", nil)
	var redacted config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &redacted); err != nil {
		t.Fatal(err)
	}
	rec = requestStage(t, server, "POST", "/config/candidate", redacted)
	cfg, _ := store.LoadCandidate(ctx)
	if rec.Code != http.StatusOK || cfg.Services.VPN.WireGuard.PrivateKey != secret {
		t.Fatal("redacted round trip restored running rather than staged secrets")
	}
}
