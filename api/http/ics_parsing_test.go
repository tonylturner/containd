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
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestICSParsingConfigRoundTrip(t *testing.T) {
	resetTestRateLimiters()
	store := stageStore(t)
	ctx := context.Background()
	server := NewServerWithEngine(store, nil, &stageEngine{mockEngine: &mockEngine{}})
	initial := map[string]string{"modbus": "strict", "iec104": "strict"}
	check := func(path string, want map[string]string) config.Config {
		t.Helper()
		rec := requestStage(t, server, "GET", path, nil)
		var cfg config.Config
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cfg.DataPlane.DPIICSParsing, want) {
			t.Fatalf("%s: parsing=%v want=%v", path, cfg.DataPlane.DPIICSParsing, want)
		}
		if got := ics.EffectiveParsing(cfg.DataPlane.DPIICSParsing, "cip"); got != ics.Tolerant {
			t.Fatalf("omitted protocol: %s", got)
		}
		return cfg
	}
	post := func(path string, body any) {
		t.Helper()
		rec := requestStage(t, server, "POST", path, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	check("/config", nil)
	post("/dataplane", config.DataPlaneConfig{DPIICSParsing: initial})
	check("/config/candidate", initial)
	check("/config", nil) // staging does not change running
	post("/config/commit", nil)
	exported := check("/config/export", initial)
	check("/config", initial)
	var dp config.DataPlaneConfig
	rec := requestStage(t, server, "GET", "/dataplane", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &dp); err != nil || rec.Code != http.StatusOK || !reflect.DeepEqual(dp.DPIICSParsing, initial) {
		t.Fatalf("dataplane round trip: %d %s %v", rec.Code, rec.Body, err)
	}

	post("/dataplane", config.DataPlaneConfig{DPIICSParsing: map[string]string{"dnp3": "strict"}})
	post("/config/commit", nil)
	post("/config/rollback", nil)
	check("/config", initial) // rollback restores the explicit strict entries
	post("/config/import", exported)
	check("/config/candidate", initial)
	post("/config/commit", nil)
	check("/config/export", initial)

	running, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(running.DataPlane.DPIICSParsing, initial) {
		t.Fatalf("stored running: %+v %v", running, err)
	}
}

func TestICSParsingAPIRejectsInvalid(t *testing.T) {
	resetTestRateLimiters()
	for _, modes := range []map[string]string{{"modbus": "invalid"}, {"enip": "strict"}} {
		for _, path := range []string{"/dataplane", "/config/import"} {
			t.Run(fmt.Sprint(path, ":", modes), func(t *testing.T) {
				store := stageStore(t)
				beforeSnapshot1, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
				before := beforeSnapshot1.Candidate
				if err != nil {
					t.Fatal(err)
				}
				cfg := config.DefaultConfig()
				cfg.DataPlane.DPIICSParsing = modes
				var body any = cfg
				if path == "/dataplane" {
					body = cfg.DataPlane
				}
				rec := requestStage(t, NewServer(store, nil), "POST", path, body)
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "dpiIcsParsing") {
					t.Fatalf("invalid parsing: %d %s", rec.Code, rec.Body)
				}
				afterSnapshot2, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
				after := afterSnapshot2.Candidate
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("invalid save changed candidate: %v", err)
				}
			})
		}
	}
}
