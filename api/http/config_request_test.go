// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestFullConfigRequestKeys(t *testing.T) {
	for _, path := range []string{"/config", "/config/candidate", "/config/validate", "/config/import"} {
		for _, test := range []struct {
			name, member, detail string
		}{
			{"unknown", `"dataplan":{}`, `unknown top-level key "dataplan"`},
			{"case", `"dataPlane":{}`, `unknown top-level key "dataPlane" (did you mean "dataplane"?)`},
			{"duplicate", `"description":"first","description":"second"`, `duplicate top-level key "description"`},
			{"canonical", `"description":"accepted"`, ""},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				store := stageStore(t)
				ctx := context.Background()
				beforeSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				if err != nil {
					t.Fatal(err)
				}
				before := beforeSnapshot.Candidate
				raw, err := json.Marshal(config.DefaultConfig())
				if err != nil {
					t.Fatal(err)
				}
				body := json.RawMessage(`{` + test.member + `,` + string(raw[1:]))
				rec := requestStage(t, NewServer(store, nil), "POST", path, body)
				wantStatus := http.StatusOK
				if test.detail != "" {
					wantStatus = http.StatusBadRequest
				}
				if rec.Code != wantStatus {
					t.Fatalf("status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body)
				}
				if test.detail != "" {
					var failure struct{ Error, Detail string }
					if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
						t.Fatal(err)
					}
					if failure.Detail != test.detail {
						t.Fatalf("detail=%q want=%q", failure.Detail, test.detail)
					}
				}
				afterSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				if err != nil {
					t.Fatal(err)
				}
				after := afterSnapshot.Candidate
				if test.detail != "" || path == "/config/validate" {
					if !reflect.DeepEqual(before, after) {
						t.Fatal("rejected request or validation mutated the candidate")
					}
				} else if after.Description != "accepted" {
					t.Fatal("canonical request was not staged")
				}
			})
		}
	}
}

func TestImportLegacyExportKey(t *testing.T) {
	for _, schema := range []string{"", "0.1.0", "0.1.7", "0.1.8", "0.1.9", config.SchemaVersionCurrent} {
		for _, path := range []string{"/config", "/config/candidate", "/config/validate", "/config/import"} {
			t.Run(path+"/"+schema, func(t *testing.T) {
				store := stageStore(t)
				ctx := context.Background()
				beforeSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				if err != nil {
					t.Fatal(err)
				}
				before := beforeSnapshot.Candidate
				raw := json.RawMessage(fmt.Sprintf(`{"schema_version":%q,"export":{},"description":"legacy import"}`, schema))
				if schema == "" {
					raw = json.RawMessage(`{"export":{},"description":"legacy import"}`)
				}
				rec := requestStage(t, NewServer(store, nil), "POST", path, raw)
				allowed := path == "/config/import" && (schema == "" || schema == "0.1.0" || schema == "0.1.7")
				if !allowed {
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("expected export rejection: %d %s", rec.Code, rec.Body)
					}
					var failure struct{ Error, Detail string }
					if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
						t.Fatal(err)
					}
					if failure.Detail != `unknown top-level key "export"` {
						t.Fatalf("detail=%q want unknown export key: %s", failure.Detail, rec.Body)
					}
					afterSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, afterSnapshot.Candidate) {
						t.Fatal("rejected legacy export mutated the candidate")
					}
					return
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("legacy import failed: %d %s", rec.Code, rec.Body)
				}
				afterSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				if err != nil {
					t.Fatal(err)
				}
				candidate := afterSnapshot.Candidate
				if candidate.SchemaVersion != config.SchemaVersionCurrent || candidate.Description != "legacy import" {
					t.Fatalf("import not migrated: %+v", candidate)
				}
				out, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(out, &fields); err != nil {
					t.Fatal(err)
				}
				if _, ok := fields["export"]; ok {
					t.Fatal("retired export key survived migration")
				}
			})
		}
	}
}
