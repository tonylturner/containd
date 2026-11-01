// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestDecodeRequestConfig(t *testing.T) {
	for _, mode := range []RequestConfigMode{RequestConfigWrite, RequestConfigImport} {
		for _, test := range []struct {
			body, want string
		}{
			{`{"schemaVersion":"0.1.0"}`, `unknown top-level key "schemaVersion"`},
			{`{"SYSTEM":{}}`, `unknown top-level key "SYSTEM" (did you mean "system"?)`},
			{`{"dataplane":{},"data\u0070lane":{}}`, `duplicate top-level key "dataplane"`},
			{`{"snapshot_format":3}`, `unknown top-level key "snapshot_format"`},
			{`{"ids_bank":1}`, `unknown top-level key "ids_bank"`},
			{`{"Export":{}}`, `unknown top-level key "Export"`},
			{`{"services":{"av":{"blockTtlSeconds":3600,"failOpenIcs":true,"timeoutSec":7}}}`, ""},
		} {
			t.Run(fmt.Sprintf("%v/%s", mode, test.body), func(t *testing.T) {
				cfg, err := DecodeRequestConfig([]byte(test.body), mode)
				if test.want != "" {
					if err == nil || err.Error() != test.want {
						t.Fatalf("error=%v want=%q", err, test.want)
					}
				} else if err != nil || cfg.Services.AV.TimeoutSec != 7 {
					t.Fatalf("nested compatibility lost: cfg=%+v err=%v", cfg, err)
				}
			})
		}
	}
}

func TestDecodeRequestConfigRejectsMalformedDocuments(t *testing.T) {
	for _, body := range []string{`null`, `[]`, ``, `{`, `{"system":`, `{} {}`, `{} garbage`} {
		t.Run(body, func(t *testing.T) {
			if _, err := DecodeRequestConfig([]byte(body), RequestConfigWrite); err == nil {
				t.Fatal("accepted a malformed or non-object document")
			}
		})
	}
}

func TestDecodeRequestConfigLegacyExportSchemas(t *testing.T) {
	for _, test := range []struct {
		schema  string
		allowed bool
	}{
		{"", true}, {"0.1.0", true}, {"0.1.1", true}, {"0.1.2", true},
		{"0.1.3", true}, {"0.1.4", true}, {"0.1.5", true}, {"0.1.6", true}, {"0.1.7", true},
		{"0.1.8", false}, {SchemaVersionCurrent, false}, {"0.0.9", false}, {"0.2.0", false}, {"invalid", false},
	} {
		t.Run(test.schema, func(t *testing.T) {
			body := fmt.Appendf(nil, `{"schema_version":%q,"export":{}}`, test.schema)
			if test.schema == "" {
				body = []byte(`{"export":{}}`) // An absent schema denotes 0.1.0.
			}
			_, err := DecodeRequestConfig(body, RequestConfigImport)
			if test.allowed && err != nil {
				t.Fatalf("legacy schema rejected: %v", err)
			}
			if !test.allowed && (err == nil || err.Error() != `unknown top-level key "export"`) {
				t.Fatalf("expected export rejection: %v", err)
			}
		})
	}
	for _, body := range []string{
		`{"export":{},"schema_version":"0.1.7","export":{}}`,
		`{"export":{},"schema_version":"0.1.0","schema_version":"0.1.7"}`,
		`{"export":{},"schemaVersion":"0.1.7"}`,
		`{"export":{},"schema_version":""}`,
		`{"export":{},"schema_version":null}`,
	} {
		if _, err := DecodeRequestConfig([]byte(body), RequestConfigImport); err == nil {
			t.Fatalf("legacy exception bypassed exact/unique keys: %s", body)
		}
	}
}

func TestStoredSnapshotMetadataStillLoads(t *testing.T) {
	store := candidateStore(t)
	ctx := context.Background()
	want, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want.Description = "stored with bank reference"
	if err := store.SaveCandidate(ctx, want); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := store.db.QueryRow(`SELECT data FROM configs WHERE key = ?`, configKeyCandidate).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Format int   `json:"snapshot_format"`
		BankID int64 `json:"ids_bank"`
	}
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Format != snapshotFormatReferencedBank || metadata.BankID == 0 {
		t.Fatalf("fixture lacks storage metadata: %s", raw)
	}
	got, err := store.LoadCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("stored snapshot failed to round-trip its document and IDS bank")
	}
}
