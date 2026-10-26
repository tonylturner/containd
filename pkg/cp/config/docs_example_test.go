// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDocsExample(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/mkdocs/config-format.md")
	if err != nil {
		t.Fatal(err)
	}
	const fence = "```json\n"
	if strings.Count(string(doc), fence) != 1 {
		t.Fatal("expected exactly one JSON example")
	}
	_, rest, _ := strings.Cut(string(doc), fence)
	example, _, ok := strings.Cut(rest, "\n```")
	if !ok {
		t.Fatal("JSON example has no closing fence")
	}
	decoder := json.NewDecoder(strings.NewReader(example))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatalf("decode documentation example: %v", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("expected a single JSON document, got: %v", err)
	}
	if cfg.SchemaVersion != SchemaVersionCurrent {
		t.Fatalf("schema_version = %q, want %q", cfg.SchemaVersion, SchemaVersionCurrent)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate documentation example: %v", err)
	}
}
