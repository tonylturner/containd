// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"context"
	"encoding/json"
	"testing"
)

// Earlier releases stored services.av.blockTtlSeconds. The setting is gone,
// but a stored or exported configuration that still carries it must load
// and validate; the value is ignored.
func TestStoredAVBlockTTLStillLoads(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	running, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	running.Services.AV = AVConfig{Enabled: true, Mode: "clamav", TimeoutSec: 7}
	raw, err := marshalStoredConfig(configKeyRunning, running)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	var services map[string]json.RawMessage
	if err := json.Unmarshal(stored["services"], &services); err != nil {
		t.Fatal(err)
	}
	var av map[string]any
	if err := json.Unmarshal(services["av"], &av); err != nil {
		t.Fatal(err)
	}
	av["blockTtlSeconds"] = 3600
	if services["av"], err = json.Marshal(av); err != nil {
		t.Fatal(err)
	}
	if stored["services"], err = json.Marshal(services); err != nil {
		t.Fatal(err)
	}
	if raw, err = json.Marshal(stored); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE configs SET data = ? WHERE key = ?`, string(raw), configKeyRunning); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("load a stored config with blockTtlSeconds: %v", err)
	}
	if got := loaded.Services.AV; !got.Enabled || got.Mode != "clamav" || got.TimeoutSec != 7 {
		t.Fatalf("av settings = %+v", got)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
