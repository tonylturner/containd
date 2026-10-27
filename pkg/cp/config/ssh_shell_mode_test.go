// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSSHShellModeValidation(t *testing.T) {
	for _, mode := range []string{"", "appliance", "linux"} {
		cfg := DefaultConfig()
		cfg.System.SSH.ShellMode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%q: %v", mode, err)
		}
	}
	for _, mode := range []string{"Linux", "LINUX", "bash", " linux", "appliance\n"} {
		cfg := DefaultConfig()
		cfg.System.SSH.ShellMode = mode
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ssh.shellMode") {
			t.Fatalf("%q accepted: %v", mode, err)
		}
	}
}

// A shellMode stored before validation existed loads as the mode it ran,
// so the stored running and candidate configurations still validate.
func TestStoredSSHShellModeLoadsAsTheModeItRan(t *testing.T) {
	for stored, want := range map[string]string{
		"":          "",
		"linux":     "linux",
		"Linux":     "linux",
		"LINUX":     "linux",
		"appliance": "appliance",
		"Appliance": "appliance",
		"bash":      "appliance",
		" linux":    "appliance",
	} {
		s := candidateStore(t)
		ctx := context.Background()
		for _, key := range []string{configKeyRunning, configKeyCandidate} {
			setStoredShellMode(t, s, key, stored)
		}
		running, err := s.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := s.LoadCandidate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []*Config{running, candidate} {
			if cfg.System.SSH.ShellMode != want {
				t.Fatalf("stored %q loaded as %q, want %q", stored, cfg.System.SSH.ShellMode, want)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("stored %q: %v", stored, err)
			}
		}
	}
}

// setStoredShellMode writes shellMode into one stored document, bypassing
// validation as a release that did not validate it would have.
func setStoredShellMode(t *testing.T, s *SQLiteStore, key, mode string) {
	t.Helper()
	var raw string
	if err := s.db.QueryRow(`SELECT data FROM configs WHERE key = ?`, configKeyRunning).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	doc["system"].(map[string]any)["ssh"].(map[string]any)["shellMode"] = mode
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`REPLACE INTO configs VALUES (?, ?, 123)`, key, string(b)); err != nil {
		t.Fatal(err)
	}
}
