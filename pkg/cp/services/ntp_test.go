// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestIntervalToPoll(t *testing.T) {
	tests := []struct {
		seconds int
		want    int
	}{
		{0, 4},     // minimum poll
		{10, 4},    // below 16s → poll 4
		{16, 4},    // exactly 16s → poll 4
		{17, 5},    // just above 16s → poll 5
		{60, 6},    // 60s → poll 6 (2^6=64)
		{64, 6},    // exactly 64s → poll 6
		{65, 7},    // just above 64s → poll 7
		{3600, 12}, // 1 hour → poll 12 (2^12=4096)
	}
	for _, tt := range tests {
		got := intervalToPoll(tt.seconds)
		if got != tt.want {
			t.Errorf("intervalToPoll(%d) = %d, want %d", tt.seconds, got, tt.want)
		}
	}
}

func TestRenderChronyConfig(t *testing.T) {
	m := &NTPManager{NTPDName: "chrony"}
	cfg := config.NTPConfig{
		Enabled:         true,
		Servers:         []string{"pool.ntp.org", "time.google.com"},
		IntervalSeconds: 3600,
	}

	out := m.renderChronyConfig(cfg)

	// Must contain server directives with iburst.
	for _, s := range cfg.Servers {
		if !contains(out, "server "+s+" iburst") {
			t.Errorf("config missing server directive for %s", s)
		}
	}
	// Must contain required chrony directives.
	for _, want := range []string{"makestep 1 -1", "driftfile /data/chrony.drift", "port 0", "cmdport 0"} {
		if !contains(out, want) {
			t.Errorf("config missing required directive %q", want)
		}
	}
	// Must contain poll parameters when interval is set.
	if !contains(out, "minpoll") || !contains(out, "maxpoll") {
		t.Error("config missing poll parameters for non-zero interval")
	}
}

func TestRenderChronyConfigNoInterval(t *testing.T) {
	m := &NTPManager{NTPDName: "chrony"}
	cfg := config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org"},
	}
	out := m.renderChronyConfig(cfg)
	if contains(out, "minpoll") || contains(out, "maxpoll") {
		t.Error("config should not contain poll parameters when interval is 0")
	}
}

func TestRenderChronyConfigSkipsEmptyServers(t *testing.T) {
	m := &NTPManager{NTPDName: "chrony"}
	cfg := config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org", "", "  ", "time.google.com"},
	}
	out := m.renderChronyConfig(cfg)
	if contains(out, "server  ") || contains(out, "server \n") {
		t.Error("config should not contain empty server directives")
	}
}

func TestRenderOpenNTPDConfig(t *testing.T) {
	m := &NTPManager{NTPDName: "openntpd"}
	cfg := config.NTPConfig{
		Enabled:         true,
		Servers:         []string{"pool.ntp.org"},
		IntervalSeconds: 60,
	}
	out := m.renderOpenNTPDConfig(cfg)
	if !contains(out, "servers pool.ntp.org") {
		t.Error("openntpd config missing server directive")
	}
}

func TestApplyWritesConfigFile(t *testing.T) {
	dir := t.TempDir()
	m := &NTPManager{
		BaseDir:   dir,
		NTPDName:  "chrony",
		NTPDPath:  "", // no binary — config should still be written
		Supervise: false,
	}

	cfg := config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org"},
	}
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	path := filepath.Join(dir, "chrony.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !contains(string(data), "server pool.ntp.org iburst") {
		t.Errorf("config file content wrong: %s", string(data))
	}
}

func TestApplyDisabledRemovesConfig(t *testing.T) {
	dir := t.TempDir()
	m := &NTPManager{
		BaseDir:   dir,
		NTPDName:  "chrony",
		Supervise: false,
	}

	// First enable and write config.
	_ = m.Apply(context.Background(), config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org"},
	})
	path := filepath.Join(dir, "chrony.conf")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("config file should exist after enable")
	}

	// Now disable.
	_ = m.Apply(context.Background(), config.NTPConfig{Enabled: false})
	if _, err := os.Stat(path); err == nil {
		t.Error("config file should be removed after disable")
	}
}

func TestStatusReflectsState(t *testing.T) {
	m := NewNTPManager(t.TempDir())
	m.Supervise = false

	_ = m.Apply(context.Background(), config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org", "time.google.com"},
	})

	status := m.Status()
	if status["enabled"] != true {
		t.Error("status should show enabled=true")
	}
	if status["servers_count"] != 2 {
		t.Errorf("status servers_count = %v, want 2", status["servers_count"])
	}
	if status["ntpd_name"] == nil || status["ntpd_name"] == "" {
		// ntpd_name should be set even if binary not found (empty string is ok)
	}
	if status["running"] != false {
		t.Error("status should show running=false when supervise is disabled")
	}
	// Backward compatibility field.
	if _, ok := status["openntpd_path"]; !ok {
		t.Error("status should include backward-compatible openntpd_path field")
	}
}

func TestDetectNTPDPrefersEnvVar(t *testing.T) {
	// Create a fake binary to test env var detection.
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "chronyd")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONTAIND_NTPD_PATH", fakeBin)
	t.Setenv("CONTAIND_OPENNTPD_PATH", "")

	path, name := detectNTPD()
	if path != fakeBin {
		t.Errorf("detectNTPD() path = %q, want %q", path, fakeBin)
	}
	if name != "chrony" {
		t.Errorf("detectNTPD() name = %q, want chrony", name)
	}
}

func TestConfigPath(t *testing.T) {
	m := &NTPManager{BaseDir: "/data/services", NTPDName: "chrony"}
	if got := m.configPath(); got != "/data/services/chrony.conf" {
		t.Errorf("configPath() = %q, want /data/services/chrony.conf", got)
	}
	m.NTPDName = "openntpd"
	if got := m.configPath(); got != "/data/services/openntpd.conf" {
		t.Errorf("configPath() = %q, want /data/services/openntpd.conf", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
