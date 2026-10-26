// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"fmt"
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

// isolateNTPManagerEnv points NewNTPManager away from host state: no chronyd
// on the host, no supervision and no log file or syslog sink.
func isolateNTPManagerEnv(t *testing.T, ntpdPath string) {
	t.Helper()
	t.Setenv("CONTAIND_NTPD_PATH", ntpdPath)
	t.Setenv("CONTAIND_SUPERVISE_NTP", "0")
	t.Setenv("CONTAIND_SERVICES_DIR", "")
	t.Setenv("CONTAIND_LOG_FILE", "0")
	t.Setenv("CONTAIND_LOG_SYSLOG_ADDR", "")
}

func TestStatusReflectsState(t *testing.T) {
	isolateNTPManagerEnv(t, filepath.Join(t.TempDir(), "absent", "chronyd"))
	m := NewNTPManager(t.TempDir())

	if err := m.Apply(context.Background(), config.NTPConfig{
		Enabled: true,
		Servers: []string{"pool.ntp.org", "time.google.com"},
	}); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	status := m.Status()
	if status["enabled"] != true {
		t.Error("status should show enabled=true")
	}
	if status["servers_count"] != 2 {
		t.Errorf("status servers_count = %v, want 2", status["servers_count"])
	}
	// The supported implementation is chrony even when the binary is missing.
	if status["ntpd_name"] != "chrony" || status["ntpd_path"] != "" {
		t.Errorf("status ntpd = %v at %q, want chrony with no path", status["ntpd_name"], status["ntpd_path"])
	}
	if status["supervise"] != false || status["running"] != false {
		t.Errorf("status supervise = %v, running = %v; want both false", status["supervise"], status["running"])
	}
}

// A detected chronyd validates the rendered config with "-p -f <path>".
func TestApplyValidatesWithDetectedChronyd(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	chronyd := filepath.Join(bin, "chronyd")
	if err := os.WriteFile(chronyd, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	isolateNTPManagerEnv(t, chronyd)
	m := NewNTPManager(t.TempDir())

	if err := m.Apply(context.Background(), config.NTPConfig{Enabled: true, Servers: []string{"pool.ntp.org"}}); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("chronyd was not run: %v", err)
	}
	if want := "-p\n-f\n" + m.configPath() + "\n"; string(args) != want {
		t.Errorf("chronyd args = %q, want %q", args, want)
	}
	if status := m.Status(); status["enabled"] != true || status["ntpd_path"] != chronyd || status["last_error"] != "" {
		t.Errorf("status = %v", status)
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

func TestStatusUsesRenderedPollInterval(t *testing.T) {
	for _, tc := range []struct {
		requested int
		interval  any
		min, max  int
	}{
		{60, 64, 64, 64}, {3600, 4096, 4096, 4096}, {1, 16, 16, 16}, {200000, 131072, 131072, 131072}, {0, nil, 64, 1024},
	} {
		m := &NTPManager{BaseDir: t.TempDir()}
		if err := m.Apply(context.Background(), config.NTPConfig{Enabled: true, Servers: []string{"pool.ntp.org"}, IntervalSeconds: tc.requested}); err != nil {
			t.Fatal(err)
		}
		status := m.Status()
		if status["interval_seconds"] != tc.interval || status["min_poll_seconds"] != tc.min || status["max_poll_seconds"] != tc.max {
			t.Fatalf("request %d: status %v", tc.requested, status)
		}
		content, err := os.ReadFile(m.configPath())
		if err != nil {
			t.Fatal(err)
		}
		if tc.requested > 0 {
			poll := 0
			for seconds := tc.min; seconds > 1; seconds /= 2 {
				poll++
			}
			if !contains(string(content), fmt.Sprintf("minpoll %d maxpoll %d", poll, poll)) {
				t.Fatalf("status disagrees with rendered config: %s", content)
			}
		}
	}
}

func TestFailedValidationPreservesAppliedStatus(t *testing.T) {
	m := &NTPManager{BaseDir: t.TempDir()}
	if err := m.Apply(context.Background(), config.NTPConfig{Enabled: true, IntervalSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	m.NTPDPath = "/nonexistent/chronyd"
	if err := m.Apply(context.Background(), config.NTPConfig{Enabled: true, IntervalSeconds: 3600}); err == nil {
		t.Fatal("expected validation failure")
	}
	if got := m.Status()["interval_seconds"]; got != 64 {
		t.Fatalf("failed request leaked into status: %v", got)
	}
}

func TestDetectNTPDRejectsOtherDaemon(t *testing.T) {
	p := filepath.Join(t.TempDir(), "openntpd")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_NTPD_PATH", p)
	path, name := detectNTPD()
	if path != "" || name != "chrony" {
		t.Fatalf("unsupported daemon selected: %q %q", path, name)
	}
}
