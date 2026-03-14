// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestValidateOpenVPNManagedClient(t *testing.T) {
	valid := &config.OpenVPNManagedClientConfig{
		Remote: "vpn.example.test",
		CA:     "ca-pem",
		Cert:   "cert-pem",
		Key:    "key-pem",
	}

	opts, err := validateOpenVPNManagedClient(valid)
	if err != nil {
		t.Fatalf("validateOpenVPNManagedClient(valid): %v", err)
	}
	if opts.remote != "vpn.example.test" || opts.port != 1194 || opts.proto != "udp" {
		t.Fatalf("unexpected managed client opts: %#v", opts)
	}

	if _, err := validateOpenVPNManagedClient(nil); err == nil {
		t.Fatal("expected nil managed client validation error")
	}
	if _, err := validateOpenVPNManagedClient(&config.OpenVPNManagedClientConfig{
		Remote: "vpn.example.test",
		CA:     "ca-pem",
		Cert:   "cert-pem",
		Key:    "key-pem",
		Username: "alice",
	}); err == nil {
		t.Fatal("expected username/password pair validation error")
	}
}

func TestValidateAndRenderOpenVPNManagedServerHelpers(t *testing.T) {
	opts, err := validateOpenVPNManagedServer(&config.OpenVPNManagedServerConfig{
		TunnelCIDR:     "10.8.0.0/24",
		Proto:          "tcp",
		PushDNS:        []string{"1.1.1.1", "", "  "},
		PushRoutes:     []string{"192.168.10.0/24"},
		ClientToClient: true,
	})
	if err != nil {
		t.Fatalf("validateOpenVPNManagedServer(valid): %v", err)
	}
	if opts.port != 1194 || opts.proto != "tcp" || opts.mask != "255.255.255.0" {
		t.Fatalf("unexpected managed server opts: %#v", opts)
	}
	if got := renderOpenVPNManagedServerConfig(opts, "ca.crt", "server.crt", "server.key"); !strings.Contains(got, "proto tcp-server") || !strings.Contains(got, "client-to-client") || !strings.Contains(got, `push "route 192.168.10.0 255.255.255.0"`) {
		t.Fatalf("unexpected rendered server config:\n%s", got)
	}

	if _, err := validateOpenVPNManagedServer(nil); err == nil {
		t.Fatal("expected nil server config validation error")
	}
	if _, err := validateOpenVPNManagedServer(&config.OpenVPNManagedServerConfig{
		TunnelCIDR: "invalid",
	}); err == nil {
		t.Fatal("expected invalid tunnel CIDR validation error")
	}
	if _, err := validateOpenVPNPushRoutes([]string{"bad-cidr"}); err == nil {
		t.Fatal("expected invalid push route validation error")
	}
	if got, err := validateOpenVPNProto("proto", "udp"); err != nil || got != "udp" {
		t.Fatalf("validateOpenVPNProto(valid) = %q, %v", got, err)
	}
	if _, err := validateOpenVPNProto("proto", "sctp"); err == nil {
		t.Fatal("expected invalid proto validation error")
	}
	if err := validateOpenVPNPort("port", 70000, 70000); err == nil {
		t.Fatal("expected invalid port validation error")
	}
	if got := trimNonEmptyStrings([]string{" a ", "", "b", "  "}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("trimNonEmptyStrings = %#v", got)
	}
	if got := firstNonEmpty("", "fallback"); got != "fallback" {
		t.Fatalf("firstNonEmpty default = %q", got)
	}
	if got := firstNonZeroPort(0, 1194); got != 1194 {
		t.Fatalf("firstNonZeroPort default = %d", got)
	}
	if err := errorsNew("boom"); err == nil || err.Error() != "boom" {
		t.Fatalf("errorsNew = %v", err)
	}
}

func TestOpenVPNConfigPathAndManagedRendering(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", tmp)
	authPassword := testCredential("managed-openvpn")

	foregroundPath := filepath.Join(tmp, "client-foreground.ovpn")
	if err := atomicWriteFile(foregroundPath, []byte("client\nverb 3\n"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile foreground: %v", err)
	}
	if err := ensureOpenVPNConfigForeground(foregroundPath); err != nil {
		t.Fatalf("ensureOpenVPNConfigForeground(valid): %v", err)
	}

	daemonPath := filepath.Join(tmp, "client-daemon.ovpn")
	if err := atomicWriteFile(daemonPath, []byte("client\ndaemon\n"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile daemon: %v", err)
	}
	if err := ensureOpenVPNConfigForeground(daemonPath); err == nil {
		t.Fatal("expected daemonized config validation error")
	}

	mgr := &VPNManager{SuperviseOpenVPN: true, OpenVPNPath: "/usr/sbin/openvpn"}
	if got, err := mgr.openVPNConfigPathForEnabled(config.OpenVPNConfig{}); err != nil || got != "" {
		t.Fatalf("openVPNConfigPathForEnabled(disabled) = %q, %v", got, err)
	}
	if _, err := mgr.openVPNConfigPathForEnabled(config.OpenVPNConfig{Enabled: true}); err == nil {
		t.Fatal("expected missing configPath validation error")
	}
	got, err := mgr.openVPNConfigPathForEnabled(config.OpenVPNConfig{Enabled: true, ConfigPath: foregroundPath})
	if err != nil || got != foregroundPath {
		t.Fatalf("openVPNConfigPathForEnabled(foreground) = %q, %v", got, err)
	}

	managedPath, err := mgr.openVPNConfigPathForEnabled(config.OpenVPNConfig{
		Enabled: true,
		Managed: &config.OpenVPNManagedClientConfig{
			Remote:   "vpn.example.test",
			Proto:    "tcp",
			CA:       "ca-pem",
			Cert:     "cert-pem",
			Key:      "key-pem",
			Username: "alice",
			Password: authPassword,
		},
	})
	if err != nil {
		t.Fatalf("openVPNConfigPathForEnabled(managed): %v", err)
	}
	if managedPath == "" {
		t.Fatal("expected managed config path")
	}
	rendered, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatalf("ReadFile(managedPath): %v", err)
	}
	if !strings.Contains(string(rendered), "proto tcp-client") || !strings.Contains(string(rendered), "auth-user-pass auth.txt") {
		t.Fatalf("unexpected managed client config:\n%s", string(rendered))
	}
	authBytes, err := os.ReadFile(filepath.Join(filepath.Dir(managedPath), "auth.txt"))
	if err != nil {
		t.Fatalf("ReadFile(auth.txt): %v", err)
	}
	if string(authBytes) != "alice\n"+authPassword+"\n" {
		t.Fatalf("unexpected auth.txt contents: %q", string(authBytes))
	}

	if err := (&VPNManager{SuperviseOpenVPN: false}).Validate(context.Background(), config.VPNConfig{
		OpenVPN: config.OpenVPNConfig{Enabled: true},
	}); err == nil {
		t.Fatal("expected supervision-disabled validation error")
	}
	if err := (&VPNManager{SuperviseOpenVPN: true}).Validate(context.Background(), config.VPNConfig{
		OpenVPN: config.OpenVPNConfig{Enabled: true, ConfigPath: foregroundPath},
	}); err == nil {
		t.Fatal("expected missing binary validation error")
	}
}

func TestSyslogFormattingHelpers(t *testing.T) {
	mgr := NewSyslogManager()
	mgr.hostname = "fw-lab"
	mgr.config.Format = "json"

	ev := dpevents.Event{
		ID:        1,
		Proto:     "modbus",
		Kind:      "service.test",
		Timestamp: time.Date(2026, 3, 13, 15, 0, 0, 0, time.UTC),
		SrcIP:     "10.0.0.1",
		SrcPort:   1234,
		DstIP:     "10.0.0.2",
		DstPort:   502,
		Transport: "tcp",
		Attributes: map[string]any{
			"count": 2,
		},
	}

	rawJSON := mgr.formatEvent(ev, "udp")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("formatEvent(json) unmarshal: %v", err)
	}
	if decoded["proto"] != "modbus" || decoded["kind"] != "service.test" {
		t.Fatalf("unexpected json event payload: %#v", decoded)
	}

	mgr.config.Format = "rfc5424"
	rfc := mgr.formatEvent(ev, "udp")
	if !strings.Contains(rfc, "<14>1 2026-03-13T15:00:00Z fw-lab containd") || !strings.Contains(rfc, `"transport":"tcp"`) || !strings.Contains(rfc, `"src":"10.0.0.1:1234"`) {
		t.Fatalf("unexpected rfc5424 payload: %s", rfc)
	}

	if got := formatTime(time.Time{}); got != "" {
		t.Fatalf("formatTime(zero) = %q", got)
	}
	if got := formatTime(ev.Timestamp); got != "2026-03-13T15:00:00Z" {
		t.Fatalf("formatTime(non-zero) = %q", got)
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "log.example.test", Port: 514, Proto: "tcp"}); err != nil {
		t.Fatalf("ValidateSyslogForwarder(valid): %v", err)
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "", Port: 514, Proto: "tcp"}); err == nil {
		t.Fatal("expected missing address validation error")
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "log.example.test", Port: 0, Proto: "tcp"}); err == nil {
		t.Fatal("expected invalid port validation error")
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "log.example.test", Port: 514, Proto: "icmp"}); err == nil {
		t.Fatal("expected invalid proto validation error")
	}
}
