// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestOpenVPNManagedClientRenderArtifacts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", root)
	authPassword := testCredential("lab-client-auth")

	mgr := NewVPNManager(t.TempDir())
	confPath, err := mgr.renderOpenVPNManagedClient(&config.OpenVPNManagedClientConfig{
		Remote:   "vpn.example.com",
		Port:     1194,
		Proto:    "tcp",
		Username: "labuser",
		Password: authPassword,
		CA:       "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
		Cert:     "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
		Key:      "-----BEGIN EC PRIVATE KEY-----\nKEY\n-----END EC PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatalf("renderOpenVPNManagedClient: %v", err)
	}

	managedDir := filepath.Join(root, "managed")
	if confPath != filepath.Join(managedDir, "openvpn.conf") {
		t.Fatalf("unexpected config path %q", confPath)
	}

	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("ReadFile(config): %v", err)
	}
	conf := string(confBytes)
	if !strings.Contains(conf, "proto tcp-client") {
		t.Fatalf("expected tcp-client config, got %q", conf)
	}
	if !strings.Contains(conf, "remote vpn.example.com 1194") {
		t.Fatalf("expected remote line, got %q", conf)
	}
	if !strings.Contains(conf, "auth-user-pass auth.txt") {
		t.Fatalf("expected auth-user-pass directive, got %q", conf)
	}

	authBytes, err := os.ReadFile(filepath.Join(managedDir, "auth.txt"))
	if err != nil {
		t.Fatalf("ReadFile(auth): %v", err)
	}
	if string(authBytes) != "labuser\n"+authPassword+"\n" {
		t.Fatalf("unexpected auth file %q", string(authBytes))
	}
}

func TestOpenVPNManagedClientAuthRemoval(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.txt")
	if err := os.WriteFile(authPath, []byte("stale\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale): %v", err)
	}
	if err := writeOpenVPNManagedClientAuth(openVPNManagedClientOptions{}, authPath); err != nil {
		t.Fatalf("writeOpenVPNManagedClientAuth(remove): %v", err)
	}
	if _, err := os.Stat(authPath); !os.IsNotExist(err) {
		t.Fatalf("expected auth file removal, got err=%v", err)
	}
}

func TestOpenVPNManagedServerRenderAndPaths(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", filepath.Join(root, "profiles"))

	mgr := NewVPNManager(t.TempDir())
	confPath, err := mgr.openVPNConfigPathForEnabled(config.OpenVPNConfig{
		Enabled: true,
		Mode:    "server",
		Server: &config.OpenVPNManagedServerConfig{
			ListenPort:     443,
			Proto:          "tcp",
			TunnelCIDR:     "10.9.0.0/24",
			PushDNS:        []string{"1.1.1.1", " 8.8.8.8 "},
			PushRoutes:     []string{"10.20.0.0/24"},
			ClientToClient: true,
		},
	})
	if err != nil {
		t.Fatalf("openVPNConfigPathForEnabled(server): %v", err)
	}

	serverDir := filepath.Join(root, "managed", "server")
	if got := openVPNManagedServerDir(); got != serverDir {
		t.Fatalf("openVPNManagedServerDir = %q", got)
	}
	if confPath != filepath.Join(serverDir, "openvpn.conf") {
		t.Fatalf("unexpected server config path %q", confPath)
	}

	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("ReadFile(server config): %v", err)
	}
	conf := string(confBytes)
	if !strings.Contains(conf, "port 443") {
		t.Fatalf("expected listen port in config, got %q", conf)
	}
	if !strings.Contains(conf, "proto tcp-server") {
		t.Fatalf("expected tcp-server config, got %q", conf)
	}
	if !strings.Contains(conf, "server 10.9.0.0 255.255.255.0") {
		t.Fatalf("expected server network line, got %q", conf)
	}
	if !strings.Contains(conf, `push "dhcp-option DNS 1.1.1.1"`) || !strings.Contains(conf, `push "route 10.20.0.0 255.255.255.0"`) {
		t.Fatalf("expected push directives, got %q", conf)
	}
	if !strings.Contains(conf, "client-to-client") {
		t.Fatalf("expected client-to-client directive, got %q", conf)
	}

	for _, rel := range []string{
		"pki/ca.crt",
		"pki/ca.key",
		"pki/server.crt",
		"pki/server.key",
	} {
		if _, err := os.Stat(filepath.Join(serverDir, rel)); err != nil {
			t.Fatalf("expected rendered PKI file %q: %v", rel, err)
		}
	}
}
