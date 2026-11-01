// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestOpenVPNProfileBoundedGrammar(t *testing.T) {
	valid := "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote-cert-tls server\n"
	for _, block := range []string{"ca", "cert", "key", "tls-auth", "tls-crypt"} {
		data := valid + "<" + block + ">\n-----BEGIN KEY-----\nYWJj\n-----END KEY-----\n</" + block + ">\n"
		p, err := ParseOpenVPNProfile([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path, err := p.render(dir)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), block+" "+block+".pem") {
			t.Fatalf("inline material missing: %s", b)
		}
	}
	for _, bad := range []string{
		"up /tmp/x", "down x", "route-up x", "script-security 2", "plugin x", "config x", "management 127.0.0.1 9999", "daemon", "cd /tmp", "log x", "log-append x", "writepid x", "status x", "ca /etc/passwd", "cert x", "key x", "auth-user-pass /etc/passwd", "tls-auth x", "tls-crypt x", "askpass x", "dev-node x", "unknown x", "--client", "remote vpn.example.com 1194 udp extra", "client extra", "remote vpn.example.com\\\n1194", "client\r\n", "client\x00", "<ca>\n</ca>\nup x", "<ca>\nkey\n</ca> junk", "<ca>\n<key>\n</ca>", "<ca>\nx", "<ca>\nx\n</ca>\n<ca>\nx\n</ca>", "verb -3",
	} {
		t.Run(strings.ReplaceAll(bad, "/", "_"), func(t *testing.T) {
			if _, err := ParseOpenVPNProfile([]byte(valid + bad + "\n")); err == nil {
				t.Fatalf("accepted %q", bad)
			}
		})
	}
	if _, err := ParseOpenVPNProfile(make([]byte, maxOpenVPNProfile+1)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}

func TestOpenVPNValidatePureAndRefusalAtomic(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", filepath.Join(root, "authority"))
	m := NewVPNManager(filepath.Join(root, "services"))
	m.SuperviseOpenVPN = true
	m.OpenVPNPath = "/bin/sh"
	cfg := config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true, Mode: "server", Server: &config.OpenVPNManagedServerConfig{TunnelCIDR: "10.8.0.0/24"}}}
	if err := m.Validate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Validate created %v", entries)
	}
	// Every refusal path is typed, and neither Validate nor Apply publishes a
	// config, creates PKI or starts/stops an existing process.
	cfg.OpenVPN.Server.PushDNS = []string{"1.1.1.1\nup evil"}
	for _, f := range []func(context.Context, config.VPNConfig) error{m.Validate, m.Apply} {
		err := f(context.Background(), cfg)
		var service *config.ServiceConfigError
		if !errors.As(err, &service) || service.Service != config.ServiceOpenVPN {
			t.Fatalf("untyped refusal: %v", err)
		}
	}
	entries, err = os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refusal created files: %v %v", entries, err)
	}
	profile := filepath.Join(root, "untrusted.ovpn")
	if err := os.WriteFile(profile, []byte("client\nup evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.OpenVPN = config.OpenVPNConfig{Enabled: true, ConfigPath: profile}
	err = m.Apply(context.Background(), cfg)
	var service *config.ServiceConfigError
	if !errors.As(err, &service) {
		t.Fatalf("arbitrary path bypassed parser: %v", err)
	}
	if _, err := os.Stat(m.BaseDir); !os.IsNotExist(err) {
		t.Fatalf("refusal created services: %v", err)
	}
}

func TestOpenVPNMaterialRevisionEveryReference(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "openvpn.conf")
	options := []string{"ca", "cert", "key", "auth-user-pass", "tls-auth", "tls-crypt", "crl-verify"}
	var text strings.Builder
	for _, option := range options {
		text.WriteString(option + " " + option + ".pem\n")
		if err := os.WriteFile(filepath.Join(dir, option+".pem"), []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(conf, []byte(text.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := openVPNMaterialRevision(conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range options {
		if err := os.WriteFile(filepath.Join(dir, option+".pem"), []byte("after"), 0o600); err != nil {
			t.Fatal(err)
		}
		next, err := openVPNMaterialRevision(conf)
		if err != nil || next == previous {
			t.Fatalf("%s not in revision: %v", option, err)
		}
		again, err := openVPNMaterialRevision(conf)
		if err != nil || next != again {
			t.Fatalf("%s unstable revision: %v", option, err)
		}
		previous = next
	}
}

func TestOpenVPNDisabledDraftAndAuthPreservation(t *testing.T) {
	m := NewVPNManager(t.TempDir())
	if err := m.Validate(context.Background(), config.VPNConfig{OpenVPN: config.OpenVPNConfig{Managed: &config.OpenVPNManagedClientConfig{}, Server: &config.OpenVPNManagedServerConfig{}}}); err != nil {
		t.Fatalf("disabled incomplete draft rejected: %v", err)
	}
	opts, err := validateOpenVPNManagedClient(&config.OpenVPNManagedClientConfig{Remote: "vpn.example.test", CA: "ca", Cert: "cert", Key: "key", Username: " alice ", Password: " secret with spaces "})
	if err != nil || opts.user != " alice " || opts.pass != " secret with spaces " {
		t.Fatalf("credentials changed: %v", err)
	}
}
