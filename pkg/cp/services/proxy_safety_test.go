// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func proxyCertificate(t *testing.T, dir string, from, until time.Time, mismatch bool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if mismatch {
		_, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	daemonWrite(t, filepath.Join(dir, "app.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	daemonWrite(t, filepath.Join(dir, "app.key"), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})))
}

func TestProxyTLSRequiresCurrentlyValidMatchingPair(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		from, until                          time.Duration
		mismatch, missing, malformed, escape bool
	}{
		{name: "valid", from: -time.Hour, until: time.Hour},
		{name: "expired", from: -2 * time.Hour, until: -time.Hour},
		{name: "future", from: time.Hour, until: 2 * time.Hour},
		{name: "mismatch", from: -time.Hour, until: time.Hour, mismatch: true},
		{name: "missing", missing: true},
		{name: "malformed", malformed: true},
		{name: "symlink_escape", from: -time.Hour, until: time.Hour, escape: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir(), NginxPath: "/nonexistent/nginx", EnvoyPath: "/nonexistent/envoy"})
			m.CertsDir = t.TempDir()
			if !tc.missing {
				dir := m.CertsDir
				if tc.escape {
					dir = t.TempDir()
				}
				proxyCertificate(t, dir, time.Now().Add(tc.from), time.Now().Add(tc.until), tc.mismatch)
				if tc.escape {
					for _, ext := range []string{".crt", ".key"} {
						if err := os.Symlink(filepath.Join(dir, "app"+ext), filepath.Join(m.CertsDir, "app"+ext)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if tc.malformed {
				daemonWrite(t, filepath.Join(m.CertsDir, "app.crt"), "not a certificate")
			}
			cfg := daemonProxyConfig()
			cfg.Reverse.Sites[0].TLSEnabled, cfg.Reverse.Sites[0].CertRef = true, "app"
			path := filepath.Join(m.BaseDir, "nginx-reverse.conf")
			daemonWrite(t, path, "current")
			err := m.Validate(context.Background(), cfg)
			daemonUnchanged(t, path, "current")
			if tc.name != "valid" {
				daemonFault(t, err, "proxy")
				daemonFault(t, m.Apply(context.Background(), cfg), "proxy")
				daemonUnchanged(t, path, "current")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"listen 8443 ssl;", "ssl_certificate " + filepath.Join(m.CertsDir, "app.crt") + ";", "ssl_certificate_key " + filepath.Join(m.CertsDir, "app.key") + ";"} {
				if !strings.Contains(string(body), want) {
					t.Fatalf("missing %q in %s", want, body)
				}
			}
			if strings.Contains(string(body), "listen 8443;") {
				t.Fatal("plaintext listener rendered for TLS")
			}
		})
	}
}

func TestProxyTLSEmptyReferenceRefusedBeforeWriting(t *testing.T) {
	m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir()})
	cfg := daemonProxyConfig()
	cfg.Reverse.Sites[0].TLSEnabled = true
	for _, path := range m.DescribeRendered() {
		daemonWrite(t, path, "current")
	}
	daemonFault(t, m.Apply(context.Background(), cfg), "proxy")
	for _, path := range m.DescribeRendered() {
		daemonUnchanged(t, path, "current")
	}
}
