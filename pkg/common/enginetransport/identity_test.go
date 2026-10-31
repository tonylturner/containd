// SPDX-License-Identifier: Apache-2.0
package enginetransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Public fixed vector: bytes 0 through 31, not an operator credential.
var testSecret = func() string {
	var vector [32]byte
	for i := range vector {
		vector[i] = byte(i)
	}
	return hex.EncodeToString(vector[:])
}()

func TestLocalHost(t *testing.T) {
	for host, local := range map[string]bool{
		"127.0.0.1": true, "127.255.1.2": true, "::1": true, "::ffff:127.1.2.3": true,
		"": false, "0.0.0.0": false, "::": false, "localhost": false, "192.0.2.1": false,
		"fe80::1%eth0": false, "::1%eth0": false,
	} {
		if LocalHost(host) != local {
			t.Errorf("%q local should be %t", host, local)
		}
	}
}

func TestSecret(t *testing.T) {
	for _, s := range []string{"", "abc", strings.Repeat("a", 64), strings.Repeat("00", 32), strings.Repeat("ff", 32), strings.Repeat("gh", 32), testSecret[:62], testSecret + "00"} {
		if _, err := ParseSecret(s); err == nil || strings.Contains(err.Error(), s) && s != "" {
			t.Fatalf("invalid secret accepted or disclosed: %v", err)
		}
	}
	a, err := ParseSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSecret(strings.ToUpper(testSecret))
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("hex case changed identity")
	}
	t.Setenv("CONTAIND_ENGINE_SECRET", " \t"+testSecret+"\n")
	c, err := Secret()
	if err != nil || !bytes.Equal(a, c) {
		t.Fatal("whitespace not trimmed")
	}
	t.Setenv("CONTAIND_ENGINE_SECRET", "")
	t.Setenv("NGFW_ENGINE_SECRET", testSecret)
	if _, err := Secret(); err == nil {
		t.Fatal("legacy secret alias accepted")
	}
}

func TestDerivationVector(t *testing.T) {
	secret, _ := ParseSecret(testSecret)
	a, err := Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]tls.Certificate{{a.Server, b.Server}, {a.Client, b.Client}} {
		if !bytes.Equal(pair[0].Certificate[0], pair[1].Certificate[0]) {
			t.Fatal("certificates not deterministic")
		}
	}
	if bytes.Equal(a.Server.PrivateKey.(ed25519.PrivateKey), a.Client.PrivateKey.(ed25519.PrivateKey)) {
		t.Fatal("keys not separated")
	}
	// These fixed digests pin the full DER bytes, including validity and serial.
	for _, tc := range []struct {
		cert tls.Certificate
		want string
	}{
		{a.Server, "009723691964f610424fc5954da2f4a58cf0b685c3dad0d69655465efcd0c9e5"}, {a.Client, "200598a31de182ae2c1ab4da987c4bd74b6dfd96f98238697176c25b692b9555"},
	} {
		hash := sha256.Sum256(tc.cert.Certificate[0])
		if got := hex.EncodeToString(hash[:]); got != tc.want {
			t.Errorf("certificate vector: %s", got)
		}
	}
	if a.Server.Leaf.DNSNames[0] != ServerName || a.Client.Leaf.Subject.CommonName != "containd-engine-client" {
		t.Fatal("wrong names")
	}
	if a.ServerTLS().ClientAuth != tls.RequireAndVerifyClientCert || a.ClientTLS().ServerName != ServerName {
		t.Fatal("wrong verifier")
	}
}

func TestExport(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", testSecret)
	secret, _ := Secret()
	identity, _ := Derive(secret)
	dir := t.TempDir()
	if err := Export(dir); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"server.crt": identity.Server.Certificate[0], "client.crt": identity.Client.Certificate[0]} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		p, _ := pem.Decode(b)
		if p == nil || !bytes.Equal(p.Bytes, want) {
			t.Fatal("certificate differs from identity")
		}
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("missing key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.(ed25519.PrivateKey), identity.Client.PrivateKey.(ed25519.PrivateKey)) {
		t.Fatal("wrong exported key")
	}
	info, err := os.Stat(filepath.Join(dir, "client.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wrong key permissions")
	}
	if err := Export(dir); err == nil {
		t.Fatal("overwrote files")
	}
	for _, name := range []string{"server.crt", "client.crt", "client.key"} {
		d := t.TempDir()
		target := filepath.Join(t.TempDir(), "absent")
		if err := os.Symlink(target, filepath.Join(d, name)); err != nil {
			t.Fatal(err)
		}
		if err := Export(d); err == nil {
			t.Fatal("followed symlink")
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatal("symlink target touched")
		}
	}
}

func TestTargetURL(t *testing.T) {
	for _, raw := range []string{"https://[hostname]:8081", "http://localhost:8081", "http://192.0.2.1:8081", "localhost:8081", "unix:///a", "http:opaque", "http://u:p@127.0.0.1:8081", "http://127.0.0.1/", "http://127.0.0.1?", "http://127.0.0.1#", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:", "http://:8081", "https://[fe80::1%25bad%20zone]:8081", "https://[fe80::1%25]:8081"} {
		if _, err := ParseURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8081", "127.0.0.2:8081", "http://[::1]:8081", "http://[::ffff:127.0.0.1]:8081", "https://engine:8081", "https://[fe80::1%25eth0]:8081"} {
		if _, err := ParseURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
