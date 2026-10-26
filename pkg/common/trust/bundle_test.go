// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func certificatePEM(t *testing.T, isCA bool, usage x509.KeyUsage) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), BasicConstraintsValid: true,
		IsCA: isCA, KeyUsage: usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertificates(t *testing.T) {
	ca := certificatePEM(t, true, x509.KeyUsageCertSign)
	otherCA := certificatePEM(t, true, 0)
	leaf := certificatePEM(t, false, x509.KeyUsageDigitalSignature)
	noSigning := certificatePEM(t, true, x509.KeyUsageDigitalSignature)
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", nil, 0},
		{"whitespace", []byte(" \n"), 0},
		{"garbage", []byte("not pem"), 0},
		{"leaf", leaf, 0},
		{"no signing usage", noSigning, 0},
		{"invalid DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad DER")}), 0},
		{"wrong type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), 0},
		{"malformed PEM", []byte("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----"), 0},
		{"unterminated PEM", []byte("-----BEGIN CERTIFICATE-----\n"), 0},
		{"malformed then valid", append([]byte("-----BEGIN CERTIFICATE-----\n!\n"), ca...), 0},
		{"leading garbage", append([]byte("garbage\n"), ca...), 0},
		{"trailing garbage", append(append([]byte{}, ca...), []byte("garbage")...), 0},
		{"CA then leaf", append(append([]byte{}, ca...), leaf...), 0},
		{"CA", ca, 1},
		{"CA bundle", append(append([]byte{}, ca...), otherCA...), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := Certificates(tt.data)
			if tt.want == 0 {
				if err == nil {
					t.Fatal("invalid bundle accepted")
				}
			} else if err != nil || len(certs) != tt.want {
				t.Fatalf("got %d certs, %v; want %d", len(certs), err, tt.want)
			}
		})
	}
}

func TestWriteBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls", "ca.pem")
	ca := certificatePEM(t, true, x509.KeyUsageCertSign)
	if err := WriteBundle(path, ca); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(path, []byte("garbage")); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(ca) {
		t.Fatalf("invalid upload altered bundle: %q, %v", got, err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0o644 {
		t.Fatalf("bundle permissions: %v, %v", stat, err)
	}
	if err := WriteBundle(path, nil); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("clear: %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary bundle files remain: %v, %v", entries, err)
	}
}
