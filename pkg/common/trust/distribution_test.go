// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleDistribution(t *testing.T) {
	ca := certificatePEM(t, true, x509.KeyUsageCertSign)
	b, err := NewBundle(append([]byte("\n  "), ca...))
	if err != nil {
		t.Fatal(err)
	}
	if b.PEM != strings.TrimSpace(string(ca))+"\n" || b.Revision != Revision(b.PEM) || !strings.HasPrefix(b.Revision, "sha256:") {
		t.Fatalf("NewBundle = %+v", b)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if again, _ := NewBundle(ca); again.Revision != b.Revision {
		t.Fatal("revision is not deterministic")
	}
	other := certificatePEM(t, true, x509.KeyUsageCertSign)
	if ob, _ := NewBundle(other); ob.Revision == b.Revision {
		t.Fatal("different bundles share a revision")
	}
	tampered := b
	tampered.PEM += string(other)
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered content matched the old revision")
	}
	if _, err := NewBundle([]byte("junk")); err == nil {
		t.Fatal("NewBundle accepted junk")
	}
	empty, err := NewBundle([]byte(" \n"))
	if err != nil || !empty.Empty() || empty.Revision != NoRevision || empty.Validate() != nil {
		t.Fatalf("empty bundle = %+v, %v", empty, err)
	}
	if pool, err := empty.RootPool(); pool != nil || err != nil {
		t.Fatalf("empty RootPool = %v, %v", pool, err)
	}
	if pool, err := b.RootPool(); pool == nil || err != nil {
		t.Fatalf("RootPool = %v, %v", pool, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "trusted_ca.pem")
	if got, err := LoadBundle(path); err != nil || !got.Empty() {
		t.Fatalf("missing file = %+v, %v", got, err)
	}
	if err := WriteBundle(path, ca); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadBundle(path); err != nil || got != b {
		t.Fatalf("LoadBundle = %+v, %v; want %+v", got, err, b)
	}
	if err := WriteBundle(path, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadBundle(path); err != nil || !got.Empty() {
		t.Fatalf("cleared file = %+v, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("invalid stored bundle = %v", err)
	}

	system := filepath.Join(dir, "system.pem")
	if err := os.WriteFile(system, other, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", system)
	eff, err := b.EffectivePEM()
	if err != nil || !strings.HasPrefix(string(eff), strings.TrimSpace(string(other))+"\n") || !strings.HasSuffix(string(eff), b.PEM) {
		t.Fatalf("EffectivePEM = %q, %v", eff, err)
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "absent.pem"))
	if _, err := b.EffectivePEM(); err == nil {
		t.Fatal("EffectivePEM without system roots succeeded")
	}
}
