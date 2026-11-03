// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPair(t *testing.T) ([]byte, []byte) {
	return testPairWithDNS(t, []string{"localhost"})
}

func testPairWithDNS(t *testing.T, dnsNames []string) ([]byte, []byte) {
	now := time.Now()
	return testPairWithValidity(t, dnsNames, now.Add(-time.Hour), now.Add(time.Hour))
}

func testPairWithValidity(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: dnsNames, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})
}

func TestValidateValidity(t *testing.T) {
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.FixedZone("test", -5*60*60))
	for _, tc := range []struct {
		name string
		leaf *x509.Certificate
		want string
	}{
		{
			name: "valid",
			leaf: &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		},
		{
			name: "expired",
			leaf: &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)},
			want: "has expired",
		},
		{
			name: "not yet valid",
			leaf: &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)},
			want: "not yet valid",
		},
		{name: "missing leaf", want: "is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateValidity(tc.leaf, now)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateValidity() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateValidity() = %v, want %q with validity dates and current time", err, tc.want)
			}
			if tc.name != "missing leaf" && (!strings.Contains(err.Error(), "NotBefore=") ||
				!strings.Contains(err.Error(), "NotAfter=") ||
				!strings.Contains(err.Error(), "current UTC time=")) {
				t.Fatalf("ValidateValidity() = %v, want validity dates and current time", err)
			}
		})
	}
}

func TestValidateSubjectAltName(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf *x509.Certificate
		want bool
	}{
		{name: "DNS", leaf: &x509.Certificate{DNSNames: []string{"management.example"}}, want: true},
		{name: "IP", leaf: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}, want: true},
		{name: "CN only", leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "management.example"}}},
		{name: "missing leaf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSubjectAltName(tc.leaf)
			if (err == nil) != tc.want {
				t.Fatalf("ValidateSubjectAltName() = %v, want success %v", err, tc.want)
			}
			if err != nil && (!strings.Contains(err.Error(), "subject alternative name") || !strings.Contains(err.Error(), "-addext")) {
				t.Fatalf("error lacks reason and fix: %v", err)
			}
		})
	}
}

func TestLoaderAllowsLegacyInitialIdentityButRejectsSANlessRotation(t *testing.T) {
	legacyCert, legacyKey := testPairWithDNS(t, nil)
	legacyPath := filepath.Join(t.TempDir(), "legacy.pem")
	if err := Publish(legacyPath, legacyCert, legacyKey); err != nil {
		t.Fatal(err)
	}
	legacy, err := NewLoader(legacyPath, legacyPath).GetCertificate(nil)
	if err != nil || legacy == nil {
		t.Fatalf("initial legacy identity was rejected: %v", err)
	}

	firstCert, firstKey := testPair(t)
	firstPath := filepath.Join(t.TempDir(), "server.pem")
	if err := Publish(firstPath, firstCert, firstKey); err != nil {
		t.Fatal(err)
	}
	loader := NewLoader(firstPath, firstPath)
	first, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(firstPath, legacyCert, legacyKey); err != nil {
		t.Fatal(err)
	}
	got, err := loader.Reload()
	if err == nil || !strings.Contains(err.Error(), "subject alternative name") || got != first {
		t.Fatalf("SAN-less rotation did not retain last-good identity: pair=%p first=%p err=%v", got, first, err)
	}
}

func TestLoaderRejectsInvalidValidityWindowAndRecovers(t *testing.T) {
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
		reason              string
	}{
		{
			name: "expired", notBefore: time.Now().Add(-2 * time.Hour), notAfter: time.Now().Add(-time.Hour),
			reason: "has expired",
		},
		{
			name: "not yet valid", notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(2 * time.Hour),
			reason: "not yet valid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "server.pem")
			currentCert, currentKey := testPair(t)
			if err := Publish(path, currentCert, currentKey); err != nil {
				t.Fatal(err)
			}
			loader := NewLoader(path, path)
			first, err := loader.GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			invalidCert, invalidKey := testPairWithValidity(
				t, []string{"localhost"}, tc.notBefore, tc.notAfter,
			)
			if err := Publish(path, invalidCert, invalidKey); err != nil {
				t.Fatal(err)
			}
			got, err := loader.Reload()
			if err == nil || !strings.Contains(err.Error(), tc.reason) || got != first {
				t.Fatalf("invalid reload: pair=%p first=%p err=%v", got, first, err)
			}
			validCert, validKey := testPair(t)
			if err := Publish(path, validCert, validKey); err != nil {
				t.Fatal(err)
			}
			got, err = loader.Reload()
			if err != nil {
				t.Fatal(err)
			}
			if got == first || bytes.Equal(got.Certificate[0], first.Certificate[0]) {
				t.Fatalf("valid replacement did not recover: pair=%p first=%p", got, first)
			}
		})
	}
}

type failingTemp struct {
	tempFile
	boundary string
}

func (f failingTemp) Write(b []byte) (int, error) {
	if f.boundary == "write" {
		return 0, errors.New("write")
	}
	if f.boundary == "short write" {
		return len(b) - 1, nil
	}
	return f.tempFile.Write(b)
}
func (f failingTemp) Sync() error {
	if f.boundary == "sync" {
		return errors.New("sync")
	}
	return f.tempFile.Sync()
}
func (f failingTemp) Close() error {
	err := f.tempFile.Close()
	if f.boundary == "close" {
		return errors.New("close")
	}
	return err
}

func TestPublisherFailureBoundaries(t *testing.T) {
	cert, key := testPair(t)
	nextCert, nextKey := testPair(t)
	old, _ := bundleBytes(cert, key)
	next, _ := bundleBytes(nextCert, nextKey)
	for _, boundary := range []string{"create", "write", "short write", "sync", "close", "rename", "dir sync"} {
		t.Run(boundary, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.pem")
			if err := Publish(path, cert, key); err != nil {
				t.Fatal(err)
			}
			inode, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer inode.Close()
			ops := diskOps
			ops.create = func(d, p string) (tempFile, error) {
				if boundary == "create" {
					return nil, errors.New("create")
				}
				f, err := diskOps.create(d, p)
				if err != nil {
					return nil, err
				}
				return failingTemp{f, boundary}, nil
			}
			if boundary == "rename" {
				ops.rename = func(string, string) error { return errors.New("rename") }
			}
			if boundary == "dir sync" {
				ops.syncDir = func(string) error { return errors.New("dir sync") }
			}
			err = publish(path, next, ops)
			if err == nil {
				t.Fatal("failure swallowed")
			}
			want := old
			if boundary == "dir sync" {
				want = next
				if !errors.Is(err, ErrCommitUncertain) {
					t.Fatalf("%v", err)
				}
			} else if errors.Is(err, ErrCommitUncertain) {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("published bytes changed incorrectly: %v", err)
			}
			prior := make([]byte, len(old))
			if _, err := inode.Read(prior); err != nil || !bytes.Equal(prior, old) {
				t.Fatal("published inode modified")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary file leaked: %v %v", entries, err)
			}
		})
	}
}

func TestManagedMigrationAndRestart(t *testing.T) {
	cert, key := testPair(t)
	nextCert, nextKey := testPair(t)
	for _, kind := range []string{"valid legacy", "mismatched legacy", "absent legacy", "bundle present", "invalid bundle"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(dir, "server.pem")
			legacyCert := filepath.Join(dir, "server.crt")
			legacyKey := filepath.Join(dir, "server.key")
			oldKey := key
			if kind == "mismatched legacy" {
				oldKey = nextKey
			}
			if kind != "absent legacy" {
				if err := os.WriteFile(legacyCert, cert, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(legacyKey, oldKey, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "bundle present" {
				if err := Publish(bundle, nextCert, nextKey); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "invalid bundle" {
				if err := os.WriteFile(bundle, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			generated := 0
			err := EnsureManaged(bundle, legacyCert, legacyKey, func() ([]byte, []byte, error) { generated++; return nextCert, nextKey, nil }, t.Logf)
			if kind == "invalid bundle" {
				if err == nil {
					t.Fatal("invalid existing bundle accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := cert
			if kind != "valid legacy" {
				want = nextCert
			}
			pair, err := NewLoader(bundle, bundle).GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(want)
			if !bytes.Equal(pair.Certificate[0], block.Bytes) {
				t.Fatal("restart loaded wrong identity")
			}
			shouldGenerate := kind == "mismatched legacy" || kind == "absent legacy"
			if (generated == 1) != shouldGenerate {
				t.Fatalf("generated %d", generated)
			}
			st, err := os.Stat(bundle)
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("bundle mode: %v %v", st, err)
			}
			if kind != "absent legacy" {
				for path, want := range map[string][]byte{legacyCert: cert, legacyKey: oldKey} {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatal("legacy bytes changed")
					}
					st, err := os.Stat(path)
					if err != nil || st.Mode().Perm() != 0o640 {
						t.Fatal("legacy mode changed")
					}
				}
			}
		})
	}
}

func TestLoaderExternalLastGood(t *testing.T) {
	cert, key := testPair(t)
	nextCert, nextKey := testPair(t)
	dir := t.TempDir()
	c := filepath.Join(dir, "c")
	k := filepath.Join(dir, "k")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write(c, cert)
	write(k, key)
	l := NewLoader(c, k)
	first, err := l.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	write(c, nextCert)
	last, err := l.Reload()
	if err == nil || last != first {
		t.Fatal("invalid rotation did not retain last-good")
	}
	if _, err := NewLoader(c, k).GetCertificate(nil); err == nil {
		t.Fatal("invalid pair at start accepted")
	}
	got, err := l.GetCertificate(nil)
	if err != nil || got != first {
		t.Fatal("handshake refused last-good")
	}
	write(k, nextKey)
	next, err := l.Reload()
	if err != nil || bytes.Equal(first.Certificate[0], next.Certificate[0]) {
		t.Fatal("valid rotation not accepted")
	}
	for path, want := range map[string][]byte{c: nextCert, k: nextKey} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("external bytes modified")
		}
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0o640 {
			t.Fatal("external mode modified")
		}
	}
	bundle := filepath.Join(dir, "bundle")
	data, _ := bundleBytes(cert, key)
	write(bundle, data)
	if _, err := NewLoader(bundle, bundle).GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRejectsAmbiguity(t *testing.T) {
	cert, key := testPair(t)
	_, otherKey := testPair(t)
	for _, data := range [][]byte{append(append([]byte{}, cert...), otherKey...), append(append(append([]byte{}, cert...), key...), key...), append(append(append([]byte{}, cert...), key...), cert...), append(append([]byte{}, cert...), []byte("garbage")...)} {
		if _, err := ParseBundle(data); err == nil {
			t.Fatal("ambiguous or invalid identity accepted")
		}
	}
}

func TestPublisherRejectsInvalidPairBeforeWriting(t *testing.T) {
	cert, key := testPair(t)
	_, otherKey := testPair(t)
	path := filepath.Join(t.TempDir(), "server.pem")
	if err := Publish(path, cert, key); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(path, cert, otherKey); err == nil {
		t.Fatal("mismatched pair published")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid upload changed bundle")
	}
}
