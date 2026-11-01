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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
